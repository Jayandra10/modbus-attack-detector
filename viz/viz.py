#!/usr/bin/env python3
"""
Visualization module for Modbus Attack Detection Lab.

Reads Phase 1/2 outputs and generates PNG plots:
- phase_timeline.png: Gantt-like timeline of attack phases
- ops_per_phase.png: Bar chart of operations per phase
- suricata_alerts_over_time.png: Line chart of IDS alerts over time
- feature_correlation.png: Heatmap of feature correlations
- model_coefficients.png: Bar chart of ML model coefficients

Input paths (mounted as /data):
- /data/labels.jsonl
- /data/generator_events.jsonl
- /data/suricata/eve.json (optional)
- /data/ml_results.json (optional)

Output paths (mounted as /reports):
- /reports/*.png (generated plots)
"""

import json
import os
import sys
from datetime import datetime

import pandas as pd
import numpy as np
import matplotlib
matplotlib.use('Agg')  # Non-interactive backend for Docker
import matplotlib.pyplot as plt

DATA_DIR = "/data"
REPORTS_DIR = "/reports"

LABELS_FILE = os.path.join(DATA_DIR, "labels.jsonl")
EVENTS_FILE = os.path.join(DATA_DIR, "generator_events.jsonl")
EVE_FILE = os.path.join(DATA_DIR, "suricata", "eve.json")
ML_RESULTS_FILE = os.path.join(DATA_DIR, "ml_results.json")

WINDOW_SEC = 5


def read_jsonl(path):
    """Read JSONL file, handling missing files and decode errors gracefully."""
    rows = []
    if not os.path.exists(path):
        return rows
    try:
        with open(path, "r", encoding="utf-8", errors="ignore") as f:
            for line in f:
                line = line.strip()
                if line:
                    try:
                        rows.append(json.loads(line))
                    except json.JSONDecodeError:
                        pass
    except Exception as e:
        print(f"Warning: Could not read {path}: {e}", file=sys.stderr)
    return rows


def parse_labels(labels_rows):
    """
    Parse labels into phase intervals.
    Returns list of (phase_name, start_ts, end_ts) tuples.
    """
    starts = {}
    ends = {}
    for r in labels_rows:
        phase = r.get("phase")
        event = r.get("event")
        ts_str = r.get("ts")
        if phase and event and ts_str:
            try:
                # Parse ISO timestamp
                dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                ts = dt.timestamp()
            except Exception:
                continue
            
            if event == "start":
                if phase not in starts:
                    starts[phase] = ts
                else:
                    starts[phase] = min(starts[phase], ts)
            elif event == "end":
                if phase not in ends:
                    ends[phase] = ts
                else:
                    ends[phase] = max(ends[phase], ts)
    
    intervals = []
    for phase in sorted(set(starts.keys()) | set(ends.keys())):
        if phase in starts and phase in ends:
            intervals.append((phase, starts[phase], ends[phase]))
    return intervals


def phase_for_ts(intervals, t):
    """Determine which phase a timestamp belongs to."""
    for phase, s, e in intervals:
        if s <= t <= e:
            return phase
    return "unknown"


def windowize(ts_min, ts_max, window_sec):
    """Create non-overlapping windows of window_sec size."""
    windows = []
    cur = int(ts_min)
    end = int(ts_max)
    while cur <= end:
        windows.append((cur, cur + window_sec))
        cur += window_sec
    return windows


def plot_phase_timeline(intervals):
    """Generate phase timeline Gantt chart."""
    if not intervals:
        print("Warning: No phase intervals found. Skipping phase_timeline.png")
        return
    
    phases = [p for p, _, _ in intervals]
    starts = [s for _, s, _ in intervals]
    ends = [e for _, _, e in intervals]
    
    if not starts or not ends:
        return
    
    base = min(starts)
    
    plt.figure(figsize=(12, 4))
    colors = ["green", "orange", "red"]
    for i, (p, s, e) in enumerate(intervals):
        color = colors[i % len(colors)]
        plt.barh([i], [e - s], left=[s - base], color=color, alpha=0.7, edgecolor="black")
    
    plt.yticks(range(len(phases)), phases)
    plt.xlabel("Seconds from start")
    plt.title("Attack Phase Timeline (Normal → Recon → Manipulation)")
    plt.grid(axis="x", alpha=0.3)
    plt.tight_layout()
    out_path = os.path.join(REPORTS_DIR, "phase_timeline.png")
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"Saved: {out_path}")


def plot_ops_per_phase(events_df, intervals):
    """Generate operations per phase bar chart."""
    if intervals is None or len(intervals) == 0:
        print("Warning: No phase intervals. Skipping ops_per_phase.png")
        return
    
    if events_df.empty:
        print("Warning: No events. Skipping ops_per_phase.png")
        return
    
    # Tag events with phase
    def get_phase(ts):
        return phase_for_ts(intervals, ts)
    
    events_df["phase"] = events_df["ts"].apply(get_phase)
    
    # Extract operation types
    def is_read(k):
        return "read" in str(k).lower()
    
    def is_write(k):
        return "write" in str(k).lower()
    
    def is_scan(k):
        return "scan" in str(k).lower() or (is_read(k) and "addr" in events_df.columns)
    
    events_df["read_ops"] = events_df["kind"].apply(is_read).astype(int)
    events_df["write_ops"] = events_df["kind"].apply(is_write).astype(int)
    events_df["scan_ops"] = events_df["kind"].apply(is_scan).astype(int)
    events_df["illegal_ops"] = (events_df.get("addr", 0) > 900).astype(int)
    
    agg = events_df.groupby("phase")[["read_ops", "write_ops", "scan_ops", "illegal_ops"]].sum()
    
    plt.figure(figsize=(10, 5))
    agg.plot(kind="bar", ax=plt.gca())
    plt.title("Operations per Phase")
    plt.xlabel("Phase")
    plt.ylabel("Count")
    plt.legend(title="Operation Type")
    plt.xticks(rotation=45)
    plt.grid(axis="y", alpha=0.3)
    plt.tight_layout()
    out_path = os.path.join(REPORTS_DIR, "ops_per_phase.png")
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"Saved: {out_path}")


def plot_suricata_alerts(eve_rows, intervals):
    """Generate Suricata alerts over time line chart with phase background shading."""
    if not eve_rows:
        print("Info: No Suricata events. Skipping suricata_alerts_over_time.png")
        return
    
    alerts = []
    for r in eve_rows:
        if r.get("event_type") == "alert":
            ts_str = r.get("timestamp")
            if ts_str:
                try:
                    dt = datetime.fromisoformat(ts_str.replace("Z", "+00:00"))
                    alerts.append(dt.timestamp())
                except Exception:
                    pass
    
    if not alerts:
        print("Info: No alert events found. Skipping suricata_alerts_over_time.png")
        return
    
    # Create windows
    ts_min = min(alerts)
    ts_max = max(alerts)
    windows = windowize(ts_min, ts_max, WINDOW_SEC)
    
    # Count alerts per window
    counts = []
    for ws, we in windows:
        counts.append(sum(1 for a in alerts if ws <= a < we))
    
    plt.figure(figsize=(14, 5))
    ax = plt.gca()
    
    # Add phase background shading
    base_time = windows[0][0]
    phase_colors = {"normal": "green", "recon": "orange", "manipulation": "red"}
    
    if intervals:
        for phase, start_ts, end_ts in intervals:
            color = phase_colors.get(phase, "gray")
            ax.axvspan(start_ts - base_time, end_ts - base_time, alpha=0.2, color=color, label=phase.capitalize())
    
    # Plot alert counts
    x_vals = [ws - windows[0][0] for ws, _ in windows]
    ax.plot(x_vals, counts, marker="o", linestyle="-", linewidth=2.5, markersize=5, color="darkblue", label="Alerts")
    
    plt.title("Suricata IDS Alerts per 5-Second Window (with Phase Context)")
    plt.xlabel("Seconds from start")
    plt.ylabel("Alert count")
    plt.grid(True, alpha=0.3, linestyle="--")
    
    # Remove duplicate labels
    handles, labels = ax.get_legend_handles_labels()
    by_label = dict(zip(labels, handles))
    ax.legend(by_label.values(), by_label.keys(), loc="upper right")
    
    plt.tight_layout()
    out_path = os.path.join(REPORTS_DIR, "suricata_alerts_over_time.png")
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"Saved: {out_path}")


def plot_feature_correlation(events_df):
    """Generate feature correlation heatmap with proper NaN handling."""
    if events_df.empty:
        print("Warning: No events. Skipping feature_correlation.png")
        return
    
    ts_min = events_df["ts"].min()
    ts_max = events_df["ts"].max()
    windows = windowize(ts_min, ts_max, WINDOW_SEC)
    
    feat_rows = []
    for ws, we in windows:
        w = events_df[(events_df["ts"] >= ws) & (events_df["ts"] < we)]
        if len(w) == 0:
            continue
        
        # Calculate features
        total_ops = len(w)
        read_ops = sum(1 for _ in w[w["kind"].astype(str).str.contains("read", case=False, na=False)].index)
        write_ops = sum(1 for _ in w[w["kind"].astype(str).str.contains("write", case=False, na=False)].index)
        scan_ops = sum(1 for _, row in w.iterrows() if "read" in str(row.get("kind", "")).lower() and row.get("addr", 0) > 100)
        illegal_ops = sum(1 for _, row in w.iterrows() if row.get("addr", 0) > 900)
        
        # Compute ok_rate properly: mean of boolean "ok" column
        if "ok" in w.columns:
            ok_values = w["ok"].astype(bool).values
            ok_rate = float(np.mean(ok_values)) if len(ok_values) > 0 else 1.0
        else:
            ok_rate = 1.0  # Default to 1.0 if no ok column
        
        feat_rows.append({
            "total_ops": total_ops,
            "read_ops": read_ops,
            "write_ops": write_ops,
            "scan_ops": scan_ops,
            "illegal_ops": illegal_ops,
            "ok_rate": ok_rate,
        })
    
    if not feat_rows:
        print("Warning: No feature windows. Skipping feature_correlation.png")
        return
    
    feats = pd.DataFrame(feat_rows)
    
    # Fill NaN values only after all computations are complete
    feats = feats.fillna(0.0)
    
    # Compute correlation
    corr = feats.corr(numeric_only=True)
    
    plt.figure(figsize=(9, 7))
    im = plt.imshow(corr.values, cmap="coolwarm", aspect="auto", vmin=-1, vmax=1)
    cbar = plt.colorbar(im, label="Correlation Coefficient")
    
    # Add correlation values as text annotations
    for i in range(len(corr.columns)):
        for j in range(len(corr.columns)):
            text = plt.text(j, i, f"{corr.values[i, j]:.2f}",
                          ha="center", va="center", color="black", fontsize=9)
    
    plt.xticks(range(len(corr.columns)), corr.columns, rotation=45, ha="right")
    plt.yticks(range(len(corr.columns)), corr.columns)
    plt.title("Feature Correlation Matrix (7 Features, 5-Second Windows)")
    plt.tight_layout()
    out_path = os.path.join(REPORTS_DIR, "feature_correlation.png")
    plt.savefig(out_path, dpi=150, bbox_inches="tight")
    plt.close()
    print(f"Saved: {out_path}")


def plot_model_coefficients(ml_results):
    """Generate model coefficients bar chart."""
    if not ml_results:
        print("Info: No ML results. Skipping model_coefficients.png")
        return
    
    # Extract model info
    if "model" in ml_results and "coefficients" in ml_results["model"]:
        coef = ml_results["model"]["coefficients"]
    elif "coef" in ml_results:
        coef = ml_results["coef"]
        if isinstance(coef, list) and len(coef) > 0:
            coef = coef[0]
    else:
        coef = None
    
    names = ml_results.get("feature_names")
    
    if names and coef:
        if len(names) != len(coef):
            names = names[:len(coef)]
        
        plt.figure(figsize=(10, 5))
        colors = ["red" if c < 0 else "green" for c in coef]
        plt.bar(names, coef, color=colors, alpha=0.7, edgecolor="black")
        plt.title("Logistic Regression Coefficients (Attack vs Normal)")
        plt.xlabel("Feature")
        plt.ylabel("Coefficient Value")
        plt.xticks(rotation=45, ha="right")
        plt.grid(axis="y", alpha=0.3)
        plt.axhline(y=0, color="black", linestyle="-", linewidth=0.8)
        plt.tight_layout()
        out_path = os.path.join(REPORTS_DIR, "model_coefficients.png")
        plt.savefig(out_path, dpi=150, bbox_inches="tight")
        plt.close()
        print(f"Saved: {out_path}")
    else:
        print("Info: No valid feature names or coefficients. Skipping model_coefficients.png")


def main():
    """Main visualization pipeline."""
    print(f"Visualization module starting...", file=sys.stderr)
    print(f"Data dir: {DATA_DIR}", file=sys.stderr)
    print(f"Reports dir: {REPORTS_DIR}", file=sys.stderr)
    
    # Create reports directory if it doesn't exist
    os.makedirs(REPORTS_DIR, exist_ok=True)
    
    # Load data
    labels_rows = read_jsonl(LABELS_FILE)
    events_rows = read_jsonl(EVENTS_FILE)
    eve_rows = read_jsonl(EVE_FILE)
    
    # Check for required files
    if not labels_rows or not events_rows:
        print(
            "ERROR: Missing labels.jsonl or generator_events.jsonl\n"
            "Run 'powershell -ExecutionPolicy Bypass -File .\\scripts\\demo.ps1' first to generate data.",
            file=sys.stderr
        )
        sys.exit(1)
    
    # Parse labels and events
    intervals = parse_labels(labels_rows)
    events_df = pd.DataFrame(events_rows)
    
    # Ensure ts column is numeric
    if "ts" in events_df.columns:
        events_df["ts"] = events_df["ts"].apply(
            lambda x: float(x) if isinstance(x, (int, float)) else datetime.fromisoformat(str(x).replace("Z", "+00:00")).timestamp()
        )
    
    # Generate plots
    print("Generating phase timeline...", file=sys.stderr)
    plot_phase_timeline(intervals)
    
    print("Generating operations per phase...", file=sys.stderr)
    plot_ops_per_phase(events_df.copy(), intervals)
    
    print("Generating Suricata alerts chart...", file=sys.stderr)
    plot_suricata_alerts(eve_rows, intervals)
    
    print("Generating feature correlation...", file=sys.stderr)
    plot_feature_correlation(events_df)
    
    # Load and plot ML results if available
    ml_results = {}
    if os.path.exists(ML_RESULTS_FILE):
        try:
            with open(ML_RESULTS_FILE, "r", encoding="utf-8") as f:
                ml_results = json.load(f)
        except Exception as e:
            print(f"Warning: Could not load ML results: {e}", file=sys.stderr)
    
    print("Generating model coefficients...", file=sys.stderr)
    plot_model_coefficients(ml_results)
    
    print(f"\nVisualization complete. Plots saved to {REPORTS_DIR}", file=sys.stderr)


if __name__ == "__main__":
    main()
