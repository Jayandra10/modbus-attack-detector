#!/usr/bin/env python3
"""
Phase 2: ML training and triage for Modbus attack detection.

Reads labels.jsonl, generator_events.jsonl, and optionally eve.json.
Creates 5-second windows, computes features, trains LogisticRegression.
Outputs classification report and saves ml_results.json.
"""

import json
import logging
import sys
from datetime import datetime
from pathlib import Path

import numpy as np
import pandas as pd
from sklearn.linear_model import LogisticRegression
from sklearn.metrics import classification_report, confusion_matrix

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('ml-train')

DATA_DIR = Path('/data')
LABELS_FILE = DATA_DIR / 'labels.jsonl'
EVENTS_FILE = DATA_DIR / 'generator_events.jsonl'
EVE_FILE = DATA_DIR / 'suricata' / 'eve.json'
OUTPUT_FILE = DATA_DIR / 'ml_results.json'


def load_labels():
    """Load phase labels from labels.jsonl and return phase intervals."""
    if not LABELS_FILE.exists():
        logger.error("labels.jsonl not found")
        sys.exit(1)
    
    labels = []
    with open(LABELS_FILE) as f:
        for line in f:
            if line.strip():
                labels.append(json.loads(line))
    
    if not labels:
        logger.error("labels.jsonl is empty")
        sys.exit(1)
    
    logger.info(f"Loaded {len(labels)} label markers")
    return labels


def build_phase_intervals(labels):
    """
    Build phase intervals from label markers.
    Returns dict: {phase_name: [(start_ts, end_ts), ...]}
    """
    phases = {}
    current_phase = None
    start_ts = None
    
    for label in labels:
        phase = label.get('phase')
        event = label.get('event')
        ts = label.get('ts')
        
        if not ts:
            continue
        
        # Parse ISO timestamp to float
        try:
            dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
            ts_float = dt.timestamp()
        except Exception as e:
            logger.warning(f"Could not parse timestamp {ts}: {e}")
            continue
        
        if event == 'start':
            current_phase = phase
            start_ts = ts_float
        elif event == 'end' and current_phase == phase and start_ts is not None:
            if phase not in phases:
                phases[phase] = []
            phases[phase].append((start_ts, ts_float))
            current_phase = None
            start_ts = None
    
    logger.info(f"Phase intervals: {phases}")
    return phases


def load_events():
    """Load traffic events from generator_events.jsonl."""
    if not EVENTS_FILE.exists():
        logger.error("generator_events.jsonl not found")
        sys.exit(1)
    
    events = []
    with open(EVENTS_FILE) as f:
        for line in f:
            if line.strip():
                events.append(json.loads(line))
    
    if not events:
        logger.error("generator_events.jsonl is empty")
        sys.exit(1)
    
    logger.info(f"Loaded {len(events)} traffic events")
    return events


def parse_timestamp(ts_str):
    """Parse ISO timestamp string to float."""
    try:
        dt = datetime.fromisoformat(ts_str.replace('Z', '+00:00'))
        return dt.timestamp()
    except Exception:
        return None


def load_suricata_alerts():
    """Load and index Suricata alerts by timestamp."""
    alerts_by_ts = {}
    
    if not EVE_FILE.exists():
        logger.warning(f"{EVE_FILE} not found; suricata_alerts will be 0")
        return alerts_by_ts
    
    try:
        with open(EVE_FILE) as f:
            for line in f:
                if line.strip():
                    evt = json.loads(line)
                    if evt.get('event_type') == 'alert':
                        ts = evt.get('timestamp')
                        if ts:
                            # Parse timestamp
                            try:
                                dt = datetime.fromisoformat(ts.replace('Z', '+00:00'))
                                ts_float = dt.timestamp()
                                if ts_float not in alerts_by_ts:
                                    alerts_by_ts[ts_float] = 0
                                alerts_by_ts[ts_float] += 1
                            except Exception:
                                pass
        logger.info(f"Loaded {len(alerts_by_ts)} alert timestamps from eve.json")
    except Exception as e:
        logger.warning(f"Error loading eve.json: {e}")
    
    return alerts_by_ts


def create_features(events, phase_intervals, alerts_by_ts, window_size=5):
    """
    Create feature matrix with 5-second windows.
    
    Returns:
        df: DataFrame with features and labels
        timestamps: list of window start timestamps
    """
    if not events:
        logger.error("No events to process")
        sys.exit(1)
    
    # Parse all event timestamps
    event_data = []
    for evt in events:
        ts_str = evt.get('ts')
        ts = parse_timestamp(ts_str)
        if ts is not None:
            event_data.append({
                'ts': ts,
                'kind': evt.get('kind', ''),
                'addr': evt.get('addr', 0),
                'ok': evt.get('ok', True)
            })
    
    if not event_data:
        logger.error("No valid events found")
        sys.exit(1)
    
    event_df = pd.DataFrame(event_data)
    min_ts = event_df['ts'].min()
    max_ts = event_df['ts'].max()
    
    logger.info(f"Event time range: {min_ts:.2f} to {max_ts:.2f}")
    
    # Create 5-second windows
    windows = []
    window_start = int(min_ts)
    
    while window_start < max_ts:
        window_end = window_start + window_size
        windows.append((window_start, window_end))
        window_start = window_end
    
    logger.info(f"Created {len(windows)} windows of {window_size}s each")
    
    # Build feature matrix
    rows = []
    timestamps = []
    
    for win_start, win_end in windows:
        # Filter events in this window
        mask = (event_df['ts'] >= win_start) & (event_df['ts'] < win_end)
        win_events = event_df[mask]
        
        # Compute features
        total_ops = len(win_events)
        read_ops = len(win_events[win_events['kind'] == 'read_regs'])
        write_ops = len(win_events[win_events['kind'] == 'write_regs'])
        scan_ops = len(win_events[
            (win_events['kind'] == 'read_regs') & 
            (win_events['addr'] > 100)
        ])
        illegal_ops = len(win_events[win_events['addr'] > 900])
        ok_rate = win_events['ok'].mean() if len(win_events) > 0 else 1.0
        
        # Count Suricata alerts in this window
        suricata_alerts = sum(
            count for ts, count in alerts_by_ts.items()
            if win_start <= ts < win_end
        )
        
        # Determine label: 1 if window overlaps attack phases, 0 otherwise
        label = 0
        for phase_name, intervals in phase_intervals.items():
            if phase_name in ['recon', 'manipulation']:
                for phase_start, phase_end in intervals:
                    if win_start < phase_end and win_end > phase_start:
                        label = 1
                        break
            if label == 1:
                break
        
        rows.append({
            'ts': win_start,
            'total_ops': total_ops,
            'read_ops': read_ops,
            'write_ops': write_ops,
            'scan_ops': scan_ops,
            'illegal_ops': illegal_ops,
            'ok_rate': ok_rate,
            'suricata_alerts': suricata_alerts,
            'label': label
        })
        
        timestamps.append(win_start)
    
    df = pd.DataFrame(rows)
    logger.info(f"Feature matrix shape: {df.shape}")
    logger.info(f"Label distribution:\n{df['label'].value_counts()}")
    
    return df, timestamps


def train_model(df):
    """Train LogisticRegression classifier."""
    if df.shape[0] < 2:
        logger.error("Not enough samples to train")
        sys.exit(1)
    
    feature_cols = [
        'total_ops', 'read_ops', 'write_ops', 'scan_ops', 
        'illegal_ops', 'ok_rate', 'suricata_alerts'
    ]
    
    X = df[feature_cols].values
    y = df['label'].values
    
    logger.info(f"Training on {X.shape[0]} samples with {X.shape[1]} features")
    
    model = LogisticRegression(random_state=42, max_iter=1000)
    model.fit(X, y)
    
    y_pred = model.predict(X)
    
    # Print classification report
    logger.info("\n=== Classification Report ===")
    logger.info("\n" + classification_report(y, y_pred, target_names=['normal', 'attack']))
    
    # Print confusion matrix
    cm = confusion_matrix(y, y_pred)
    logger.info("\n=== Confusion Matrix ===")
    logger.info(f"\nTN={cm[0,0]}, FP={cm[0,1]}")
    logger.info(f"FN={cm[1,0]}, TP={cm[1,1]}\n")
    
    return model, feature_cols


def save_results(model, feature_cols, n_samples):
    """Save model and results to ml_results.json."""
    results = {
        'timestamp': datetime.utcnow().isoformat() + 'Z',
        'n_samples': n_samples,
        'feature_names': feature_cols,
        'model': {
            'coefficients': model.coef_[0].tolist(),
            'intercept': float(model.intercept_[0]),
            'classes': model.classes_.tolist()
        }
    }
    
    with open(OUTPUT_FILE, 'w') as f:
        json.dump(results, f, indent=2)
    
    logger.info(f"Results saved to {OUTPUT_FILE}")


def main():
    """Main training pipeline."""
    logger.info("Starting Phase 2 ML training...")
    
    # Load labels and build phase intervals
    labels = load_labels()
    phase_intervals = build_phase_intervals(labels)
    
    # Load events
    events = load_events()
    
    # Load Suricata alerts (optional)
    alerts_by_ts = load_suricata_alerts()
    
    # Create features
    df, timestamps = create_features(events, phase_intervals, alerts_by_ts)
    
    # Train model
    model, feature_cols = train_model(df)
    
    # Save results
    save_results(model, feature_cols, df.shape[0])
    
    logger.info("Phase 2 ML training complete!")
    print("\n✅ ML training successful. Results saved to /data/ml_results.json")


if __name__ == '__main__':
    main()
