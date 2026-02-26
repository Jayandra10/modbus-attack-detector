#!/usr/bin/env python3
"""
Modbus traffic generator for Phase 1.
Generates synthetic attack traffic in three phases: normal, recon, and manipulation.
"""

import time
import json
import logging
from datetime import datetime
from pathlib import Path
from pymodbus.client import AsyncModbusTcpClient
import asyncio

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('traffic-gen')


class TrafficGenerator:
    """Generate Modbus traffic patterns for attack detection testing."""
    
    def __init__(self, host='modbus-server', port=5020, data_dir='/data'):
        self.host = host
        self.port = port
        self.data_dir = Path(data_dir)
        self.data_dir.mkdir(parents=True, exist_ok=True)
        
        self.labels_file = self.data_dir / 'labels.jsonl'
        self.events_file = self.data_dir / 'generator_events.jsonl'
        
        # Clear previous files
        self.labels_file.write_text('')
        self.events_file.write_text('')
        
        self.client = None
        self.start_time = None
    
    async def connect(self):
        """Connect to Modbus server."""
        self.client = AsyncModbusTcpClient(host=self.host, port=self.port)
        logger.info(f"Connecting to {self.host}:{self.port}...")
        connected = await self.client.connect()
        if not connected:
            raise ConnectionError(f"Failed to connect to {self.host}:{self.port}")
        logger.info("Connected successfully")
        self.start_time = time.time()
    
    async def disconnect(self):
        """Disconnect from Modbus server."""
        if self.client:
            try:
                await self.client.close()
            except Exception as e:
                logger.warning(f"Error closing client: {e}")
            logger.info("Disconnected")
    
    def get_timestamp(self):
        """Get current timestamp relative to start."""
        elapsed = time.time() - self.start_time
        return datetime.utcnow().isoformat() + 'Z'
    
    def log_label_marker(self, phase, marker_type):
        """Log phase start/end marker."""
        record = {
            'ts': self.get_timestamp(),
            'phase': phase,
            'event': marker_type  # 'start' or 'end'
        }
        with open(self.labels_file, 'a') as f:
            f.write(json.dumps(record) + '\n')
        logger.info(f"{phase} {marker_type}")
    
    def log_event(self, kind, addr, count=None, value=None, ok=True):
        """Log a traffic event."""
        record = {
            'ts': self.get_timestamp(),
            'kind': kind,  # 'read_regs', 'write_regs', 'read_coils', 'write_coils'
            'addr': addr,
            'ok': ok
        }
        if count is not None:
            record['count'] = count
        if value is not None:
            record['value'] = value
        
        with open(self.events_file, 'a') as f:
            f.write(json.dumps(record) + '\n')
    
    async def phase_normal(self, duration=120):
        """
        Normal phase: periodic holding-register reads at 1 Hz for 120 seconds.
        """
        self.log_label_marker('normal', 'start')
        end_time = time.time() + duration
        addr = 0
        
        while time.time() < end_time:
            try:
                result = await self.client.read_holding_registers(
                    address=addr,
                    count=1,
                    slave=0
                )
                ok = result.isError() is False
                self.log_event('read_regs', addr, count=1, ok=ok)
                addr = (addr + 1) % 100  # Cycle through first 100 registers
                
                # 1 Hz means ~1 second per read
                await asyncio.sleep(1.0)
            except Exception as e:
                logger.warning(f"Error during normal phase: {e}")
                self.log_event('read_regs', addr, count=1, ok=False)
        
        self.log_label_marker('normal', 'end')
    
    async def phase_recon(self, duration=60):
        """
        Recon phase: scan-like burst reads across wide address range (0-900) for 60 seconds.
        """
        self.log_label_marker('recon', 'start')
        end_time = time.time() + duration
        
        while time.time() < end_time:
            try:
                # Scan a random starting address and read a block
                start_addr = (int(time.time() * 100) % 850)  # 0-850
                count = 50  # Read 50 registers at a time
                
                result = await self.client.read_holding_registers(
                    address=start_addr,
                    count=count,
                    slave=0
                )
                ok = result.isError() is False
                self.log_event('read_regs', start_addr, count=count, ok=ok)
                
                # Fast bursts in recon phase
                await asyncio.sleep(0.1)
            except Exception as e:
                logger.warning(f"Error during recon phase: {e}")
                self.log_event('read_regs', 0, count=50, ok=False)
        
        self.log_label_marker('recon', 'end')
    
    async def phase_manipulation(self, duration=60):
        """
        Manipulation phase: write bursts + occasional illegal reads at high addresses (950-1200) for 60 seconds.
        """
        self.log_label_marker('manipulation', 'start')
        end_time = time.time() + duration
        write_count = 0
        
        while time.time() < end_time:
            try:
                # Write bursts
                write_addr = (write_count % 50)
                value = (int(time.time() * 1000) % 65535)
                
                result = await self.client.write_register(
                    address=write_addr,
                    value=value,
                    slave=0
                )
                ok = result.isError() is False
                self.log_event('write_regs', write_addr, value=value, ok=ok)
                write_count += 1
                
                # Occasional reads at high (potentially illegal) addresses
                if write_count % 3 == 0:
                    high_addr = 950 + (write_count % 250)  # 950-1200
                    try:
                        result = await self.client.read_holding_registers(
                            address=high_addr,
                            count=1,
                            slave=0
                        )
                        ok = result.isError() is False
                        self.log_event('read_regs', high_addr, count=1, ok=ok)
                    except Exception as e:
                        self.log_event('read_regs', high_addr, count=1, ok=False)
                
                await asyncio.sleep(0.05)
            except Exception as e:
                logger.warning(f"Error during manipulation phase: {e}")
                self.log_event('write_regs', 0, value=0, ok=False)
        
        self.log_label_marker('manipulation', 'end')
    
    async def run(self):
        """Run the complete traffic generation sequence."""
        try:
            await self.connect()
            
            logger.info("Starting traffic generation...")
            
            # Run the three phases in sequence
            await self.phase_normal(duration=120)
            await self.phase_recon(duration=60)
            await self.phase_manipulation(duration=60)
            
            logger.info("Traffic generation complete")
            
        finally:
            await self.disconnect()


async def main():
    """Main entry point."""
    gen = TrafficGenerator()
    await gen.run()


if __name__ == '__main__':
    asyncio.run(main())
