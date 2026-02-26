#!/usr/bin/env python3
"""
Simple Modbus TCP server for Phase 1 attack detection.
Listens on 0.0.0.0:5020 with basic register/coil support.
"""

import logging
import asyncio
from pymodbus.server.async_io import StartAsyncTcpServer

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(name)s - %(levelname)s - %(message)s'
)
logger = logging.getLogger('modbus-server')


async def main():
    """Start the Modbus TCP server."""
    logger.info("Starting Modbus TCP server on 0.0.0.0:5020...")
    
    try:
        # Start server with default datastore
        await StartAsyncTcpServer(address=("0.0.0.0", 5020))
    except KeyboardInterrupt:
        logger.info("Server shutting down...")
    except Exception as e:
        logger.error(f"Server error: {e}")


if __name__ == '__main__':
    try:
        asyncio.run(main())
    except KeyboardInterrupt:
        logger.info("Server interrupted")
