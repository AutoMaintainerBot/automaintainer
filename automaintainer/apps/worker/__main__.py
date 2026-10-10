"""
Worker Plane Entrypoint.
Allows starting the worker daemon directly via:
    python -m automaintainer.apps.worker
"""
import asyncio
import logging
import sys
from automaintainer.apps.worker.daemon import WorkerDaemon

def main():
    logging.basicConfig(
        level=logging.INFO,
        format="%(asctime)s [%(levelname)s] %(name)s: %(message)s"
    )
    daemon = WorkerDaemon()
    try:
        asyncio.run(daemon.start())
    except KeyboardInterrupt:
        daemon.stop()
        logging.info("Worker daemon stopped cleanly.")
        sys.exit(0)

if __name__ == "__main__":
    main()
