"""
Application entry point.

Usage:
    python run.py [--host HOST] [--port PORT] [--reload]
"""

import argparse
import sys
from pathlib import Path

# Ensure app package is importable
sys.path.insert(0, str(Path(__file__).parent))


def main():
    parser = argparse.ArgumentParser(description="Run the DFEO application.")
    parser.add_argument("--host", default="127.0.0.1", help="Bind host (default: 127.0.0.1)")
    parser.add_argument("--port", type=int, default=8000, help="Port (default: 8000)")
    parser.add_argument("--reload", action="store_true", help="Enable auto-reload for development")
    args = parser.parse_args()

    import uvicorn
    uvicorn.run(
        "app.main:app",
        host=args.host,
        port=args.port,
        reload=args.reload,
        log_level="info",
    )


if __name__ == "__main__":
    main()
