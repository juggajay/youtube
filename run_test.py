#!/usr/bin/env python3
"""
Quick test script to run the pipeline in mock mode.

Usage:
    python run_test.py
"""

import sys
import os

# Add src to path
sys.path.insert(0, os.path.dirname(os.path.abspath(__file__)))

from src.utils import setup_logging, load_config
from src.orchestrator import run_pipeline


def main():
    # Setup
    setup_logging()
    load_config()

    print("=" * 60)
    print("PODCAST PIPELINE TEST")
    print("Running in MOCK mode - no API keys required")
    print("=" * 60)
    print()

    # Run pipeline in mock mode
    results = run_pipeline(mock=True)

    print()
    print("=" * 60)
    print("TEST COMPLETE")
    print("=" * 60)
    print(f"Output directory: {results.get('output_dir')}")
    print()
    print("Files generated:")

    output_dir = results.get("output_dir")
    if output_dir and os.path.exists(output_dir):
        for f in os.listdir(output_dir):
            size = os.path.getsize(os.path.join(output_dir, f))
            print(f"  - {f} ({size:,} bytes)")

    print()
    print("Next steps:")
    print("  1. Review the generated files in the output directory")
    print("  2. Add your API keys to .env")
    print("  3. Run again without --mock to use real APIs")


if __name__ == "__main__":
    main()
