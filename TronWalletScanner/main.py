#!/usr/bin/env python3
"""
Main entry point for the TRON Wallet Scanner application.
This provides a simple CLI interface to run the enhanced analyzer.
"""

import sys
import os
from pathlib import Path

# Add current directory to path for imports
sys.path.insert(0, str(Path(__file__).parent))

from tron_wallet_analyzer import main as analyzer_main

if __name__ == "__main__":
    sys.exit(analyzer_main())