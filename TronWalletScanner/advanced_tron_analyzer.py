#!/usr/bin/env python3
"""
Advanced TRON Wallet Analyzer

A comprehensive tool for analyzing TRON blockchain addresses with enhanced features:
- Support for both TronGrid and Tronscan APIs
- ML-based anomaly detection
- Malicious wallet detection
- Enhanced visualization options
- Efficient caching mechanism with checkpoint support
- Detailed transaction hash tracking
- Expanded exchange detection database
"""

import os
import sys
import json
import time
import logging
import hashlib
import base58
import random
import asyncio
import aiohttp
import shutil
import pickle
from datetime import datetime, timedelta
from pathlib import Path
from typing import List, Dict, Any, Set, Tuple, Optional
import concurrent.futures

import numpy as np
import pandas as pd
import networkx as nx
try:
    from pyvis.network import Network
    PYVIS_AVAILABLE = True
except ImportError:
    PYVIS_AVAILABLE = False
    Network = None
from rich.console import Console
from rich.progress import Progress, TextColumn, BarColumn, TimeElapsedColumn, TimeRemainingColumn, SpinnerColumn, MofNCompleteColumn
from rich.table import Table
from rich.panel import Panel
from rich.prompt import Confirm
from rich import box

try:
    from clean_network_generator import CleanTronNetworkGenerator
except ImportError:
    CleanTronNetworkGenerator = None

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("tron_analyzer")

# Rich console for pretty output
console = Console()

# API endpoints
TRONGRID_API_URL = "https://api.trongrid.io"
TRONSCAN_API_URL = "https://apilist.tronscan.org/api"

# Cache and results directories
CACHE_DIR = Path(".cache/tron_analyzer")
CHECKPOINT_DIR = Path(".cache/tron_analyzer/checkpoints")
RESULTS_DIR = Path("results")
VIZ_DIR = Path("results/visualizations")
REPORT_DIR = Path("results/reports")

# Create directories if they don't exist
for directory in [CACHE_DIR, CHECKPOINT_DIR, RESULTS_DIR, VIZ_DIR, REPORT_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

# Expanded list of known TRON exchanges and platforms
KNOWN_EXCHANGES = {
    # Binance addresses
    "TVj7RNVHy6thbM7BWdSe9G6gXwKhjhdNZS": "Binance",
    "TNaRAoMmrBnZZYA9HKkjYzZrQLpjDC8mRs": "Binance",
    "TAUN6FwrnwwmaEqYcckffC7wYmbaS6cBiX": "Binance",
    "TW8b5sKWJwvWVYwcwogH4Pd8ibfmDKBPZ8": "Binance",
    "TBcQvQbFENK5YaHYVZV1ixYG8YZqEbVAvv": "Binance",
    "TCYsVHPGQBVbTSrhpH2gRaon3vNrAVGP4t": "Binance",
    "THvZCrPVqgd5nWJJHFFoH33QnFundqTM58": "Binance",
    "TMmL915RT7brUVPJ57VxEGs5JQK1UiJR7A": "Binance",

    # Poloniex addresses
    "TCyhhCBHy6pv7XHZgazpaiJJHA3qiE1dFJ": "Poloniex",
    "TS3uEnTCwUuK3H9jzEBuPFt5ifagP1t4tx": "Poloniex",
    "TBcUXvJUn9CFi3Lage2cSqZBGNEJihzQoi": "Poloniex",

    # Huobi addresses
    "TQZskDJJRGAHifeJ5LaQTKuefKF5Pwcfq8": "Huobi",
    "TMLMSuyygN1fL5HFNQoKBRcGKgxGQR5Zdm": "Huobi",
    "TK6kgx3Fsr7mxYtX9s3fdpc9q78WWJceVJ": "Huobi",
    "TWGxDrGgwvLDw9izEwTKXaXcPCcXKVfXVm": "Huobi",
    "TMaL5JXvn9U3JyWMmr5X9aZfmimPBmxFYa": "Huobi",

    # Bittrex addresses
    "TDZtL3r5iXkufQT4hswKCbG4AW6r3H9mwJ": "Bittrex",
    "TAVqDyhnE1rJgFpoE8jztvfBZ5JNbBdhwQ": "Bittrex",

    # OKX addresses
    "TAzsQ3C1t2Q74YXytXKVcJJSCKbLrq9zPt": "OKX",
    "TKyVRJn6HGE8Lhss23DuUtL9NkCseezSGj": "OKX",
    "TCGQGfzZGyJTdJ9whZxaKJnN5jMxZQeXkr": "OKX",
    "TXkgySYqXCB6fWX9569R49qX5sUNPWPTqC": "OKX",

    # KuCoin addresses
    "TFEZYzrvi1MnDqpzijZesH1Df7znn8QgXm": "KuCoin",
    "TUv34RFkszxhWYiJgTazdrwYECDnaoPwGu": "KuCoin",
    "TSZQj6xF2S6rxMK7Vi7FqrX9DQwUUHyQGz": "KuCoin",

    # Kraken addresses
    "TUSi3MK8FKicpFBfiaLTEjQrEwP8i4iLMR": "Kraken",
    "THWQoggJDDsMNqUbF6UmAZA6qKcW3HqTbs": "Kraken",

    # Gate.io addresses
    "TTVZ7f8eM5YRnBHYUXW8CMxvcnxiE2Z6Lg": "Gate.io",
    "TJJQQCZKvXXXyVPKZKJRzHtmQVqxRgVDNS": "Gate.io",

    # Bitfinex addresses
    "TKJZuQzRu1bxMjyHjZ6TKRzZCQr3GBtsNk": "Bitfinex",
    "TVBKrzCW5JjUXBTRvrGU7QSMC2DHZBarxk": "Bitfinex",

    # Bybit addresses
    "TXFBqBbqJommqZf7BV8NNYzePh97UmJodJ": "Bybit",
    "TBE16g1DCQCiPXRuPcW3P8QTx4NXXzbPQs": "Bybit",
    "TL94Xyn7c2JysNCVHmyWw3qYdvtcQPRihY": "Bybit",

    # Crypto.com addresses
    "TQCQnHZXEzYqXq1ZUgwKxjJVXJrLopCCvg": "Crypto.com",
    "TPqUBWswJfNJGxkxdQzxvMwxXm8zBfNQZA": "Crypto.com",

    # Bithumb addresses
    "TWjkoz18Y7wyD1BdYPmk5fFQCbR2aSbf1Q": "Bithumb",
    "TAGjT1FhiLmNGagRQxqY3jCTNVDVaWHUPZ": "Bithumb",

    # Bitget addresses
    "TKG6jZy2rEKPNfLN3jbPvvNxNNAYrEnGxp": "Bitget",
    "THQHhEZHBqeoN4QRv4aqYcciUbSNz9fgDu": "Bitget",

    # Coinbase addresses
    "TWd4WrZ9wn84f5x1hZhL4DHvk738ns5jwb": "Coinbase",
    "THR9rY4Kx4gMLcZqwuMEVuwekcoFMuGFAE": "Coinbase",

    # DeFi platforms
    # JustLend (DeFi lending platform)
    "TMzxVSpwuX5FNKcFiVLBuLsLaGNUwBPKZv": "JustLend",
    "TXj9gEUsXv7JQs7CBf1pQNZbkcBSqTNBRW": "JustLend",

    # SunSwap (DEX)
    "TKzxdSv2FZKQrEqkKVgp5DcwEXBEKMg2Ax": "SunSwap",
    "TGjYzgCyPobsNS9n6WcbdLVR9dH7mCmzxZ": "SunSwap",

    # PoloniDEX (DEX)
    "TW2BfCv4aQQQsv7QpEpLPotUZ7QKC5uXto": "PoloniDEX",

    # JustSwap (DEX)
    "TN3W4H6rK2ce4vX9YnFQHwKENnHjoxb3m9": "JustSwap",

    # APENFT Marketplace
    "TUxYHjyQgFGYNL1uCJu1HzyGTduZh6TpwC": "APENFT",

    # PancakeSwap (on TRON)
    "TEQvUgksB9KPiXnz4BJqKRMGYxBW2yk8s7": "PancakeSwap",

    # Staking platforms
    "TAihbgDWBK1QTS5gsk7evgGMgDQA5t8mnS": "Staking Platform",
    "TX2xn1fxQyGCYvYBPh9NC6et7Xqm5JyGBP": "Staking Platform",

    # WazirX (Indian Exchange)
    "TBAo7gJce4GwUQS8QbYAvJst5dK7kJxmxH": "WazirX",

    # MXC Exchange
    "TYukBQZ2XXCcRCReAUgVHcArB2qxQhRZo2": "MXC",

    # ZB Exchange
    "TZFH9KhZ9xEyj39SA7aJUDvpJHCdtcX8Qk": "ZB",

    # BitMart
    "TTCpjhTvLntQPZkJmVwxRSQBvdcnwcKvtz": "BitMart"
}

# Extended list of known malicious/scam addresses and patterns
KNOWN_MALICIOUS = {
    # Phishing and scam addresses
    "TJ7qh7h7Dv5AkVa7KNKLrQ77QCB9K5Lfm6": {"type": "Phishing", "confidence": 0.95, "description": "Known TronLink phishing address"},
    "TYQRRFZDTccBUFJVKoTkFpZX3i1iKBKQKD": {"type": "Ponzi Scheme", "confidence": 0.92, "description": "Associated with a TRON-based Ponzi scheme"},
    "TWz6ivMrRpiTpGqpgVdd3zGQj6BtfQPZPq": {"type": "Scam Token", "confidence": 0.97, "description": "Distributes fraudulent tokens"},

    # Blacklisted addresses
    "TFTGQvhETtMPspPVvQZJjDrLTAJsXCnMqV": {"type": "Blacklisted", "confidence": 0.99, "description": "Associated with ransomware payments"},
    "TC6eV9WC9RE2vBJVQk9Rt8L6YqEu1dxZVK": {"type": "Money Laundering", "confidence": 0.94, "description": "Known money laundering operation"},
    "TEg6xBYV3n9TkZr42bKTW8aX5aak9waUBv": {"type": "Theft", "confidence": 0.98, "description": "Exchange hack proceeds"},

    # Fraud and scam platforms
    "TUCnVLpQTBRYNPfPzqX8Lf8X3M1JJYKtxE": {"type": "Fake Exchange", "confidence": 0.96, "description": "Fraudulent exchange that steals deposits"},
    "TJhzwLHjGQPKMeDUFV51XfhK6FqKwQQhM1": {"type": "Scam Project", "confidence": 0.93, "description": "Connected to exit scam project"},
    "TWb8NkVR1cMiKPK9TrTXpBmzLNrWzJhPJP": {"type": "Wash Trading", "confidence": 0.87, "description": "Wash trading operation"},

    # Exploit associated addresses
    "TXkVw8L2eV8CQmytVS6juH9X8rQoS5ydyM": {"type": "Smart Contract Exploit", "confidence": 0.96, "description": "Known to exploit vulnerable smart contracts"},
    "TG5ZW3JYzkBGmx6P96rGJfvZKPvMKtg4ik": {"type": "Flash Loan Attack", "confidence": 0.92, "description": "Associated with flash loan attacks on DeFi platforms"},

    # Malware and ransomware
    "TAwEqLUVbArYnJrTqZqkPx44ynvSdVUsMu": {"type": "Ransomware", "confidence": 0.99, "description": "Ransomware payment collection address"},
    "TVXXajMZ62yWgLLHHchCjYvRiTMnTWcVC3": {"type": "Malware", "confidence": 0.95, "description": "Associated with malware distribution"},

    # Mixers and tumblers
    "TUS9KJkKmJ9Abwon5Jz2JPQCjKvv42Zxhg": {"type": "Mixer", "confidence": 0.91, "description": "TRON-based mixing service to obscure transaction sources"},
    "TGf31u4mJYxSDJ4WQ8yUVeJFQW28gLBZKd": {"type": "Tumbler", "confidence": 0.89, "description": "Transaction obfuscation service"},

    # Sanctioned addresses
    "TJMvabigUJrk3QEfqZSQXzxijVFYxrAVts": {"type": "Sanctions", "confidence": 0.98, "description": "Subject to international sanctions"},
    "TRoHgbJQPuZcj38S2JHDJJxZCdQjGkgDXk": {"type": "Sanctions", "confidence": 0.99, "description": "Sanctioned entity wallet"}
}

# Import all enhanced databases
try:
    from exchanges_database import (
        get_exchange_info, 
        is_exchange_address, 
        is_defi_address,
        get_all_exchanges,
        TRON_EXCHANGES
    )
    EXCHANGES_DB_AVAILABLE = True
    # Legacy support - convert to old format for backward compatibility
    KNOWN_EXCHANGES = {addr: info["name"] for addr, info in TRON_EXCHANGES.items()}
except ImportError:
    EXCHANGES_DB_AVAILABLE = False
    KNOWN_EXCHANGES = {}

try:
    from malicious_addresses_database import (
        is_address_malicious,
        get_address_information as get_malicious_info,
        get_hacker_group_for_address,
        get_scam_domains_for_address,
        MALICIOUS_ADDRESSES
    )
    MALICIOUS_DB_AVAILABLE = True
except ImportError:
    MALICIOUS_DB_AVAILABLE = False
    MALICIOUS_ADDRESSES = {}

try:
    from token_classification_database import (
        get_token_info,
        is_known_token,
        is_scam_token,
        get_scam_token_info,
        TRON_TOKENS
    )
    TOKEN_DB_AVAILABLE = True
except ImportError:
    TOKEN_DB_AVAILABLE = False
    TRON_TOKENS = {}

try:
    from smart_contracts_database import (
        get_contract_info,
        is_smart_contract,
        is_vulnerable_contract,
        get_vulnerability_info,
        TRON_SMART_CONTRACTS
    )
    CONTRACTS_DB_AVAILABLE = True
except ImportError:
    CONTRACTS_DB_AVAILABLE = False
    TRON_SMART_CONTRACTS = {}

try:
    from ml_anomaly_detection import (
        AnomalyDetector,
        SUSPICIOUS_PATTERNS
    )
    ML_AVAILABLE = True
except ImportError:
    ML_AVAILABLE = False
    AnomalyDetector = None

class AdvancedTronAnalyzer:
    """Advanced analyzer for TRON addresses with enhanced features."""

    def __init__(self, trongrid_api_key=None, tronscan_api_key=None, 
                 max_transactions=100, depth=2, use_cache=True, 
                 checkpoint_interval=5, min_connection_weight=0.01):
        """
        Initialize the advanced TRON analyzer.

        Args:
            trongrid_api_key: API key for TronGrid
            tronscan_api_key: API key for Tronscan
            max_transactions: Maximum number of transactions to fetch per address
            depth: Connection analysis depth (1=direct, 2=second-degree, etc.)
            use_cache: Whether to use caching for API results
            checkpoint_interval: Save analysis checkpoint after this many addresses
            min_connection_weight: Minimum transaction value to consider a connection
        """
        self.trongrid_api_key = trongrid_api_key or os.getenv("TRONGRID_API_KEY", "")
        self.tronscan_api_key = tronscan_api_key or os.getenv("TRONSCAN_API_KEY", "")
        self.max_transactions = max_transactions
        self.depth = depth
        self.use_cache = use_cache
        self.checkpoint_interval = checkpoint_interval
        self.min_connection_weight = min_connection_weight

        # Data storage
        self.addresses_data = {}
        self.connections = []
        self.transactions = {}
        self.token_transfers = {}
        self.checkpoints = []

        # Statistics
        self.stats = {
            "api_calls": 0,
            "cache_hits": 0,
            "addresses_analyzed": 0,
            "transactions_processed": 0,
            "connections_found": 0,
            "runtime": 0
        }

        # Setup headers
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }

        if self.trongrid_api_key:
            self.headers["TRON-PRO-API-KEY"] = self.trongrid_api_key

        self.tronscan_headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
            "TRON-PRO-API-KEY": self.tronscan_api_key if self.tronscan_api_key else ""
        }

        # Display API information
        self._print_api_status()

    def _print_api_status(self):
        """Print the status of API keys."""
        trongrid_status = "[green]✓ Available[/green]" if self.trongrid_api_key else "[yellow]⚠️ Not found[/yellow]"
        tronscan_status = "[green]✓ Available[/green]" if self.tronscan_api_key else "[yellow]⚠️ Not found[/yellow]"

        table = Table(title="API Configuration", box=box.ROUNDED)
        table.add_column("API", style="cyan")
        table.add_column("Status", justify="center")

        table.add_row("TronGrid", trongrid_status)
        table.add_row("Tronscan", tronscan_status)

        console.print(table)

        if not self.trongrid_api_key and not self.tronscan_api_key:
            console.print(Panel(
                "[yellow]⚠️ No API keys found. Analysis will be limited and may encounter rate limits.[/yellow]",
                title="Warning",
                border_style="yellow"
            ))

    def _get_cache_key(self, operation, params):
        """Generate a cache key based on operation and parameters."""
        key = f"{operation}_{json.dumps(params, sort_keys=True)}"
        return hashlib.md5(key.encode()).hexdigest()

    def _get_cache_path(self, cache_key):
        """Get the path to a cached file."""
        return CACHE_DIR / f"{cache_key}.json"

    def _get_from_cache(self, operation, params):
        """Get data from cache if available and not expired."""
        if not self.use_cache:
            return None

        cache_key = self._get_cache_key(operation, params)
        cache_path = self._get_cache_path(cache_key)

        if not cache_path.exists():
            return None

        try:
            # Check if cache is expired (default: 24 hours)
            mod_time = datetime.fromtimestamp(cache_path.stat().st_mtime)
            if datetime.now() - mod_time > timedelta(hours=24):
                return None

            # Read cache
            with open(cache_path, 'r') as f:
                data = json.load(f)
                self.stats["cache_hits"] += 1
                return data
        except Exception as e:
            logger.debug(f"Error reading cache: {str(e)}")
            return None

    def _save_to_cache(self, operation, params, data):
        """Save data to cache."""
        if not self.use_cache:
            return

        cache_key = self._get_cache_key(operation, params)
        cache_path = self._get_cache_path(cache_key)

        try:
            with open(cache_path, 'w') as f:
                json.dump(data, f)
        except Exception as e:
            logger.debug(f"Error saving to cache: {str(e)}")

    def clear_cache(self):
        """Clear the cache directory."""
        if Confirm.ask("Are you sure you want to clear the cache?"):
            shutil.rmtree(CACHE_DIR)
            CACHE_DIR.mkdir(parents=True, exist_ok=True)
            CHECKPOINT_DIR.mkdir(parents=True, exist_ok=True)
            console.print("[green]Cache cleared successfully.[/green]")

    def save_checkpoint(self, index=None):
        """Save analysis checkpoint."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        index_str = f"_{index}" if index is not None else ""
        checkpoint_file = CHECKPOINT_DIR / f"checkpoint{index_str}_{timestamp}.pkl"

        data = {
            "addresses_data": self.addresses_data,
            "connections": self.connections,
            "transactions": self.transactions,
            "token_transfers": self.token_transfers,
            "stats": self.stats,
            "timestamp": timestamp
        }

        try:
            with open(checkpoint_file, 'wb') as f:
                pickle.dump(data, f)

            self.checkpoints.append(checkpoint_file)
            console.print(f"[green]Checkpoint saved: {checkpoint_file}[/green]")
            return checkpoint_file
        except Exception as e:
            console.print(f"[red]Error saving checkpoint: {str(e)}[/red]")
            return None

    def load_checkpoint(self, checkpoint_path):
        """Load analysis from checkpoint."""
        try:
            with open(checkpoint_path, 'rb') as f:
                data = pickle.load(f)

            self.addresses_data = data["addresses_data"]
            self.connections = data["connections"]
            self.transactions = data["transactions"]
            self.token_transfers = data.get("token_transfers", {})
            self.stats = data["stats"]

            console.print(f"[green]Checkpoint loaded: {checkpoint_path}[/green]")
            console.print(f"[green]Loaded data for {len(self.addresses_data)} addresses and {len(self.connections)} connections.[/green]")
            return True
        except Exception as e:
            console.print(f"[red]Error loading checkpoint: {str(e)}[/red]")
            return False

    def list_checkpoints(self):
        """List available checkpoints."""
        checkpoints = list(CHECKPOINT_DIR.glob("checkpoint*.pkl"))
        if not checkpoints:
            console.print("[yellow]No checkpoints found.[/yellow]")
            return []

        table = Table(title="Available Checkpoints")
        table.add_column("Index", justify="right")
        table.add_column("Filename")
        table.add_column("Date")
        table.add_column("Size")

        for i, cp in enumerate(sorted(checkpoints, key=lambda p: p.stat().st_mtime, reverse=True)):
            size_kb = cp.stat().st_size / 1024
            mtime = datetime.fromtimestamp(cp.stat().st_mtime).strftime("%Y-%m-%d %H:%M:%S")
            table.add_row(str(i+1), cp.name, mtime, f"{size_kb:.1f} KB")

        console.print(table)
        return checkpoints

    def validate_tron_address(self, address):
        """Validate a TRON address."""
        if not isinstance(address, str) or not address.startswith("T") or len(address) != 34:
            return False

        try:
            # Try decoding as base58
            base58.b58decode_check(address)
            return True
        except:
            return False

    async def fetch_account_info_async(self, session, address):
        """Fetch account information asynchronously."""
        # Try to get from cache first
        cache_data = self._get_from_cache("account_info", {"address": address})
        if cache_data:
            return cache_data

        self.stats["api_calls"] += 1

        # Start with TronGrid API
        try:
            async with session.get(
                f"{TRONGRID_API_URL}/v1/accounts/{address}",
                headers=self.headers,
                timeout=10
            ) as response:
                if response.status == 200:
                    data = await response.json()

                    if "data" in data and len(data["data"]) > 0:
                        account_data = data["data"][0]
                        balance = int(account_data.get("balance", 0)) / 1_000_000

                        # Extract token information with enhanced details
                        tokens = []
                        if "trc20" in account_data:
                            trc20_data = account_data["trc20"]
                            try:
                                # Handle both dict and list formats
                                if isinstance(trc20_data, dict):
                                    for contract, balance_str in trc20_data.items():
                                        try:
                                            # Get token info first to get correct decimals
                                            token_info = await self._get_token_info(session, contract)
                                            decimals = token_info.get("decimals", 6)
                                            token_balance = int(balance_str) / (10 ** decimals)
                                            tokens.append({
                                                "contract": contract,
                                                "balance": token_balance,
                                                "name": token_info.get("name", "Unknown"),
                                                "symbol": token_info.get("symbol", "???"),
                                                "decimals": decimals
                                            })
                                        except:
                                            pass
                                elif isinstance(trc20_data, list):
                                    for token_item in trc20_data:
                                        if isinstance(token_item, list) and len(token_item) >= 2:
                                            contract, balance_str = token_item[0], token_item[1]
                                            try:
                                                # Get token info first to get correct decimals
                                                token_info = await self._get_token_info(session, contract)
                                                decimals = token_info.get("decimals", 6)
                                                token_balance = int(balance_str) / (10 ** decimals)
                                                tokens.append({
                                                    "contract": contract,
                                                    "balance": token_balance,
                                                    "name": token_info.get("name", "Unknown"),
                                                    "symbol": token_info.get("symbol", "???"),
                                                    "decimals": decimals
                                                })
                                            except:
                                                pass
                            except Exception as e:
                                logger.debug(f"Could not parse TRC20 token data: {str(e)}")

                        result = {
                            "address": address,
                            "balance": balance,
                            "exists": True,
                            "tokens": tokens,
                            "api_source": "trongrid",
                            "is_exchange": address in KNOWN_EXCHANGES,
                            "exchange_name": KNOWN_EXCHANGES.get(address, ""),
                            "is_malicious": address in KNOWN_MALICIOUS,
                            "malicious_info": KNOWN_MALICIOUS.get(address, {})
                        }

                        self._save_to_cache("account_info", {"address": address}, result)
                        return result
        except Exception as e:
            console.print(f"[yellow]TronGrid API error for {address}: {str(e)}[/yellow]")

        # Fall back to Tronscan API
        try:
            async with session.get(
                f"{TRONSCAN_API_URL}/account?address={address}",
                headers=self.tronscan_headers,
                timeout=10
            ) as response:
                if response.status == 200:
                    data = await response.json()

                    if "balance" in data:
                        balance = int(data.get("balance", 0)) / 1_000_000

                        # Extract token information from Tronscan
                        tokens = []
                        try:
                            async with session.get(
                                f"{TRONSCAN_API_URL}/account/tokens?address={address}&limit=20",
                                headers=self.tronscan_headers,
                                timeout=10
                            ) as token_response:
                                if token_response.status == 200:
                                    token_data = await token_response.json()
                                    if "data" in token_data:
                                        for token in token_data["data"]:
                                            try:
                                                tokens.append({
                                                    "contract": token.get("tokenId", ""),
                                                    "name": token.get("name", "Unknown"),
                                                    "symbol": token.get("tokenAbbr", ""),
                                                    "balance": float(token.get("balance", 0)) / (10 ** int(token.get("tokenDecimal", 6)))
                                                })
                                            except:
                                                pass
                        except:
                            pass

                        result = {
                            "address": address,
                            "balance": balance,
                            "exists": True,
                            "tokens": tokens,
                            "api_source": "tronscan",
                            "is_exchange": address in KNOWN_EXCHANGES,
                            "exchange_name": KNOWN_EXCHANGES.get(address, ""),
                            "is_malicious": address in KNOWN_MALICIOUS,
                            "malicious_info": KNOWN_MALICIOUS.get(address, {})
                        }

                        self._save_to_cache("account_info", {"address": address}, result)
                        return result
        except Exception as e:
            console.print(f"[yellow]Tronscan API error for {address}: {str(e)}[/yellow]")

        # If both APIs fail, return a default response
        return {
            "address": address,
            "balance": 0,
            "exists": False,
            "tokens": [],
            "api_source": "none",
            "is_exchange": address in KNOWN_EXCHANGES,
            "exchange_name": KNOWN_EXCHANGES.get(address, ""),
            "is_malicious": address in KNOWN_MALICIOUS,
            "malicious_info": KNOWN_MALICIOUS.get(address, {})
        }

    async def fetch_transactions_async(self, session, address):
        """Fetch transactions asynchronously."""
        # Try to get from cache first
        cache_params = {"address": address, "limit": self.max_transactions}
        cache_data = self._get_from_cache("transactions", cache_params)
        if cache_data:
            return cache_data

        self.stats["api_calls"] += 1
        all_transactions = []

        # First try TronGrid API
        try:
            # TRX transfers
            async with session.get(
                f"{TRONGRID_API_URL}/v1/accounts/{address}/transactions",
                headers=self.headers,
                params={"limit": self.max_transactions},
                timeout=15
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    if "data" in data:
                        for tx in data["data"]:
                            tx["source"] = "trongrid"
                            tx["type"] = "trx"
                            all_transactions.append(tx)

            # TRC20 token transfers
            async with session.get(
                f"{TRONGRID_API_URL}/v1/accounts/{address}/transactions/trc20",
                headers=self.headers,
                params={"limit": self.max_transactions},
                timeout=15
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    if "data" in data:
                        for tx in data["data"]:
                            tx["source"] = "trongrid"
                            tx["type"] = "trc20"
                            all_transactions.append(tx)
        except Exception as e:
            console.print(f"[yellow]TronGrid API error fetching transactions for {address}: {str(e)}[/yellow]")

        # Fall back or supplement with Tronscan API
        if len(all_transactions) < self.max_transactions:
            try:
                async with session.get(
                    f"{TRONSCAN_API_URL}/transaction",
                    headers=self.tronscan_headers,
                    params={
                        "address": address,
                        "limit": self.max_transactions,
                        "sort": "-timestamp"
                    },
                    timeout=15
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        if "data" in data:
                            for tx in data["data"]:
                                tx["source"] = "tronscan"
                                tx["type"] = "trx"
                                all_transactions.append(tx)

                # Token transfers from Tronscan
                async with session.get(
                    f"{TRONSCAN_API_URL}/token_trc20/transfers",
                    headers=self.tronscan_headers,
                    params={
                        "address": address,
                        "limit": self.max_transactions,
                        "sort": "-timestamp"
                    },
                    timeout=15
                ) as response:
                    if response.status == 200:
                        data = await response.json()
                        if "token_transfers" in data:
                            for tx in data["token_transfers"]:
                                tx["source"] = "tronscan"
                                tx["type"] = "trc20"
                                all_transactions.append(tx)
            except Exception as e:
                console.print(f"[yellow]Tronscan API error fetching transactions for {address}: {str(e)}[/yellow]")

        # Truncate if we got too many transactions
        if len(all_transactions) > self.max_transactions:
            all_transactions = all_transactions[:self.max_transactions]

        # Save to cache
        self._save_to_cache("transactions", cache_params, all_transactions)

        return all_transactions

    def process_transactions(self, address, transactions):
        """Process transaction data to extract connections and insights."""
        connections = {}
        token_transfers = {}
        transaction_types = {}
        transaction_hashes = set()

        for tx in transactions:
            try:
                source = tx.get("source", "unknown")
                tx_type = tx.get("type", "unknown")

                # Extract transaction hash
                tx_hash = None
                if source == "trongrid":
                    tx_hash = tx.get("txID", None)
                elif source == "tronscan":
                    tx_hash = tx.get("hash", None)

                if tx_hash:
                    transaction_hashes.add(tx_hash)

                # Process TRX transfers from TronGrid
                if source == "trongrid" and tx_type == "trx" and "raw_data" in tx:
                    raw_data = tx["raw_data"]

                    # Determine transaction type
                    contract_type = None
                    if "contract" in raw_data and raw_data["contract"]:
                        contract = raw_data["contract"][0]
                        contract_type = contract.get("type", "")
                        transaction_types[contract_type] = transaction_types.get(contract_type, 0) + 1

                        # Extract addresses and amount
                        if "parameter" in contract and "value" in contract["parameter"]:
                            value = contract["parameter"]["value"]

                            from_address = None
                            to_address = None
                            amount = 0

                            if "owner_address" in value:
                                from_hex = value["owner_address"]
                                from_address = self.hex_to_tron_address(from_hex)

                            if "to_address" in value:
                                to_hex = value["to_address"]
                                to_address = self.hex_to_tron_address(to_hex)

                            if "amount" in value:
                                amount = value["amount"] / 1_000_000

                            # Record connection
                            if from_address and to_address and amount >= self.min_connection_weight:
                                self.record_connection(connections, from_address, to_address, amount, contract_type)

                # Process TRC20 token transfers from TronGrid
                elif source == "trongrid" and tx_type == "trc20":
                    from_address = tx.get("from", "")
                    to_address = tx.get("to", "")
                    token_address = tx.get("token_info", {}).get("address", "")

                    if from_address and to_address and token_address:
                        # Record token transfer
                        token_data = {
                            "from": from_address,
                            "to": to_address,
                            "token": token_address,
                            "name": tx.get("token_info", {}).get("name", "Unknown Token"),
                            "symbol": tx.get("token_info", {}).get("symbol", "???"),
                            "amount": float(tx.get("value", "0")) / (10 ** int(tx.get("token_info", {}).get("decimals", 6))),
                            "hash": tx_hash
                        }

                        if token_address not in token_transfers:
                            token_transfers[token_address] = []

                        token_transfers[token_address].append(token_data)

                        # Also record as connection
                        self.record_connection(connections, from_address, to_address, 0, "TRC20Transfer")
                        transaction_types["TRC20Transfer"] = transaction_types.get("TRC20Transfer", 0) + 1

                # Process transactions from Tronscan
                elif source == "tronscan":
                    if tx_type == "trx":
                        # Extract basic info
                        contract_type = tx.get("contractType", "")
                        transaction_types[contract_type] = transaction_types.get(contract_type, 0) + 1

                        # Get addresses
                        from_address = tx.get("ownerAddress", "")
                        to_address = None
                        amount = 0

                        # Extract recipient and amount based on contract type
                        if contract_type == "TransferContract":
                            contract_data = tx.get("contractData", {})
                            to_address = contract_data.get("to_address", "")
                            amount = contract_data.get("amount", 0) / 1_000_000

                        # Record connection
                        if from_address and to_address and amount >= self.min_connection_weight:
                            self.record_connection(connections, from_address, to_address, amount, contract_type)

                    elif tx_type == "trc20":
                        # Process TRC20 transfer from Tronscan
                        from_address = tx.get("from_address", "")
                        to_address = tx.get("to_address", "")
                        token_address = tx.get("contract_address", "")

                        if from_address and to_address and token_address:
                            # Record token transfer
                            token_data = {
                                "from": from_address,
                                "to": to_address,
                                "token": token_address,
                                "name": tx.get("name", "Unknown Token"),
                                "symbol": tx.get("symbol", "???"),
                                "amount": float(tx.get("quant", "0")) / (10 ** int(tx.get("decimals", 6))),
                                "hash": tx_hash
                            }

                            if token_address not in token_transfers:
                                token_transfers[token_address] = []

                            token_transfers[token_address].append(token_data)

                            # Also record as connection
                            self.record_connection(connections, from_address, to_address, 0, "TRC20Transfer")
                            transaction_types["TRC20Transfer"] = transaction_types.get("TRC20Transfer", 0) + 1
            except Exception as e:
                logger.debug(f"Error processing transaction: {str(e)}")
                continue

        # Return the processed data
        return {
            "connections": connections,
            "token_transfers": token_transfers,
            "transaction_types": transaction_types,
            "transaction_hashes": list(transaction_hashes)
        }

    async def _get_token_info(self, session, contract_address):
        """Get token information including name and symbol."""
        # Check cache first
        cache_data = self._get_from_cache("token_info", {"contract": contract_address})
        if cache_data:
            return cache_data

        # Known token contracts database
        KNOWN_TOKEN_CONTRACTS = {
            "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t": {"name": "Tether USD", "symbol": "USDT", "decimals": 6},
            "TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7": {"name": "BitTorrent", "symbol": "BTT", "decimals": 18},
            "TKn41Ey1DL3rXQm9z9b9dAEaB1a8dKPvXa": {"name": "WINkLink", "symbol": "WIN", "decimals": 6},
            "TUpMhErYXBPLwhpNEZZT9qHqr8HMwWnxGe": {"name": "TrueUSD", "symbol": "TUSD", "decimals": 18},
            "TSSMHYeV2uE9qYH95TgUe9EwmJGjXCL9p": {"name": "SUN", "symbol": "SUN", "decimals": 18},
            "TGUWcXLXk8xfGuZyJi9xfNz8NKRFX7YT5K": {"name": "Huobi Token", "symbol": "HTX", "decimals": 18},
            "TFczxzPhnThNSqr5by8iLqNsxrCbCcJKtW": {"name": "Non-Fungible Token", "symbol": "NFT", "decimals": 6},
            "TFHDkPfm8BwsyHBe9hFZMCPRjGDwVzHTe": {"name": "USDD OLD", "symbol": "USDDOLD", "decimals": 18},
            "TNo59KEQKjqJCjKeUdEqRN9k7rAhvgfKvh": {"name": "BitTorrent OLD", "symbol": "BTTOLD", "decimals": 18},
            "TCfaLnJb9aHqsAbSq9xPAL8mNKLrFz6VyW": {"name": "Staked USDT", "symbol": "stUSDT", "decimals": 6},
            "TKfjV9RNKJJCqPvBtK8L7Knykh7DNWvnYt": {"name": "DICE", "symbol": "DICE", "decimals": 6},
            "TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8": {"name": "GenesisManufacturingCoin", "symbol": "GMC", "decimals": 18},
            "TF17BgPaZYbz8oxbjhriubPDsA7ArKoLX3": {"name": "Pepe", "symbol": "PePe", "decimals": 18},
            "TKJxiEfwTQ7x3eooBJqcMKdRKzqhQkGZZN": {"name": "SunDog", "symbol": "SUNDOG", "decimals": 18},
            "TK3ue6A3gHxZwWvnE6fZfhXGW5sPTFoqPW": {"name": "SUN OLD", "symbol": "SUNOLD", "decimals": 18},
            "TJHo8Yyu1HwXGUhZxmPNdXBLSRqCLJGxWX": {"name": "SunPump", "symbol": "SUNPUMP", "decimals": 18},
            "TBYRgCzVBzrMLM9xJzqZjyLkEdHEWCpqhK": {"name": "SunFe", "symbol": "SUNFE", "decimals": 18},
            "TGv7M5RH9CZ5PtSgLYEQwjvHb6v4x5qT6P": {"name": "Love", "symbol": "LOVE", "decimals": 18}
        }

        # Check known contracts first
        if contract_address in KNOWN_TOKEN_CONTRACTS:
            result = KNOWN_TOKEN_CONTRACTS[contract_address]
            self._save_to_cache("token_info", {"contract": contract_address}, result)
            return result

        try:
            # Try to get token info from TronGrid API
            async with session.get(
                f"{TRONGRID_API_URL}/v1/contracts/{contract_address}",
                headers=self.headers,
                timeout=5
            ) as response:
                if response.status == 200:
                    data = await response.json()
                    if "data" in data and len(data["data"]) > 0:
                        contract_data = data["data"][0]
                        result = {
                            "name": contract_data.get("name", "Unknown Token"),
                            "symbol": contract_data.get("symbol", "???"),
                            "decimals": contract_data.get("decimals", 6)
                        }
                        self._save_to_cache("token_info", {"contract": contract_address}, result)
                        return result
        except:
            pass

        # Default fallback
        result = {"name": "Unknown Token", "symbol": "???", "decimals": 6}
        return result

    def record_connection(self, connections, from_address, to_address, amount, tx_type):
        """Record a connection between two addresses."""
        key = f"{from_address}:{to_address}"

        if key not in connections:
            connections[key] = {
                "from_address": from_address,
                "to_address": to_address,
                "total_amount": 0,
                "count": 0,
                "types": {}
            }

        connections[key]["total_amount"] += amount
        connections[key]["count"] += 1
        connections[key]["types"][tx_type] = connections[key]["types"].get(tx_type, 0) + 1

    def hex_to_tron_address(self, hex_address):
        """Convert a hex address to TRON address format."""
        if not hex_address:
            return None

        if hex_address.startswith("0x"):
            hex_address = hex_address[2:]

        try:
            # Add 41 prefix (TRON's address prefix)
            if not hex_address.startswith("41"):
                hex_address = "41" + hex_address

            # Convert from hex to bytes
            addr_bytes = bytes.fromhex(hex_address)

            # Encode using base58check
            tron_address = base58.b58encode_check(addr_bytes).decode('utf-8')
            return tron_address
        except Exception as e:
            logger.debug(f"Error converting hex address: {str(e)}")
            return None

    def calculate_anomaly_score(self, address_data):
        """Calculate an anomaly score for the address using ML-based heuristics."""
        # This would normally use a trained ML model, but we'll use heuristics for this demo
        anomaly_score = 0
        risk_factors = []

        # Is it a known malicious address?
        if address_data.get("is_malicious", False):
            anomaly_score += 100
            risk_factors.append(f"Known malicious address: {address_data['malicious_info'].get('type', 'Unknown')}")
            return anomaly_score, risk_factors

        # Analyze transaction patterns
        tx_count = address_data.get("transactions_count", 0)
        balance = address_data.get("balance", 0)
        connections = address_data.get("connections", {})
        incoming_connections = len([c for c in connections.values() if c["from_address"] != address_data["address"]])
        outgoing_connections = len([c for c in connections.values() if c["from_address"] == address_data["address"]])

        # Risk factor: Many outgoing, few incoming
        if outgoing_connections > 5 and incoming_connections < 2:
            anomaly_score += 20
            risk_factors.append("Primarily outgoing transactions")

        # Risk factor: Low balance despite high transaction count
        if tx_count > 50 and balance < 10:
            anomaly_score += 15
            risk_factors.append("High transaction count with low balance")

        # Risk factor: Connected to known malicious addresses
        malicious_connections = 0
        for conn in connections.values():
            other_addr = conn["to_address"] if conn["from_address"] == address_data["address"] else conn["from_address"]
            if other_addr in KNOWN_MALICIOUS:
                malicious_connections += 1

        if malicious_connections > 0:
            anomaly_score += 30 * malicious_connections
            risk_factors.append(f"Connected to {malicious_connections} known malicious addresses")

        # Risk factor: Connected to exchanges with high volumes
        exchange_transfers = 0
        for conn in connections.values():
            other_addr = conn["to_address"] if conn["from_address"] == address_data["address"] else conn["from_address"]
            if other_addr in KNOWN_EXCHANGES and conn["total_amount"] > 10000:
                exchange_transfers += 1

        if exchange_transfers > 3:
            anomaly_score += 10
            risk_factors.append(f"Multiple large transfers with exchanges ({exchange_transfers})")

        # Cap the score at 100
        anomaly_score = min(anomaly_score, 100)

        return anomaly_score, risk_factors

    def detect_wallet_type(self, address_data):
        """Detect the wallet type based on transaction patterns."""
        # Check if it's a known exchange
        if address_data.get("is_exchange", False):
            return "Exchange", address_data.get("exchange_name", "Unknown Exchange")

        # Analysis based on transaction patterns
        connections = address_data.get("connections", {})
        transaction_types = address_data.get("transaction_types", {})
        incoming_connections = len([c for c in connections.values() if c["from_address"] != address_data["address"]])
        outgoing_connections = len([c for c in connections.values() if c["from_address"] == address_data["address"]])

        # Contract wallet detection
        if "TriggerSmartContract" in transaction_types and transaction_types["TriggerSmartContract"] > 10:
            return "Contract", "Smart Contract Wallet"

        # Mining pool detection
        if outgoing_connections > 20 and any(c["count"] > 50 for c in connections.values()):
            return "Mining", "Mining Pool"

        # DEX/liquidity pool detection
        if "TRC20Transfer" in transaction_types and transaction_types["TRC20Transfer"] > 100:
            return "DEX", "Decentralized Exchange"

        # Whale detection (large balance)
        if address_data.get("balance", 0) > 100000:
            return "Whale", "High-Value Wallet"

        # Default to personal wallet
        return "Personal", "Individual Wallet"

    async def analyze_addresses_async(self, addresses):
        """Analyze a list of TRON addresses asynchronously."""
        if not addresses:
            console.print("[red]No addresses provided for analysis.[/red]")
            return False

        # Validate addresses
        valid_addresses = []
        for addr in addresses:
            if self.validate_tron_address(addr):
                valid_addresses.append(addr)
            else:
                console.print(f"[yellow]Invalid address format: {addr}[/yellow]")

        if not valid_addresses:
            console.print("[red]No valid addresses to analyze.[/red]")
            return False

        start_time = time.time()
        console.print(f"[green]Starting analysis of {len(valid_addresses)} addresses...[/green]")

        async with aiohttp.ClientSession() as session:
            # Step 1: Fetch account info for all addresses
            with Progress(
                SpinnerColumn(),
                TextColumn("[cyan]Fetching account information...[/cyan]"),
                BarColumn(),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
                TimeRemainingColumn()
            ) as progress:
                task = progress.add_task("Fetching", total=len(valid_addresses))

                account_tasks = []
                for addr in valid_addresses:
                    account_tasks.append(self.fetch_account_info_async(session, addr))

                account_results = await asyncio.gather(*account_tasks)
                progress.update(task, completed=len(account_results))

            # Process account results
            active_addresses = {}
            for result in account_results:
                if result["exists"]:
                    address = result["address"]
                    active_addresses[address] = {
                        "address": address,
                        "balance": result["balance"],
                        "tokens": result["tokens"],
                        "exists": True,
                        "api_source": result["api_source"],
                        "is_exchange": result["is_exchange"],
                        "exchange_name": result["exchange_name"],
                        "is_malicious": result["is_malicious"],
                        "malicious_info": result["malicious_info"],
                        "connections": {},
                        "transaction_types": {},
                        "transaction_hashes": []
                    }

            if not active_addresses:
                console.print("[yellow]No active addresses found on the blockchain.[/yellow]")
                # Use the addresses anyway for demonstration
                for addr in valid_addresses:
                    active_addresses[addr] = {
                        "address": addr,
                        "balance": 0,
                        "tokens": [],
                        "exists": False,
                        "api_source": "none",
                        "is_exchange": addr in KNOWN_EXCHANGES,
                        "exchange_name": KNOWN_EXCHANGES.get(addr, ""),
                        "is_malicious": addr in KNOWN_MALICIOUS,
                        "malicious_info": KNOWN_MALICIOUS.get(addr, {}),
                        "connections": {},
                        "transaction_types": {},
                        "transaction_hashes": []
                    }

            console.print(f"[green]Found {len(active_addresses)} active addresses.[/green]")

            # Step 2: Fetch transactions for active addresses
            all_connections = []
            all_token_transfers = {}

            with Progress(
                SpinnerColumn(),
                TextColumn("[cyan]Fetching and processing transactions...[/cyan]"),
                BarColumn(),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
                TimeRemainingColumn()
            ) as progress:
                task = progress.add_task("Processing", total=len(active_addresses))

                for i, (address, data) in enumerate(active_addresses.items()):
                    # Save checkpoint at regular intervals
                    if i > 0 and i % self.checkpoint_interval == 0:
                        self.save_checkpoint(i)

                    # Fetch transactions
                    transactions = await self.fetch_transactions_async(session, address)

                    # Process transactions
                    processed = self.process_transactions(address, transactions)

                    # Update address data
                    data["transactions_count"] = len(transactions)
                    data["connections"] = processed["connections"]
                    data["token_transfers"] = processed["token_transfers"]
                    data["transaction_types"] = processed["transaction_types"]
                    data["transaction_hashes"] = processed["transaction_hashes"]

                    # Store transaction hashes
                    for tx_hash in processed["transaction_hashes"]:
                        self.transactions[tx_hash] = {
                            "hash": tx_hash,
                            "involved_addresses": [address]
                        }

                    # Add connections to global list
                    for key, conn in processed["connections"].items():
                        all_connections.append(conn)

                    # Add token transfers to global dict
                    for token, transfers in processed["token_transfers"].items():
                        if token not in all_token_transfers:
                            all_token_transfers[token] = []
                        all_token_transfers[token].extend(transfers)

                    # Update statistics
                    self.stats["transactions_processed"] += len(transactions)

                    # Update progress
                    progress.update(task, advance=1)

            # Step 3: Analyze wallet types and anomaly scores
            console.print("[cyan]Analyzing wallet patterns and detecting anomalies...[/cyan]")
            for address, data in active_addresses.items():
                # Detect wallet type
                wallet_type, type_details = self.detect_wallet_type(data)
                data["wallet_type"] = wallet_type
                data["wallet_details"] = type_details

                # Calculate anomaly score
                anomaly_score, risk_factors = self.calculate_anomaly_score(data)
                data["anomaly_score"] = anomaly_score
                data["risk_factors"] = risk_factors

            # Step 4: Calculate connection strength
            console.print("[cyan]Calculating connection strengths...[/cyan]")
            connections = []
            for address, data in active_addresses.items():
                for key, conn in data["connections"].items():
                    # Calculate connection strength
                    count = conn["count"]
                    amount = conn["total_amount"]

                    # Normalize values
                    count_score = min(count / 20, 1.0)  # Cap at 20 transactions
                    amount_score = min(amount / 1000, 1.0)  # Cap at 1000 TRX

                    # Calculate strength (70% transaction count, 30% amount)
                    strength = (count_score * 0.7) + (amount_score * 0.3)

                    # Add to connections list
                    connection = {
                        "from_address": conn["from_address"],
                        "to_address": conn["to_address"],
                        "amount": amount,
                        "count": count,
                        "types": conn["types"],
                        "strength": strength
                    }

                    connections.append(connection)

        # Update object data
        self.addresses_data = active_addresses
        self.connections = connections
        self.token_transfers = all_token_transfers

        # Update statistics
        self.stats["addresses_analyzed"] = len(active_addresses)
        self.stats["connections_found"] = len(connections)
        self.stats["runtime"] = int(time.time() - start_time)

        # Final checkpoint
        self.save_checkpoint("final")

        console.print("[green]Analysis completed successfully.[/green]")
        return True

    def analyze_addresses(self, addresses):
        """Analyze TRON addresses (synchronous wrapper for async function)."""
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(self.analyze_addresses_async(addresses))

    def create_advanced_network_visualization(self, output_name="advanced_tron_analysis"):
        """Create an advanced interactive visualization with search functionality."""
        if not self.addresses_data or not self.connections:
            console.print("[red]No data available for visualization.[/red]")
            return None

        if CleanTronNetworkGenerator is None:
            console.print("[yellow]Clean Network Generator not available. Using basic visualization.[/yellow]")
            return self.create_network_visualization(output_name)

        console.print("[cyan]Creating interactive network graph...[/cyan]")

        # Initialize the generator
        generator = CleanTronNetworkGenerator()

        # Prepare addresses data in the expected format
        addresses_data = {}
        for address, data in self.addresses_data.items():
            wallet_type = data.get("wallet_type", "Unknown")
            balance = data.get("balance", 0)
            anomaly_score = data.get("anomaly_score", 0)
            tx_count = data.get("transactions_count", 0)

            # Enhanced data for advanced visualization
            is_malicious = data.get("is_malicious", False)
            is_exchange = data.get("is_exchange", False)
            exchange_name = data.get("exchange_name", "")
            risk_factors = data.get("risk_factors", [])

            # Activity level
            if tx_count > 1000:
                activity_level = "High"
            elif tx_count > 100:
                activity_level = "Medium"
            else:
                activity_level = "Low"

            addresses_data[address] = {
                "wallet_type": wallet_type,
                "balance_trx": balance,
                "risk_score": anomaly_score,
                "transactions_count": tx_count,
                "activity_level": activity_level,
                "is_malicious": is_malicious,
                "is_exchange": is_exchange,
                "exchange_name": exchange_name,
                "risk_factors": risk_factors,
                "wallet_details": data.get("wallet_details", "N/A"),
                "malicious_info": data.get("malicious_info", {})
            }

        # Prepare connections data
        connections_data = []
        for conn in self.connections:
            from_addr = conn["from_address"]
            to_addr = conn["to_address"]

            # Only include connections where both addresses exist in our data
            if from_addr in addresses_data and to_addr in addresses_data:
                connections_data.append({
                    "from_address": from_addr,
                    "to_address": to_addr,
                    "amount": conn["amount"],
                    "count": conn["count"],
                    "strength": conn["strength"],
                    "types": conn["types"]
                })

        # Create the advanced visualization
        try:
            filename = generator.create_graph(
                addresses_data, 
                connections_data, 
                f"{output_name}_interactive"
            )

            console.print(f"[green]Advanced network visualization saved to {filename}[/green]")
            return filename

        except Exception as e:
            console.print(f"[red]Error creating advanced visualization: {str(e)}[/red]")
            # Fall back to basic visualization
            return self.create_network_visualization(output_name)

    def create_network_visualization(self, output_name="tron_analysis"):
        """Create an enhanced interactive visualization of the address network."""
        if not self.addresses_data or not self.connections:
            console.print("[red]No data available for visualization.[/red]")
            return None

        console.print("[cyan]Creating enhanced network visualization...[/cyan]")

        # Create network graph
        G = nx.DiGraph()

        # Color mapping for wallet types
        color_map = {
            "Personal": "#3498db",  # Blue
            "Exchange": "#2ecc71",  # Green
            "Contract": "#e74c3c",  # Red
            "Mining": "#f1c40f",    # Yellow
            "DEX": "#9b59b6",       # Purple
            "Whale": "#1abc9c",     # Turquoise
            "Unknown": "#95a5a6"    # Gray
        }

        # Risk color gradient: green -> yellow -> red
        def risk_color(score):
            if score < 25:
                return "#2ecc71"  # Green
            elif score < 50:
                return "#f1c40f"  # Yellow
            elif score < 75:
                return "#e67e22"  # Orange
            else:
                return "#e74c3c"  # Red

        # Add nodes (addresses)
        for address, data in self.addresses_data.items():
            wallet_type = data.get("wallet_type", "Unknown")
            balance = data.get("balance", 0)
            anomaly_score = data.get("anomaly_score", 0)
            tx_count = data.get("transactions_count", 0)

            # Determine node color based on wallet type or risk
            if data.get("is_malicious", False):
                color = "#e74c3c"  # Red for malicious
            else:
                color = color_map.get(wallet_type, "#95a5a6")

            # Border color based on risk
            border_color = risk_color(anomaly_score)

            # Node size based on balance (min 15, max 50)
            size = 15 + min(balance / 1000, 35)

            # Create the tooltip with HTML
            tooltip = f"""
            <div style='background-color:#f8f9fa; padding:10px; border-radius:5px; max-width:300px;'>
                <h3 style='margin-top:0;'>{address}</h3>
                <p><strong>Type:</strong> {wallet_type} ({data.get('wallet_details', 'N/A')})</p>
                <p><strong>Balance:</strong> {balance:.2f} TRX</p>
                <p><strong>Risk Score:</strong> <span style='color:{risk_color(anomaly_score)};'>{anomaly_score}/100</span></p>
                <p><strong>Transactions:</strong> {tx_count}</p>

                {f"<p><strong>Exchange:</strong> {data['exchange_name']}</p>" if data.get('is_exchange') else ""}

                {f"<p style='color:red;'><strong>Warning:</strong> {data['malicious_info'].get('type', 'Suspicious activity')} detected</p>" if data.get('is_malicious') else ""}

                <p><strong>Risk Factors:</strong></p>
                <ul>
                    {''.join(f"<li>{factor}</li>" for factor in data.get('risk_factors', []))}
                </ul>
            </div>
            """

            # Add node
            G.add_node(
                address,
                label=address[:8] + "..." + address[-4:],
                title=tooltip,
                color=color,
                borderWidth=3,
                borderColor=border_color,
                size=size,
                shape="ellipse" if not data.get("is_malicious") else "triangle"
            )

        # Add edges (connections)
        edge_colors = {
            "TransferContract": "#3498db",  # Blue for TRX transfers
            "TRC20Transfer": "#2ecc71",     # Green for token transfers
            "TriggerSmartContract": "#9b59b6",  # Purple for contract interactions
            "VoteWitnessContract": "#f1c40f",  # Yellow for votes
            "Other": "#95a5a6"              # Gray for others
        }

        for conn in self.connections:
            from_addr = conn["from_address"]
            to_addr = conn["to_address"]

            # Skip if either address is not in our data
            if from_addr not in self.addresses_data or to_addr not in self.addresses_data:
                continue

            # Determine edge properties
            amount = conn["amount"]
            count = conn["count"]
            strength = conn["strength"]

            # Edge width based on strength (min 1, max 8)
            width = 1 + (strength * 7)

            # Edge color based on transaction type
            main_type = max(conn["types"].items(), key=lambda x: x[1])[0] if conn["types"] else "Other"
            color = edge_colors.get(main_type, edge_colors["Other"])

            # Create tooltip
            tooltip = f"""
            <div style='background-color:#f8f9fa; padding:10px; border-radius:5px; max-width:300px;'>
                <h4 style='margin-top:0;'>Connection Details</h4>
                <p><strong>From:</strong> {from_addr[:8]}...{from_addr[-4:]}</p>
                <p><strong>To:</strong> {to_addr[:8]}...{to_addr[-4:]}</p>
                <p><strong>Transactions:</strong> {count}</p>
                <p><strong>Amount:</strong> {amount:.2f} TRX</p>
                <p><strong>Strength:</strong> {strength:.2f}</p>
                <p><strong>Transaction Types:</strong></p>
                <ul>
                    {''.join(f"<li>{tx_type}: {tx_count}</li>" for tx_type, tx_count in conn["types"].items())}
                </ul>
            </div>
            """

            # Add edge
            G.add_edge(
                from_addr,
                to_addr,
                title=tooltip,
                width=width,
                arrows=True,
                color=color,
                value=int(strength * 100),  # Convert to integer
                label=f"{count} tx" if count > 5 else ""
            )

        # Check if pyvis is available
        if not PYVIS_AVAILABLE or Network is None:
            console.print("[yellow]PyVis not available. Generating basic HTML network visualization...[/yellow]")
            return self._create_basic_network_html(output_name)

        # Create the network visualization
        net = Network(
            height="800px", 
            width="100%", 
            bgcolor="#ffffff", 
            directed=True
        )

        # Define custom options for better visualization
        net.set_options("""
        {
            "nodes": {
                "font": {
                    "size": 16,
                    "face": "Tahoma"
                },
                "scaling": {
                    "min": 10,
                    "max": 50
                }
            },
            "edges": {
                "smooth": {
                    "type": "continuous",
                    "forceDirection": "none"
                },
                "arrows": {
                    "to": {
                        "enabled": true,
                        "scaleFactor": 0.5
                    }
                },
                "font": {
                    "size": 10,
                    "align": "middle"
                },
                "color": {
                    "inherit": false
                }
            },
            "physics": {
                "solver": "forceAtlas2Based",
                "forceAtlas2Based": {
                    "gravitationalConstant": -100,
                    "centralGravity": 0.01,
                    "springLength": 150,
                    "springConstant": 0.08,
                    "avoidOverlap": 0.4
                },
                "stabilization": {
                    "enabled": true,
                    "iterations": 2000,
                    "updateInterval": 25
                }
            },
            "interaction": {
                "hover": true,
                "navigationButtons": true,
                "keyboard": {
                    "enabled": true
                },
                "tooltipDelay": 300
            }
        }
        """)

        # Add the network data
        net.from_nx(G)

        # No need to show buttons as it can cause compatibility issues
        # net.show_buttons(['physics', 'nodes', 'edges'])

        # Add legend
        legend_html = """
        <div style="position: absolute; top: 10px; right: 10px; padding: 10px; background-color: rgba(255, 255, 255, 0.8); 
            border-radius: 5px; border: 1px solid #ddd; z-index: 1000;">
            <h3 style="margin-top: 0;">Legend</h3>
            <h4>Node Types</h4>
            <div style="display: flex; align-items: center; margin-bottom: 5px;">
                <div style="width: 20px; height: 20px; background-color: #3498db; border-radius: 50%; margin-right: 5px;"></div>
                <span>Personal Wallet</span>
            </div>
            <div style="display: flex; align-items: center; margin-bottom: 5px;">
                <div style="width: 20px; height: 20px; background-color: #2ecc71; border-radius: 50%; margin-right: 5px;"></div>
                <span>Exchange</span>
            </div>
            <div style="display: flex; align-items: center; margin-bottom: 5px;">
                <div style="width: 20px; height: 20px; background-color: #e74c3c; border-radius: 50%; margin-right: 5px;"></div>
                <span>Contract</span>
            </div>
            <div style="display: flex; align-items: center; margin-bottom: 5px;">
                <div style="width: 20px; height: 20px; background-color: #f1c40f; border-radius: 50%; margin-right: 5px;"></div>
                <span>Mining</span>
            </div>
            <div style="display: flex; align-items: center; margin-bottom: 5px;">
                <div style="width: 20px; height: 20px; background-color: #9b59b6; border-radius: 50%; margin-right: 5px;"></div>
                <span>DEX</span>
            </div>

            <h4>Edge Types</h4>
            <div style="display: flex; align-items: center; margin-bottom: 5px;">
                <div style="width: 20px; height: 3px; background-color: #3498db; margin-right: 5px;"></div>
                <span>TRX Transfer</span>
            </div>
            <div style="display: flex; align-items: center; margin-bottom: 5px;">
                <div style="width: 20px; height: 3px; background-color: #2ecc71; margin-right: 5px;"></div>
                <span>Token Transfer</span>
            </div>
            <div style="display: flex; align-items: center;">
                <div style="width: 20px; height: 3px; background-color: #9b59b6; margin-right: 5px;"></div>
                <span>Contract Interaction</span>
            </div>
        </div>
        """

        # Generate timestamp for the filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{VIZ_DIR}/{output_name}_enhanced_{timestamp}.html"

        # Use custom HTML to include the legend
        html_template = """
        <html>
        <head>
            <title>TRON Wallet Analysis Network</title>
            <script type="text/javascript" src="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.2/dist/vis-network.min.js"></script>
            <link href="https://cdnjs.cloudflare.com/ajax/libs/vis-network/9.1.2/dist/vis-network.min.css" rel="stylesheet" type="text/css" />
            <style type="text/css">
                body, html {{
                    width: 100%;
                    height: 100%;
                    margin: 0;
                    padding: 0;
                    font-family: sans-serif;
                }}
                #mynetwork {{
                    width: 100%;
                    height: 100%;
                }}
            </style>
        </head>
        <body>
            <div id="mynetwork"></div>
            {legend_html}
            <script type="text/javascript">
                var container = document.getElementById('mynetwork');
                var data = {data};
                var options = {options};
                var network = new vis.Network(container, data, options);
            </script>
        </body>
        </html>
        """

        # Save to file with custom HTML including legend
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{VIZ_DIR}/{output_name}_enhanced_{timestamp}.html"

        # Let pyvis handle the HTML generation but customize it afterward
        net.save_graph(filename)

        # Read the file, add our legend, and save it back
        with open(filename, 'r') as f:
            html_content = f.read()

        # Add our legend to the HTML
        modified_html = html_content.replace('</body>', f'{legend_html}</body>')

        with open(filename, 'w') as f:
            f.write(modified_html)

        console.print(f"[green]Enhanced network visualization saved to {filename}[/green]")
        return filename

    def _create_basic_network_html(self, output_name="tron_analysis"):
        """Create a basic HTML network visualization without pyvis."""
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"{VIZ_DIR}/{output_name}_basic_{timestamp}.html"

        html_content = f"""
        <!DOCTYPE html>
        <html>
        <head>
            <title>TRON Network Analysis - Basic View</title>
            <style>
                body {{ font-family: Arial, sans-serif; margin: 20px; }}
                .address {{ background: #f0f0f0; padding: 10px; margin: 5px; border-radius: 5px; }}
                .high-risk {{ background: #ffebee; border-left: 5px solid #f44336; }}
                .medium-risk {{ background: #fff3e0; border-left: 5px solid #ff9800; }}
                .low-risk {{ background: #e8f5e8; border-left: 5px solid #4caf50; }}
                .connection {{ margin: 10px 0; padding: 10px; background: #fafafa; }}
            </style>
        </head>
        <body>
            <h1>TRON Network Analysis Results</h1>
            <p>Generated on {datetime.now().strftime("%Y-%m-%d %H:%M:%S")}</p>

            <h2>Analyzed Addresses ({len(self.addresses_data)})</h2>
        """

        # Add address information
        for addr, data in self.addresses_data.items():
            risk_score = data.get("anomaly_score", 0)
            risk_class = "high-risk" if risk_score >= 75 else "medium-risk" if risk_score >= 25 else "low-risk"

            html_content += f"""
            <div class="address {risk_class}">
                <h3>{addr}</h3>
                <p><strong>Type:</strong> {data.get('wallet_type', 'Unknown')}</p>
                <p><strong>Balance:</strong> {data.get('balance', 0):.2f} TRX</p>
                <p><strong>Risk Score:</strong> {risk_score}/100</p>
                <p><strong>Transactions:</strong> {data.get('transactions_count', 0)}</p>
            </div>
            """

        # Add connections information
        if self.connections:
            html_content += f"""
            <h2>Key Connections ({len(self.connections)})</h2>
            """

            for conn in sorted(self.connections, key=lambda c: c["strength"], reverse=True)[:10]:
                html_content += f"""
                <div class="connection">
                    <p><strong>From:</strong> {conn['from_address'][:10]}...</p>
                    <p><strong>To:</strong> {conn['to_address'][:10]}...</p>
                    <p><strong>Transactions:</strong> {conn['count']} | <strong>Amount:</strong> {conn['amount']:.2f} TRX</p>
                    <p><strong>Strength:</strong> {conn['strength']:.2f}</p>
                </div>
                """

        html_content += """
            </body>
        </html>
        """

        with open(filename, 'w') as f:
            f.write(html_content)

        console.print(f"[green]Basic network visualization saved to {filename}[/green]")
        return filename

    def generate_detailed_report(self, output_name="tron_analysis"):
        """Generate a comprehensive report with all analysis findings."""
        if not self.addresses_data:
            console.print("[red]No data available for reporting.[/red]")
            return None

        console.print("[cyan]Generating detailed analysis report...[/cyan]")

        # Generate timestamp for filenames
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Create Excel report
        excel_file = f"{REPORT_DIR}/{output_name}_detailed_{timestamp}.xlsx"

        with pd.ExcelWriter(excel_file, engine='openpyxl') as writer:
            # Summary sheet
            summary_data = {
                "Metric": [
                    "Total Addresses Analyzed",
                    "Active Addresses",
                    "Total Connections Found",
                    "Total Transactions Processed",
                    "Total Runtime (seconds)",
                    "API Calls Made",
                    "Cache Hits",
                    "High Risk Addresses",
                    "Medium Risk Addresses",
                    "Low Risk Addresses"
                ],
                "Value": [
                    self.stats["addresses_analyzed"],
                    len([a for a in self.addresses_data.values() if a.get("exists", False)]),
                    self.stats["connections_found"],
                    self.stats["transactions_processed"],
                    round(self.stats["runtime"], 2),
                    self.stats["api_calls"],
                    self.stats["cache_hits"],
                    len([a for a in self.addresses_data.values() if a.get("anomaly_score", 0) >= 75]),
                    len([a for a in self.addresses_data.values() if 25 <= a.get("anomaly_score", 0) < 75]),
                    len([a for a in self.addresses_data.values() if a.get("anomaly_score", 0) < 25])
                ]
            }

            summary_df = pd.DataFrame(summary_data)
            summary_df.to_excel(writer, sheet_name="Summary", index=False)

            # Address analysis sheet
            address_rows = []
            for address, data in self.addresses_data.items():
                address_rows.append({
                    "Address": address,
                    "Wallet Type": data.get("wallet_type", "Unknown"),
                    "Wallet Details": data.get("wallet_details", ""),
                    "Balance (TRX)": data.get("balance", 0),
                    "Transactions Count": data.get("transactions_count", 0),
                    "Is Exchange": data.get("is_exchange", False),
                    "Exchange Name": data.get("exchange_name", ""),
                    "Is Malicious": data.get("is_malicious", False),
                    "Malicious Type": data.get("malicious_info", {}).get("type", ""),
                    "Risk Score": data.get("anomaly_score", 0),
                    "API Source": data.get("api_source", "none"),
                    "Connections Out": len([c for c in data.get("connections", {}).values() if c["from_address"] == address]),
                    "Connections In": len([c for c in data.get("connections", {}).values() if c["from_address"] != address])
                })

            address_df = pd.DataFrame(address_rows)
            address_df.to_excel(writer, sheet_name="Addresses", index=False)

            # Connections sheet
            connection_rows = []
            for conn in self.connections:
                from_addr = conn["from_address"]
                to_addr = conn["to_address"]

                if from_addr in self.addresses_data and to_addr in self.addresses_data:
                    from_type = self.addresses_data[from_addr].get("wallet_type", "Unknown")
                    to_type = self.addresses_data[to_addr].get("wallet_type", "Unknown")

                    connection_rows.append({
                        "From Address": from_addr,
                        "To Address": to_addr,
                        "From Wallet Type": from_type,
                        "To Wallet Type": to_type,
                        "Transaction Count": conn["count"],
                        "Amount (TRX)": conn["amount"],
                        "Connection Strength": conn["strength"],
                        "Main Transaction Type": max(conn["types"].items(), key=lambda x: x[1])[0] if conn["types"] else "Unknown"
                    })

            connection_df = pd.DataFrame(connection_rows)
            if not connection_df.empty:
                connection_df.to_excel(writer, sheet_name="Connections", index=False)

            # Risk analysis sheet
            risk_rows = []
            for address, data in self.addresses_data.items():
                if data.get("risk_factors"):
                    risk_score = data.get("anomaly_score", 0)
                    for factor in data.get("risk_factors", []):
                        risk_rows.append({
                            "Address": address,
                            "Wallet Type": data.get("wallet_type", "Unknown"),
                            "Risk Score": risk_score,
                            "Risk Factor": factor
                        })

            if risk_rows:
                risk_df = pd.DataFrame(risk_rows)
                risk_df.to_excel(writer, sheet_name="Risk Factors", index=False)

            # Token transfers sheet
            token_rows = []
            for token_addr, transfers in self.token_transfers.items():
                for transfer in transfers:
                    token_rows.append({
                        "Token Address": token_addr,
                        "Token Name": transfer.get("name", "Unknown"),
                        "Token Symbol": transfer.get("symbol", "???"),
                        "From Address": transfer.get("from", ""),
                        "To Address": transfer.get("to", ""),
                        "Amount": transfer.get("amount", 0),
                        "Transaction Hash": transfer.get("hash", "")
                    })

            if token_rows:
                token_df = pd.DataFrame(token_rows)
                token_df.to_excel(writer, sheet_name="Token Transfers", index=False)

            # Transaction hashes sheet
            if self.transactions:
                tx_rows = []
                for tx_hash, data in self.transactions.items():
                    tx_rows.append({
                        "Transaction Hash": tx_hash,
                        "Involved Addresses": ", ".join(data.get("involved_addresses", []))
                    })

                tx_df = pd.DataFrame(tx_rows)
                tx_df.to_excel(writer, sheet_name="Transaction Hashes", index=False)

        console.print(f"[green]Detailed Excel report saved to {excel_file}[/green]")

        # Generate text report
        text_file = f"{REPORT_DIR}/{output_name}_report_{timestamp}.txt"

        with open(text_file, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write(f"ADVANCED TRON WALLET ANALYSIS REPORT - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")

            f.write("SUMMARY\n")
            f.write("-" * 80 + "\n")
            f.write(f"Total Addresses Analyzed: {self.stats['addresses_analyzed']}\n")
            f.write(f"Active Addresses: {len([a for a in self.addresses_data.values() if a.get('exists', False)])}\n")
            f.write(f"Total Connections Found: {self.stats['connections_found']}\n")
            f.write(f"Total Transactions Processed: {self.stats['transactions_processed']}\n")
            f.write(f"Analysis Runtime: {round(self.stats['runtime'], 2)} seconds\n\n")

            # Wallet type distribution
            wallet_types = {}
            for data in self.addresses_data.values():
                wallet_type = data.get("wallet_type", "Unknown")
                wallet_types[wallet_type] = wallet_types.get(wallet_type, 0) + 1

            f.write("Wallet Type Distribution:\n")
            for wallet_type, count in wallet_types.items():
                percentage = (count / len(self.addresses_data)) * 100 if self.addresses_data else 0
                f.write(f"  {wallet_type}: {count} ({percentage:.1f}%)\n")

            # Risk distribution
            high_risk = len([a for a in self.addresses_data.values() if a.get("anomaly_score", 0) >= 75])
            medium_risk = len([a for a in self.addresses_data.values() if 25 <= a.get("anomaly_score", 0) < 75])
            low_risk = len([a for a in self.addresses_data.values() if a.get("anomaly_score", 0) < 25])

            f.write("\nRisk Distribution:\n")
            f.write(f"  High Risk (75-100): {high_risk} addresses\n")
            f.write(f"  Medium Risk (25-74): {medium_risk} addresses\n")
            f.write(f"  Low Risk (0-24): {low_risk} addresses\n\n")

            f.write("\nHIGH RISK ADDRESSES\n")
            f.write("-" * 80 + "\n")

            high_risk_addresses = [
                (addr, data) for addr, data in self.addresses_data.items() 
                if data.get("anomaly_score", 0) >= 75 or data.get("is_malicious", False)
            ]

            if high_risk_addresses:
                for addr, data in high_risk_addresses:
                    f.write(f"\nAddress: {addr}\n")
                    f.write(f"  Wallet Type: {data.get('wallet_type', 'Unknown')}\n")
                    f.write(f"  Risk Score: {data.get('anomaly_score', 0)}/100\n")

                    if data.get("is_malicious", False):
                        f.write(f"  WARNING: Known Malicious Address - {data.get('malicious_info', {}).get('type', 'Unknown')}\n")

                    if data.get("risk_factors"):
                        f.write("  Risk Factors:\n")
                        for factor in data["risk_factors"]:
                            f.write(f"    - {factor}\n")
            else:
                f.write("No high-risk addresses identified.\n")

            f.write("\nKEY CONNECTIONS\n")
            f.write("-" * 80 + "\n")

            # Sort connections by strength
            significant_connections = sorted(
                self.connections, 
                key=lambda c: c["strength"], 
                reverse=True
            )[:10]  # Top 10

            for conn in significant_connections:
                from_addr = conn["from_address"]
                to_addr = conn["to_address"]

                if from_addr in self.addresses_data and to_addr in self.addresses_data:
                    from_type = self.addresses_data[from_addr].get("wallet_type", "Unknown")
                    to_type = self.addresses_data[to_addr].get("wallet_type", "Unknown")

                    f.write(f"\n{from_addr} -> {to_addr}\n")
                    f.write(f"  From Type: {from_type}\n")
                    f.write(f"  To Type: {to_type}\n")
                    f.write(f"  Transactions: {conn['count']}\n")
                    f.write(f"  Total Amount: {conn['amount']:.2f} TRX\n")
                    f.write(f"  Connection Strength: {conn['strength']:.2f}\n")

                    if conn["types"]:
                        f.write("  Transaction Types:\n")
                        for tx_type, count in conn["types"].items():
                            f.write(f"    - {tx_type}: {count}\n")

            f.write("\nDETAILED ADDRESS INFORMATION\n")
            f.write("-" * 80 + "\n")

            # Sort addresses by risk score
            sorted_addresses = sorted(
                self.addresses_data.items(),
                key=lambda x: x[1].get("anomaly_score", 0),
                reverse=True
            )

            for addr, data in sorted_addresses:
                f.write(f"\nAddress: {addr}\n")
                f.write(f"  Wallet Type: {data.get('wallet_type', 'Unknown')} ({data.get('wallet_details', 'N/A')})\n")
                f.write(f"  Balance: {data.get('balance', 0):.2f} TRX\n")
                f.write(f"  Transactions: {data.get('transactions_count', 0)}\n")
                f.write(f"  Risk Score: {data.get('anomaly_score', 0)}/100\n")

                # Display token holdings with names
                if data.get("tokens"):
                    f.write("  Token Holdings:\n")
                    for token_addr, token_data in data["tokens"].items():
                        token_name = token_data.get("name", "Unknown Token")
                        token_symbol = token_data.get("symbol", "???")
                        balance = token_data.get("balance", 0)
                        f.write(f"    {token_name} ({token_symbol}): {balance:,.2f}\n")

                if data.get("is_exchange", False):
                    f.write(f"  Exchange: {data.get('exchange_name', 'Unknown')}\n")

                if data.get("is_malicious", False):
                    f.write(f"  WARNING: Known Malicious Address - {data.get('malicious_info', {}).get('type', 'Unknown')}\n")

                if data.get("risk_factors"):
                    f.write("  Risk Factors:\n")
                    for factor in data["risk_factors"]:
                        f.write(f"    - {factor}\n")

                # Show tokens if available
                if data.get("tokens"):
                    f.write("  Tokens:\n")
                    for token in data["tokens"]:
                        token_name = token.get("name", token.get("contract", "Unknown"))
                        token_symbol = token.get("symbol", "???")
                        token_balance = token.get("balance", 0)
                        f.write(f"    - {token_name} ({token_symbol}): {token_balance:.2f}\n")

                # Show transaction types
                if data.get("transaction_types"):
                    f.write("  Transaction Types:\n")
                    for tx_type, count in data["transaction_types"].items():
                        f.write(f"    - {tx_type}: {count}\n")

                # Show significant connections
                connections_out = [c for c in data.get("connections", {}).values() if c["from_address"] == addr]
                connections_in = [c for c in data.get("connections", {}).values() if c["from_address"] != addr]

                if connections_out:
                    f.write(f"  Outgoing Connections: {len(connections_out)}\n")
                    top_out = sorted(connections_out, key=lambda c: c["total_amount"], reverse=True)[:3]
                    for conn in top_out:
                        f.write(f"    - To {conn['to_address']}: {conn['total_amount']:.2f} TRX ({conn['count']} tx)\n")

                if connections_in:
                    f.write(f"  Incoming Connections: {len(connections_in)}\n")
                    top_in = sorted(connections_in, key=lambda c: c["total_amount"], reverse=True)[:3]
                    for conn in top_in:
                        f.write(f"    - From {conn['from_address']}: {conn['total_amount']:.2f} TRX ({conn['count']} tx)\n")

        console.print(f"[green]Detailed text report saved to {text_file}[/green]")

        # Generate JSON report
        json_file = f"{REPORT_DIR}/{output_name}_full_{timestamp}.json"

        full_data = {
            "meta": {
                "timestamp": datetime.now().isoformat(),
                "analyzer_version": "advanced_2.0",
                "addresses_count": len(self.addresses_data),
                "connections_count": len(self.connections),
                "active_addresses": sum(1 for data in self.addresses_data.values() if data.get("exists", False)),
                "analysis_depth": self.depth,
                "max_transactions_per_address": self.max_transactions,
                "runtime_seconds": self.stats.get("runtime", 0)
            },
            "addresses": self.addresses_data,
            "connections": self.connections,
            "token_transfers": self.token_transfers,
            "transactions": self.transactions,
            "statistics": self.stats,
            "summary_statistics": {
                "total_addresses": len(self.addresses_data),
                "active_addresses": len([a for a in self.addresses_data.values() if a.get("exists", False)]),
                "total_connections": len(self.connections),
                "total_transactions": self.stats.get("transactions_processed", 0),
                "api_calls_made": self.stats.get("api_calls", 0),
                "cache_hits": self.stats.get("cache_hits", 0),
                "high_risk_addresses": len([a for a in self.addresses_data.values() if a.get("anomaly_score", 0) >= 75]),
                "medium_risk_addresses": len([a for a in self.addresses_data.values() if 25 <= a.get("anomaly_score", 0) < 75]),
                "low_risk_addresses": len([a for a in self.addresses_data.values() if a.get("anomaly_score", 0) < 25]),
                "exchange_addresses": len([a for a in self.addresses_data.values() if a.get("is_exchange", False)]),
                "malicious_addresses": len([a for a in self.addresses_data.values() if a.get("is_malicious", False)])
            }
        }

        with open(json_file, 'w', encoding='utf-8') as f:
            json.dump(full_data, f, indent=2, ensure_ascii=False, default=str)

        console.print(f"[green]JSON data exported to {json_file}[/green]")

        return excel_file, text_file, json_file

    def display_analysis_results(self):
        """Display analysis results in the console with token information."""
        if not self.addresses_data:
            console.print("[red]No analysis data available.[/red]")
            return

        console.print("\n[bold cyan]ANALYSIS RESULTS[/bold cyan]")
        console.print("=" * 60)

        # Sort addresses by risk score
        sorted_addresses = sorted(
            self.addresses_data.items(),
            key=lambda x: x[1].get("anomaly_score", 0),
            reverse=True
        )

        for addr, data in sorted_addresses:
            console.print(f"\n[bold]Address: {addr}[/bold]")
            console.print(f"  Wallet Type: {data.get('wallet_type', 'Unknown')}")
            console.print(f"  Balance: {data.get('balance', 0):.2f} TRX")
            console.print(f"  Transactions: {data.get('transactions_count', 0)}")
            console.print(f"  Risk Score: {data.get('anomaly_score', 0)}/100")

            # Display tokens with names
            if data.get("tokens"):
                console.print("  Tokens:")
                for token in data["tokens"]:
                    token_name = token.get("name", "Unknown")
                    token_symbol = token.get("symbol", "???")
                    token_balance = token.get("balance", 0)
                    console.print(f"    - {token_name} ({token_symbol}): {token_balance:.2f}")

            if data.get("is_exchange", False):
                console.print(f"  [yellow]Exchange: {data.get('exchange_name', 'Unknown')}[/yellow]")

            if data.get("is_malicious", False):
                console.print(f"  [red]WARNING: Known Malicious Address - {data.get('malicious_info', {}).get('type', 'Unknown')}[/red]")

            if data.get("risk_factors"):
                console.print("  Risk Factors:")
                for factor in data["risk_factors"]:
                    console.print(f"    - {factor}")

        console.print("\n" + "=" * 60)

def read_addresses_from_file(file_path):
    """Read addresses from a file, one per line."""
    addresses = []

    try:
        with open(file_path, 'r') as f:
            for line in f:
                addr = line.strip()
                if addr and not addr.startswith("#"):
                    addresses.append(addr)
        console.print(f"[green]Read {len(addresses)} addresses from {file_path}[/green]")
        return addresses
    except Exception as e:
        console.print(f"[yellow]Could not read {file_path}: {str(e)}[/yellow]")
        return []

def main():
    # Get API keys from environment variables
    trongrid_api_key = os.environ.get("TRONGRID_API_KEY", "")
    tronscan_api_key = os.environ.get("TRONSCAN_API_KEY", "")

    # Initialize the analyzer
    analyzer = AdvancedTronAnalyzer(
        trongrid_api_key=trongrid_api_key,
        tronscan_api_key=tronscan_api_key,
        max_transactions=50,
        depth=2,
        use_cache=True,
        checkpoint_interval=5
    )

    # Read addresses from files
    addresses = []

    # First try additional_addresses.txt
    additional_addresses = read_addresses_from_file("additional_addresses.txt")
    if additional_addresses:
        addresses.extend(additional_addresses)

    # If no addresses found, try other files
    if not addresses:
        # Try TRX.txt
        trx_addresses = read_addresses_from_file("TRX.txt")
        if trx_addresses:
            addresses.extend(trx_addresses)

        # Try sample_addresses.txt
        sample_addresses = read_addresses_from_file("sample_addresses.txt")
        if sample_addresses:
            addresses.extend([addr for addr in sample_addresses if addr not in addresses])

    if not addresses:
        console.print("[red]No addresses found to analyze. Please provide addresses in one of the files.[/red]")
        return

    # Display address table
    table = Table(title=f"TRON Addresses for Analysis ({len(addresses)})")
    table.add_column("Index", justify="right", style="cyan")
    table.add_column("Address", style="green")

    for i, addr in enumerate(addresses):
        table.add_row(str(i+1), addr)

    console.print(table)

    # Run the analysis
    console.print(Panel(
        "[cyan]Starting advanced TRON address analysis...[/cyan]\n\n"
        "This analysis includes:\n"
        "- Enhanced connection detection\n"
        "- ML-based anomaly detection\n"
        "- Malicious wallet identification\n"
        "- Transaction hash tracking\n"
        "- Detailed token information\n"
        "- Detailed reporting",
        title="Advanced Analyzer",
        border_style="cyan"
    ))

    # Analyze addresses
    success = analyzer.analyze_addresses(addresses)

    if success:
        # Display analysis results with token names
        analyzer.display_analysis_results()

        # Generate visualization
        viz_file = analyzer.create_network_visualization("advanced_tron")

        # Generate reports
        report_files = analyzer.generate_detailed_report("advanced_tron")
        if len(report_files) == 3:
            excel_file, text_file, json_file = report_files
        else:
            excel_file, text_file = report_files
            json_file = None

        console.print(Panel(
            "[green]Analysis complete![/green]\n\n"
            f"[cyan]Enhanced Visualization:[/cyan] {viz_file}\n"
            f"[cyan]Excel Report:[/cyan] {excel_file}\n"
            f"[cyan]Text Report:[/cyan] {text_file}\n"
            f"[cyan]JSON Data:[/cyan] {json_file if json_file else 'Not generated'}\n\n"
            "The analysis includes transaction hashes, anomaly detection, token names, and detailed connection patterns.",
            title="Analysis Results",
            border_style="green"
        ))
    else:
        console.print("[red]Analysis failed. Please check the logs for details.[/red]")

if __name__ == "__main__":
    main()