#!/usr/bin/env python3
"""
TRON Wallet Analyzer - A tool for automated wallet research on TRON addresses

This script analyzes transaction patterns between TRON addresses and identifies
potential connections, exporting the results to various formats.
"""

import os
import sys
import json
import time
import logging
import argparse
import hashlib
import re
import traceback
import webbrowser
from datetime import datetime, timedelta
from typing import List, Dict, Any, Set, Tuple, Optional
from pathlib import Path

import requests
import pandas as pd
import networkx as nx
from pyvis.network import Network
from rich.console import Console
from rich.progress import (
    Progress, 
    TextColumn, 
    BarColumn, 
    TimeElapsedColumn, 
    TimeRemainingColumn,
    MofNCompleteColumn,
    SpinnerColumn
)

# Import the Transaction Story Generator and Interactive Report Generator
try:
    from fixed_transaction_story import FixedTransactionStoryGenerator
    TransactionStoryGenerator = FixedTransactionStoryGenerator  # For backward compatibility
except ImportError:
    TransactionStoryGenerator = None
    FixedTransactionStoryGenerator = None

try:
    from comprehensive_report_generator import ComprehensiveReportGenerator
except ImportError:
    ComprehensiveReportGenerator = None

try:
    from clean_network_generator import CleanTronNetworkGenerator
except ImportError:
    CleanTronNetworkGenerator = None

from rich.table import Table
from rich.panel import Panel
from rich.logging import RichHandler
from rich.style import Style
from rich import box

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format="%(message)s",
    datefmt="[%X]",
    handlers=[RichHandler(rich_tracebacks=True)]
)
logger = logging.getLogger("tron_analyzer")

# Rich console for pretty output
console = Console()

# TRON API endpoints
TRONGRID_API_URL = "https://api.trongrid.io"
TRONSCAN_API_URL = "https://apilist.tronscan.org/api"

# Cache directory
CACHE_DIR = Path(".cache/tron_analyzer")
# Create cache directory if it doesn't exist
CACHE_DIR.mkdir(parents=True, exist_ok=True)

# Common TRON token contract addresses (TRC20)
KNOWN_TOKENS = {
    "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t": {"name": "USDT", "symbol": "USDT", "type": "Stablecoin"},
    "TNUC9Qb1rRpS5CbWLmNMxXBjyFoydXjWFR": {"name": "Bitcoin-Peg", "symbol": "BTCT", "type": "Pegged"},
    "TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7": {"name": "WINKLINK", "symbol": "WIN", "type": "Utility"},
    "TEkxiTehnzSmSe2XqrBj4w32RUN966rdz8": {"name": "USD Coin", "symbol": "USDC", "type": "Stablecoin"},
    "TWuDZiJ95e31FpNGAWbWHAXsgeVyXKNKp1": {"name": "WardenSwap", "symbol": "WARDEN", "type": "DeFi"},
    "TSSMHYeV2uE9qYH95DqyoCuNCzEL1NvU3S": {"name": "Binance-Peg ETH", "symbol": "ETH", "type": "Pegged"},
    "TMwFHYXLJaRUPeW6421aqXL4ZEzPRFGkGT": {"name": "JUST", "symbol": "JST", "type": "Governance"},
    "TKkeiboTkxXKJpbmVFbv4a8ov5rAfRDMf9": {"name": "JustLend", "symbol": "LEND", "type": "DeFi"},
    "TLvDJcvKJDi3QuHgFbJC6SeTj3UacmtQU3": {"name": "SUN", "symbol": "SUN", "type": "DeFi"}
}

# Import all databases
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
        get_scam_domains_for_address
    )
    MALICIOUS_DB_AVAILABLE = True
except ImportError:
    MALICIOUS_DB_AVAILABLE = False

try:
    from token_classification_database import (
        get_token_info,
        is_known_token,
        is_scam_token,
        get_scam_token_info
    )
    TOKEN_DB_AVAILABLE = True
except ImportError:
    TOKEN_DB_AVAILABLE = False

try:
    from smart_contracts_database import (
        get_contract_info,
        is_smart_contract,
        is_vulnerable_contract,
        get_vulnerability_info
    )
    CONTRACTS_DB_AVAILABLE = True
except ImportError:
    CONTRACTS_DB_AVAILABLE = False

# Transaction types
TRANSACTION_TYPES = {
    "TransferContract": "TRX Transfer",
    "TransferAssetContract": "Token Transfer",
    "TriggerSmartContract": "Smart Contract",
    "VoteWitnessContract": "Vote",
    "WitnessCreateContract": "Witness Creation",
    "AccountCreateContract": "Account Creation",
    "FreezeBalanceContract": "Freeze Balance",
    "UnfreezeBalanceContract": "Unfreeze Balance",
    "WithdrawBalanceContract": "Withdraw Balance",
    "ExchangeCreateContract": "DEX Create",
    "ExchangeInjectContract": "DEX Inject",
    "ExchangeWithdrawContract": "DEX Withdraw",
    "ExchangeTransactionContract": "DEX Trade"
}


class TronWalletAnalyzer:
    """Main class for analyzing TRON wallets and their connections."""

    def __init__(self, api_key: Optional[str] = None, max_transactions: int = 200, 
                 depth: int = 1, min_connection_weight: float = 0.01,
                 use_cache: bool = True, cache_ttl: int = 3600):
        """
        Initialize the TRON wallet analyzer.

        Args:
            api_key: TronGrid API key (optional, but recommended to avoid rate limits)
            max_transactions: Maximum number of transactions to fetch per address
            depth: How deep to search for connections (1 = direct connections only)
            min_connection_weight: Minimum transaction value (in TRX) to consider a connection significant
            use_cache: Whether to use caching to reduce API calls
            cache_ttl: Time-to-live for cached data in seconds (default: 1 hour)
        """
        self.api_key = api_key or os.getenv("TRONGRID_API_KEY", "")
        self.max_transactions = max_transactions
        self.depth = depth
        self.min_connection_weight = min_connection_weight
        self.addresses_data = {}
        self.connections = []
        self.use_cache = use_cache
        self.cache_ttl = cache_ttl
        self.error_count = 0
        self.rate_limit_hit = False

        # Initialize stats for interactive reports
        self.stats = {
            "total_addresses": 0,
            "valid_addresses": 0,
            "active_addresses": 0,
            "total_transactions": 0,
            "total_connections": 0,
            "exchanges_found": 0,
            "tokens_found": 0,
            "malicious_addresses": 0,
            "high_risk_addresses": 0
        }

        # Default headers for API requests
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json",
        }

        # Add API key if available
        if self.api_key:
            self.headers["TRON-PRO-API-KEY"] = self.api_key
        else:
            console.print(
                Panel(
                    "[yellow]⚠️ No TronGrid API key found. You may experience rate limiting.[/yellow]\n" +
                    "Set the TRONGRID_API_KEY environment variable for better performance.",
                    title="API Key Warning",
                    border_style="yellow"
                )
            )

    def _get_cache_path(self, key: str) -> Path:
        """Get the path to a cached file."""
        # Use hashing to create a filename that won't have invalid characters
        hashed_key = hashlib.md5(key.encode()).hexdigest()
        return CACHE_DIR / f"{hashed_key}.json"

    def _get_from_cache(self, key: str) -> Optional[Any]:
        """
        Get data from cache if it exists and is not expired.

        Args:
            key: Cache key

        Returns:
            Cached data if available, None otherwise
        """
        if not self.use_cache:
            return None

        cache_path = self._get_cache_path(key)

        if not cache_path.exists():
            return None

        try:
            # Check if cache is expired
            modification_time = datetime.fromtimestamp(cache_path.stat().st_mtime)
            if datetime.now() - modification_time > timedelta(seconds=self.cache_ttl):
                logger.debug(f"Cache expired for {key}")
                return None

            # Read cache
            with open(cache_path, 'r') as f:
                data = json.load(f)
                logger.debug(f"Cache hit for {key}")
                return data
        except Exception as e:
            logger.debug(f"Error reading cache for {key}: {str(e)}")
            return None

    def _save_to_cache(self, key: str, data: Any) -> None:
        """
        Save data to cache.

        Args:
            key: Cache key
            data: Data to cache (dictionary or list)
        """
        if not self.use_cache:
            return

        cache_path = self._get_cache_path(key)

        try:
            with open(cache_path, 'w') as f:
                json.dump(data, f)
                logger.debug(f"Saved to cache: {key}")
        except Exception as e:
            logger.debug(f"Error saving to cache for {key}: {str(e)}")

    def _handle_api_error(self, response: requests.Response, operation: str) -> Dict[str, Any]:
        """
        Handle API errors with appropriate messages.

        Args:
            response: The API response
            operation: Description of the operation being performed

        Returns:
            Dictionary with error information
        """
        self.error_count += 1

        if response.status_code == 429:
            self.rate_limit_hit = True
            message = "Rate limit exceeded. Consider using an API key or waiting before trying again."
            logger.error(f"[bold red]⚠️ {message}[/bold red]")
            return {"error": "rate_limit", "message": message}

        if response.status_code == 400:
            try:
                error_data = response.json()
                message = error_data.get("error", "Bad request")
            except:
                message = "Bad request"
            logger.error(f"Bad request during {operation}: {message}")
            return {"error": "bad_request", "message": message}

        if response.status_code in (401, 403):
            message = "Authentication failed. Check your API key."
            logger.error(f"[bold red]⚠️ {message}[/bold red]")
            return {"error": "auth_failed", "message": message}

        if response.status_code >= 500:
            message = "TRON API server error. Try again later."
            logger.error(f"[bold red]⚠️ {message}[/bold red]")
            return {"error": "server_error", "message": message}

        # Generic error handling
        try:
            error_data = response.json()
            message = error_data.get("error", f"API error {response.status_code}")
        except:
            message = f"API error {response.status_code}"

        logger.error(f"Error during {operation}: {message}")
        return {"error": "api_error", "message": message}

    def validate_tron_address(self, address: str) -> bool:
        """
        Validate if the string is a valid TRON address.

        Args:
            address: TRON address to validate

        Returns:
            True if valid, False otherwise
        """
        # TRON addresses always start with T and are 34 characters long
        if not address.startswith("T") or len(address) != 34:
            return False

        # For improved reliability, let's use a basic regex pattern
        # This doesn't guarantee the address exists, just that it has valid format
        import re
        tron_address_pattern = re.compile(r'^T[A-Za-z0-9]{33}$')
        if not tron_address_pattern.match(address):
            return False

        # Further validation can be done by querying the blockchain
        # But for now we'll assume it's valid if it passes the format check
        return True

    def fetch_account_info(self, address: str) -> Dict[str, Any]:
        """
        Fetch basic account information for a TRON address.

        Args:
            address: TRON address to fetch info for

        Returns:
            Dictionary with account information
        """
        # Check cache first
        cache_key = f"account_info_{address}"
        cached_data = self._get_from_cache(cache_key)
        if cached_data:
            return cached_data

        try:
            with console.status(f"[cyan]Fetching account info for {address}...[/cyan]", spinner="dots"):
                response = requests.get(
                    f"{TRONGRID_API_URL}/v1/accounts/{address}",
                    headers=self.headers,
                    timeout=15
                )

                # Handle unsuccessful responses
                if response.status_code != 200:
                    error_info = self._handle_api_error(response, f"fetching account info for {address}")
                    return {
                        "address": address,
                        "balance": 0,
                        "exists": False,
                        "error": error_info.get("message", "Unknown error")
                    }

                # Parse data
                try:
                    data = response.json()
                except json.JSONDecodeError:
                    logger.error(f"Error decoding JSON response for {address}")
                    return {
                        "address": address,
                        "balance": 0,
                        "exists": False,
                        "error": "Invalid response format from API"
                    }

                # Check if data exists
                if "data" not in data or len(data["data"]) == 0:
                    logger.warning(f"No account data found for {address}")
                    result = {
                        "address": address, 
                        "balance": 0, 
                        "exists": False,
                        "error": "Address not found or has no data"
                    }
                    self._save_to_cache(cache_key, result)
                    return result

                account_data = data["data"][0]

                # Extract balance information
                balance = 0
                if "balance" in account_data:
                    balance = int(account_data["balance"]) / 1_000_000  # Convert SUN to TRX

                # Get token balances if available
                tokens = {}
                if "trc20" in account_data:
                    try:
                        # TRC20 might be a list of lists OR a dictionary
                        if isinstance(account_data["trc20"], list):
                            for token_item in account_data["trc20"]:
                                if isinstance(token_item, list) and len(token_item) >= 2:
                                    token_address, token_balance = token_item[0], token_item[1]
                                    tokens[token_address] = int(token_balance)
                        elif isinstance(account_data["trc20"], dict):
                            for token_address, token_balance in account_data["trc20"].items():
                                tokens[token_address] = int(token_balance)
                    except Exception as e:
                        logger.debug(f"Could not parse TRC20 token data: {str(e)}")

                # Process token data to add names and types
                processed_tokens = {}
                for token_address, balance in tokens.items():
                    token_info = {
                        "address": token_address,
                        "balance": balance,
                        "name": "Unknown",
                        "symbol": "???",
                        "type": "Unknown"
                    }

                    # Check if this is a known token
                    if token_address in KNOWN_TOKENS:
                        known = KNOWN_TOKENS[token_address]
                        token_info.update({
                            "name": known["name"],
                            "symbol": known["symbol"],
                            "type": known["type"]
                        })

                    processed_tokens[token_address] = token_info

                # Check if this is a known exchange account
                is_exchange = False
                exchange_name = None
                exchange_type = None
                exchange_info = {}

                if EXCHANGES_DB_AVAILABLE:
                    exchange_info = get_exchange_info(address)
                    if exchange_info:
                        is_exchange = True
                        exchange_name = exchange_info["name"]
                        exchange_type = exchange_info.get("type", "Unknown")
                        console.print(f"[bold green]✓ Exchange detected:[/bold green] {address} = {exchange_name}")
                elif address in KNOWN_EXCHANGES:
                    is_exchange = True
                    exchange_name = KNOWN_EXCHANGES[address]
                    console.print(f"[bold green]✓ Exchange detected:[/bold green] {address} = {exchange_name}")

                # Build result
                result = {
                    "address": address,
                    "balance": balance,
                    "tokens": processed_tokens,
                    "exists": True,
                    "created": account_data.get("create_time", 0),
                    "last_activity": account_data.get("latest_opration_time", 0),
                    "frozen": account_data.get("frozen", []),
                    "bandwidth": account_data.get("bandwidth", {}),
                    "resource": account_data.get("resource", {}),
                    "is_exchange": is_exchange,
                    "exchange_name": exchange_name,
                    "exchange_type": exchange_type,
                    "exchange_info": exchange_info
                }

                # Save to cache
                self._save_to_cache(cache_key, result)
                return result

        except requests.Timeout:
            logger.error(f"Timeout while fetching account info for {address}")
            return {
                "address": address,
                "balance": 0,
                "exists": False,
                "error": "Request timed out. Network issues or API is down."
            }
        except Exception as e:
            logger.error(f"Error fetching account info for {address}: {str(e)}")
            if self.rate_limit_hit:
                error_msg = "Rate limit exceeded. Use an API key or reduce request frequency."
            else:
                error_msg = f"Unexpected error: {str(e)}"

            return {
                "address": address,
                "balance": 0,
                "exists": False,
                "error": error_msg
            }

    def fetch_transactions(self, address: str) -> List[Dict[str, Any]]:
        """
        Fetch transactions for a TRON address.

        Args:
            address: TRON address to fetch transactions for

        Returns:
            List of transaction dictionaries
        """
        # Check cache first
        cache_key = f"transactions_{address}_{self.max_transactions}"
        cached_data = self._get_from_cache(cache_key)
        if cached_data and isinstance(cached_data, list):
            logger.info(f"Using cached transactions for {address}")
            return cached_data

        all_transactions = []
        error_occurred = False

        # Fetch transfers to/from this address
        try:
            progress_text = f"[cyan]Fetching transactions for {address}[/cyan]"
            with Progress(
                SpinnerColumn(),
                TextColumn("[progress.description]{task.description}"),
                BarColumn(complete_style="green", finished_style="bright_green"),
                TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
                MofNCompleteColumn(),
                TimeElapsedColumn(),
                TimeRemainingColumn(),
                console=console
            ) as progress:
                task = progress.add_task(progress_text, total=2)  # 2 API calls

                # 1. First fetch normal TRX transfers
                try:
                    response = requests.get(
                        f"{TRONSCAN_API_URL}/transaction",
                        params={
                            "address": address,
                            "limit": self.max_transactions,
                            "sort": "-timestamp"
                        },
                        timeout=15
                    )

                    if response.status_code == 200:
                        try:
                            data = response.json()
                            if "data" in data:
                                # Process and identify transaction types
                                trx_transactions = []
                                for tx in data["data"]:
                                    # Get contract type for classification
                                    contract_type = None
                                    if "contractType" in tx:
                                        contract_type = tx["contractType"]
                                    elif "contract_type" in tx:
                                        contract_type = tx["contract_type"]
                                    elif "contractTypes" in tx and tx["contractTypes"]:
                                        contract_type = tx["contractTypes"][0]

                                    # Set transaction type based on contract type
                                    if contract_type and str(contract_type) in TRANSACTION_TYPES:
                                        tx["transaction_type"] = TRANSACTION_TYPES[str(contract_type)]
                                    else:
                                        tx["transaction_type"] = "Unknown Transaction"

                                    # Check if from/to addresses are exchanges
                                    from_addr = tx.get("from", "")
                                    to_addr = tx.get("to", "")

                                    if from_addr in KNOWN_EXCHANGES:
                                        tx["from_exchange"] = KNOWN_EXCHANGES[from_addr]
                                    elif EXCHANGES_DB_AVAILABLE:
                                        try:
                                            from_exchange_info = get_exchange_info(from_addr)
                                            if from_exchange_info:
                                                tx["from_exchange"] = from_exchange_info["name"]
                                        except:
                                            pass

                                    if to_addr in KNOWN_EXCHANGES:
                                        tx["to_exchange"] = KNOWN_EXCHANGES[to_addr]
                                    elif EXCHANGES_DB_AVAILABLE:
                                        try:
                                            to_exchange_info = get_exchange_info(to_addr)
                                            if to_exchange_info:
                                                tx["to_exchange"] = to_exchange_info["name"]
                                        except:
                                            pass

                                    trx_transactions.append(tx)

                                all_transactions.extend(trx_transactions)
                                logger.debug(f"Fetched {len(trx_transactions)} TRX transactions for {address}")
                            else:
                                logger.warning(f"No transaction data found for {address}")
                        except json.JSONDecodeError:
                            logger.error(f"Error decoding TRX transactions response for {address}")
                            error_occurred = True
                    else:
                        self._handle_api_error(response, f"fetching TRX transactions for {address}")
                        error_occurred = True

                except requests.Timeout:
                    logger.error(f"Timeout while fetching TRX transactions for {address}")
                    error_occurred = True
                except Exception as e:
                    logger.error(f"Error fetching TRX transactions for {address}: {str(e)}")
                    error_occurred = True

                progress.update(task, advance=1)

                # Delay between API calls to avoid rate limiting
                if not error_occurred:
                    time.sleep(1)

                # 2. Then fetch TRC20 token transfers
                try:
                    response = requests.get(
                        f"{TRONSCAN_API_URL}/token_trc20/transfers",
                        params={
                            "relatedAddress": address,
                            "limit": self.max_transactions,
                            "sort": "-timestamp"
                        },
                        timeout=15
                    )

                    if response.status_code == 200:
                        try:
                            data = response.json()
                            if "token_transfers" in data:
                                # Process TRC20 transfers differently
                                token_transfers = []
                                for transfer in data["token_transfers"]:
                                    # Get the token contract address
                                    token_address = transfer.get("contract_address", "")
                                    token_name = transfer.get("tokenName", "Unknown Token")
                                    token_symbol = transfer.get("tokenAbbr", "???")
                                    token_type = "Unknown"

                                    # Check if this is a known token
                                    if token_address in KNOWN_TOKENS:
                                        known_token = KNOWN_TOKENS[token_address]
                                        if not token_name or token_name == "Unknown Token":
                                            token_name = known_token["name"]
                                        if not token_symbol or token_symbol == "???":
                                            token_symbol = known_token["symbol"]
                                        token_type = known_token["type"]

                                    # Check if from/to addresses are exchanges
                                    from_address = transfer.get("from_address", "")
                                    to_address = transfer.get("to_address", "")
                                    from_exchange = None
                                    to_exchange = None

                                    if from_address in KNOWN_EXCHANGES:
                                        from_exchange = KNOWN_EXCHANGES[from_address]

                                    if to_address in KNOWN_EXCHANGES:
                                        to_exchange = KNOWN_EXCHANGES[to_address]

                                    # Add with standardized format and enhanced information
                                    tx = {
                                        "txID": transfer.get("transactionHash", ""),
                                        "timestamp": transfer.get("timestamp", 0),
                                        "transaction_type": "Token Transfer",
                                        "from": from_address,
                                        "to": to_address,
                                        "value": float(transfer.get("quant", "0")),
                                        "tokenName": token_name,
                                        "tokenSymbol": token_symbol,
                                        "tokenType": token_type,
                                        "tokenAddress": token_address,
                                        "confirmed": True,
                                        "from_exchange": from_exchange,
                                        "to_exchange": to_exchange
                                    }
                                    token_transfers.append(tx)

                                all_transactions.extend(token_transfers)
                                logger.debug(f"Fetched {len(token_transfers)} token transfers for {address}")
                            else:
                                logger.debug(f"No token transfers found for {address}")
                        except json.JSONDecodeError:
                            logger.error(f"Error decoding token transfers response for {address}")
                            error_occurred = True
                    else:
                        self._handle_api_error(response, f"fetching token transfers for {address}")
                        error_occurred = True

                except requests.Timeout:
                    logger.error(f"Timeout while fetching token transfers for {address}")
                    error_occurred = True
                except Exception as e:
                    logger.error(f"Error fetching token transfers for {address}: {str(e)}")
                    error_occurred = True

                progress.update(task, advance=1)

        except Exception as e:
            logger.error(f"Unexpected error fetching transactions for {address}: {str(e)}")
            logger.debug(traceback.format_exc())
            error_occurred = True

        # Save to cache if we got some data and no errors occurred
        if all_transactions and not error_occurred:
            self._save_to_cache(cache_key, all_transactions)

        if not all_transactions:
            logger.warning(f"No transactions found for {address}")

        return all_transactions

    def analyze_transactions(self, transactions: List[Dict[str, Any]], address: str) -> Dict[str, Any]:
        """
        Analyze transactions to identify connections to other addresses.

        Args:
            transactions: List of transactions to analyze
            address: The address being analyzed

        Returns:
            Dictionary with analysis results
        """
        connections = {}
        sent_count = 0
        received_count = 0
        sent_volume = 0
        received_volume = 0
        tokens_sent = {}
        tokens_received = {}
        transaction_types = {}
        exchanges_interacted = set()

        for tx in transactions:
            # Get transaction type and track it
            tx_type = tx.get("type", "")
            transaction_type = tx.get("transaction_type", "Unknown Transaction")
            transaction_types[transaction_type] = transaction_types.get(transaction_type, 0) + 1

            # Get addresses
            from_addr = tx.get("from", tx.get("ownerAddress", ""))
            to_addr = tx.get("to", tx.get("toAddress", ""))

            # Skip transactions with missing addresses
            if not from_addr or not to_addr:
                continue

            # Track exchange interactions
            from_exchange = tx.get("from_exchange", None)
            to_exchange = tx.get("to_exchange", None)

            if from_exchange:
                exchanges_interacted.add(from_exchange)
            if to_exchange:
                exchanges_interacted.add(to_exchange)

            # Determine if this is a TRX or token transfer
            is_token = tx_type in ("TRC20_TRANSFER", "TriggerSmartContract") or transaction_type == "Token Transfer"
            token_name = tx.get("tokenName", "TRX")
            token_symbol = tx.get("tokenSymbol", "TRX")
            token_type = tx.get("tokenType", "Native")

            # Extract value based on transaction type
            if is_token:
                value = float(tx.get("value", tx.get("quant", 0)))
                # For some token transfers, we might need to adjust based on decimals
                # This is a simplified approach
            else:
                value = float(tx.get("amount", 0)) / 1_000_000  # Convert SUN to TRX

            # Skip transactions with zero value
            if value <= 0:
                continue

            # Record connections and transaction metrics
            if from_addr.lower() == address.lower():
                # This address sent funds
                sent_count += 1
                if is_token:
                    tokens_sent[token_symbol] = tokens_sent.get(token_symbol, 0) + value
                else:
                    sent_volume += value

                # Record connection to recipient
                if to_addr != address and value >= self.min_connection_weight:
                    if to_addr not in connections:
                        connections[to_addr] = {
                            "sent": 0, "received": 0, 
                            "sent_count": 0, "received_count": 0,
                            "tokens_sent": {}, "tokens_received": {}
                        }

                    connections[to_addr]["sent"] += value if not is_token else 0
                    connections[to_addr]["sent_count"] += 1

                    if is_token:
                        token_data = connections[to_addr]["tokens_sent"]
                        token_data[token_symbol] = token_data.get(token_symbol, 0) + value

            elif to_addr.lower() == address.lower():
                # This address received funds
                received_count += 1
                if is_token:
                    tokens_received[token_symbol] = tokens_received.get(token_symbol, 0) + value
                else:
                    received_volume += value

                # Record connection from sender
                if from_addr != address and value >= self.min_connection_weight:
                    if from_addr not in connections:
                        connections[from_addr] = {
                            "sent": 0, "received": 0, 
                            "sent_count": 0, "received_count": 0,
                            "tokens_sent": {}, "tokens_received": {}
                        }

                    connections[from_addr]["received"] += value if not is_token else 0
                    connections[from_addr]["received_count"] += 1

                    if is_token:
                        token_data = connections[from_addr]["tokens_received"]
                        token_data[token_symbol] = token_data.get(token_symbol, 0) + value

        # Calculate the strength of connections
        for conn_addr, conn_data in connections.items():
            # Simple connection strength calculation
            trx_strength = (conn_data["sent"] + conn_data["received"]) 
            tx_count_strength = (conn_data["sent_count"] + conn_data["received_count"])

            # Add a connection strength score - more transactions and higher values = stronger connection
            conn_data["strength"] = trx_strength * 0.7 + tx_count_strength * 0.3

        return {
            "connections": connections,
            "metrics": {
                "sent_count": sent_count,
                "received_count": received_count,
                "sent_volume": sent_volume,
                "received_volume": received_volume,
                "tokens_sent": tokens_sent,
                "tokens_received": tokens_received,
                "unique_connections": len(connections),
                "transaction_types": transaction_types,
                "exchanges_interacted": list(exchanges_interacted)
            }
        }

    def process_address(self, address: str) -> Dict[str, Any]:
        """
        Process a single address to gather its data and connections.

        Args:
            address: TRON address to process

        Returns:
            Dictionary with processed data
        """
        # Validate the address
        if not self.validate_tron_address(address):
            logger.warning(f"Invalid TRON address: {address}")
            return {
                "address": address,
                "valid": False,
                "error": "Invalid TRON address format or address does not exist"
            }

        # Check if we have cached results for this address
        cache_key = f"processed_address_{address}_{self.max_transactions}_{self.min_connection_weight}"
        cached_data = self._get_from_cache(cache_key)
        if cached_data:
            logger.info(f"Using cached analysis for {address}")
            return cached_data

        # Fetch account information
        account_info = self.fetch_account_info(address)

        # Check for malicious addresses
        is_malicious = False
        malicious_info = {}
        if MALICIOUS_DB_AVAILABLE:
            is_malicious = is_address_malicious(address)
            if is_malicious:
                malicious_info = get_malicious_info(address)
                logger.warning(f"Address {address} is flagged as malicious")

        # Check for token information (scam tokens etc)
        is_scam_token = False
        scam_token_info = {}

        # Check if address is a smart contract
        is_contract = False
        contract_info = {}
        is_vulnerable = False
        vulnerability_info = {}

        if CONTRACTS_DB_AVAILABLE:
            is_contract = is_smart_contract(address)
            if is_contract:
                contract_info = get_contract_info(address)
                is_vulnerable = is_vulnerable_contract(address)
                if is_vulnerable:
                    vulnerability_info = get_vulnerability_info(address)

        if not account_info.get("exists", False):
            error_msg = account_info.get("error", "Address exists but has no activity")
            logger.warning(f"Address {address} does not exist or has no activity: {error_msg}")
            result = {
                "address": address,
                "valid": True,
                "exists": False,
                "error": error_msg
            }
            self._save_to_cache(cache_key, result)
            return result

        # Fetch transactions
        transactions = self.fetch_transactions(address)

        if not transactions:
            logger.warning(f"No transactions found for address {address}")
            result = {
                "address": address,
                "valid": True,
                "exists": True,
                "account_info": account_info,
                "transactions_count": 0,
                "error": "No transactions found"
            }
            self._save_to_cache(cache_key, result)
            return result

        # Analyze transactions to find connections
        analysis = self.analyze_transactions(transactions, address)

        # Perform advanced heuristics analysis
        heuristics = self._analyze_heuristics(transactions, address, account_info)

        # Build the complete address data
        address_data = {
            "address": address,
            "valid": True,
            "exists": True,
            "account_info": account_info,
            "transactions_count": len(transactions),
            "analysis": analysis,
            "heuristics": heuristics,
            "is_malicious": is_malicious,
            "malicious_info": malicious_info,
            "is_scam_token": is_scam_token,
            "scam_token_info": scam_token_info,
            "is_contract": is_contract,
            "contract_info": contract_info,
            "is_vulnerable": is_vulnerable,
            "vulnerability_info": vulnerability_info
        }

        # Save results to cache
        self._save_to_cache(cache_key, address_data)

        return address_data

    def _analyze_heuristics(self, transactions: List[Dict[str, Any]], 
                            address: str, account_info: Dict[str, Any]) -> Dict[str, Any]:
        """
        Perform advanced heuristics analysis on transaction patterns.

        Args:
            transactions: List of transactions to analyze
            address: The address being analyzed
            account_info: Account information

        Returns:
            Dictionary with heuristics analysis results
        """
        if not transactions:
            return {"wallet_type": "unknown", "risk_score": 0, "patterns": []}

        # Initialize variables for analysis
        incoming_tx_count = 0
        outgoing_tx_count = 0
        unique_incoming_addresses = set()
        unique_outgoing_addresses = set()
        token_types = set()
        tx_amounts = []
        tx_frequencies = {}  # timestamp bucket -> count
        patterns = []
        periodic_patterns = []
        risk_indicators = []

        # Extract transaction timestamps for time pattern analysis
        timestamps = []

        # Sort transactions by timestamp
        sorted_tx = sorted(transactions, key=lambda x: x.get("timestamp", 0))
        first_tx_time = sorted_tx[0].get("timestamp", 0) if sorted_tx else 0
        last_tx_time = sorted_tx[-1].get("timestamp", 0) if sorted_tx else 0

        # Calculate transaction frequencies over time
        day_buckets = {}
        hour_buckets = {}

        for tx in transactions:
            tx_type = tx.get("type", "")
            from_addr = tx.get("from", tx.get("ownerAddress", ""))
            to_addr = tx.get("to", tx.get("toAddress", ""))
            timestamp = tx.get("timestamp", 0)

            # Skip transactions with missing addresses
            if not from_addr or not to_addr:
                continue

            # Record token types
            if "tokenName" in tx and tx["tokenName"]:
                token_types.add(tx["tokenName"])

            # Extract timestamp for pattern analysis
            if timestamp:
                timestamps.append(timestamp)

                # Daily frequency
                day = timestamp // (24 * 3600 * 1000)  # Convert to day bucket
                day_buckets[day] = day_buckets.get(day, 0) + 1

                # Hourly frequency
                hour = timestamp // (3600 * 1000)  # Convert to hour bucket
                hour_buckets[hour] = hour_buckets.get(hour, 0) + 1

            # Determine if this is a TRX or token transfer
            is_token = tx_type in ("TRC20_TRANSFER", "TriggerSmartContract")

            # Extract value based on transaction type
            value = 0
            if is_token:
                value = float(tx.get("value", tx.get("quant", 0)))
            else:
                value = float(tx.get("amount", 0)) / 1_000_000  # Convert SUN to TRX

            if value > 0:
                tx_amounts.append(value)

            # Count incoming and outgoing transactions
            if from_addr.lower() == address.lower():
                # Outgoing transaction
                outgoing_tx_count += 1
                unique_outgoing_addresses.add(to_addr)

                # Check for large outflows
                if not is_token and value > 10000:  # Large TRX transfer
                    risk_indicators.append({
                        "type": "large_outflow",
                        "details": f"Large outgoing transfer of {value} TRX to {to_addr}"
                    })
            elif to_addr.lower() == address.lower():
                # Incoming transaction
                incoming_tx_count += 1
                unique_incoming_addresses.add(from_addr)

                # Check for large inflows
                if not is_token and value > 10000:  # Large TRX transfer
                    risk_indicators.append({
                        "type": "large_inflow",
                        "details": f"Large incoming transfer of {value} TRX from {from_addr}"
                    })

        # Analyze transaction patterns

        # 1. Frequency patterns (lots of similar-sized transactions)
        if tx_amounts:
            # Group amounts by rounded value to find patterns
            rounded_amounts = {}
            for amount in tx_amounts:
                # Round to 2 decimal places for pattern detection
                rounded = round(amount, 2)
                rounded_amounts[rounded] = rounded_amounts.get(rounded, 0) + 1

            # Find most frequent transaction amounts
            frequent_amounts = sorted(
                [(amt, count) for amt, count in rounded_amounts.items() if count > 1],
                key=lambda x: x[1], 
                reverse=True
            )[:5]  # Top 5 frequent amounts

            if frequent_amounts:
                for amount, count in frequent_amounts:
                    if count >= 3:  # At least 3 occurrences
                        percentage = (count / len(tx_amounts)) * 100
                        if percentage >= 10:  # At least 10% of transactions
                            patterns.append({
                                "type": "frequent_amount",
                                "details": f"{amount} TRX/tokens occurs {count} times ({percentage:.1f}% of transactions)"
                            })

        # 2. Time patterns
        if timestamps and len(timestamps) >= 5:
            # Check for periodic transactions (daily, weekly patterns)
            time_diffs = []
            for i in range(1, len(timestamps)):
                diff = (timestamps[i] - timestamps[i-1]) / (1000 * 60 * 60)  # Hours
                time_diffs.append(diff)

            # Look for consistent time differences
            hour_diff_buckets = {}
            for diff in time_diffs:
                rounded_diff = round(diff)
                hour_diff_buckets[rounded_diff] = hour_diff_buckets.get(rounded_diff, 0) + 1

            # Find most common time differences
            common_diffs = sorted(
                [(diff, count) for diff, count in hour_diff_buckets.items() if count > 1],
                key=lambda x: x[1], 
                reverse=True
            )[:3]  # Top 3 time differences

            for diff, count in common_diffs:
                if count >= 3:  # At least 3 occurrences
                    if 23 <= diff <= 25:  # Daily pattern
                        periodic_patterns.append({
                            "type": "daily",
                            "count": count,
                            "details": f"Transactions occur approximately daily ({count} occurrences)"
                        })
                    elif 167 <= diff <= 169:  # Weekly pattern
                        periodic_patterns.append({
                            "type": "weekly",
                            "count": count,
                            "details": f"Transactions occur approximately weekly ({count} occurrences)"
                        })

            # Check for specific time-of-day patterns (business hours vs. night)
            if hour_buckets:
                business_hours_count = 0
                night_hours_count = 0

                for hour, count in hour_buckets.items():
                    hour_of_day = (hour % 24)
                    if 9 <= hour_of_day <= 17:  # 9 AM - 5 PM
                        business_hours_count += count
                    elif 0 <= hour_of_day <= 4:  # Midnight - 4 AM
                        night_hours_count += count

                total_hours = sum(hour_buckets.values())
                business_hours_pct = (business_hours_count / total_hours) * 100
                night_hours_pct = (night_hours_count / total_hours) * 100

                if business_hours_pct >= 70:
                    patterns.append({
                        "type": "business_hours",
                        "details": f"{business_hours_pct:.1f}% of transactions occur during business hours"
                    })
                elif night_hours_pct >= 40:
                    patterns.append({
                        "type": "night_activity",
                        "details": f"{night_hours_pct:.1f}% of transactions occur during night hours (midnight-4am)"
                    })

        # 3. Balance and transaction volume patterns
        balance = account_info.get("balance", 0)

        # Calculate transaction volume
        total_incoming = sum(float(tx.get("amount", 0)) / 1_000_000 for tx in transactions 
                         if tx.get("to", "") == address and not tx.get("type", "").startswith("TRC20"))
        total_outgoing = sum(float(tx.get("amount", 0)) / 1_000_000 for tx in transactions 
                          if tx.get("from", "") == address and not tx.get("type", "").startswith("TRC20"))

        # Determine wallet type
        wallet_type = "unknown"
        wallet_type_confidence = 0
        wallet_subtype = ""

        # Analyze wallet characteristics
        incoming_to_outgoing_ratio = 0
        if outgoing_tx_count > 0:
            incoming_to_outgoing_ratio = incoming_tx_count / outgoing_tx_count

        # Calculate average transaction values
        avg_incoming = 0
        if incoming_tx_count > 0:
            avg_incoming = total_incoming / incoming_tx_count

        avg_outgoing = 0
        if outgoing_tx_count > 0:
            avg_outgoing = total_outgoing / outgoing_tx_count

        # Unique address patterns
        unique_incoming_count = len(unique_incoming_addresses)
        unique_outgoing_count = len(unique_outgoing_addresses)

        # 1. Exchange wallet patterns
        if (unique_incoming_count > 50 and unique_outgoing_count > 50 and 
            len(transactions) > 100):
            wallet_type = "exchange"
            wallet_type_confidence = 0.7

            # Hot vs. cold wallet
            if balance > 100000:  # High balance
                wallet_subtype = "hot_wallet"
                if len(transactions) > 1000:
                    wallet_type_confidence = 0.9

        # 2. Personal wallet patterns
        elif (unique_incoming_count < 20 and unique_outgoing_count < 20 and
             len(transactions) < 100):
            wallet_type = "personal"
            wallet_type_confidence = 0.6

            # Active trader vs. hodler
            if len(token_types) > 5:
                wallet_subtype = "trader"
                wallet_type_confidence = 0.8
            elif incoming_tx_count > outgoing_tx_count * 3:
                wallet_subtype = "hodler"
                wallet_type_confidence = 0.7

        # 3. Mining pool patterns
        elif (outgoing_tx_count > incoming_tx_count * 5 and
              unique_outgoing_count > unique_incoming_count * 5):
            wallet_type = "mining_pool"
            wallet_type_confidence = 0.7

        # 4. Smart contract patterns
        elif "token" in "".join(token_types).lower() or len(token_types) > 10:
            wallet_type = "contract"
            wallet_type_confidence = 0.6

        # Risk scoring (0-100, higher = more suspicious)
        risk_score = 0

        # Base risk indicators
        if len(risk_indicators) > 0:
            risk_score += len(risk_indicators) * 10

        # Transaction pattern risks
        if unique_incoming_count > 100 and unique_outgoing_count < 5:
            risk_score += 15
            risk_indicators.append({
                "type": "funnel_pattern",
                "details": "Many incoming sources, few outgoing destinations"
            })

        if total_outgoing > total_incoming * 1.5 and balance < 100:
            risk_score += 20
            risk_indicators.append({
                "type": "unexplained_outflows",
                "details": "Outgoing volume exceeds incoming volume significantly"
            })

        # Cap risk score at 100
        risk_score = min(risk_score, 100)

        return {
            "wallet_type": wallet_type,
            "wallet_subtype": wallet_subtype,
            "type_confidence": wallet_type_confidence,
            "transaction_patterns": patterns,
            "periodic_patterns": periodic_patterns,
            "risk_score": risk_score,
            "risk_indicators": risk_indicators,
            "stats": {
                "unique_incoming_addresses": unique_incoming_count,
                "unique_outgoing_addresses": unique_outgoing_count,
                "token_types": len(token_types),
                "avg_incoming_value": avg_incoming,
                "avg_outgoing_value": avg_outgoing,
                "incoming_to_outgoing_ratio": incoming_to_outgoing_ratio,
                "active_period_days": (last_tx_time - first_tx_time) / (24 * 3600 * 1000) if first_tx_time else 0
            }
        }

    def analyze_addresses(self, addresses: List[str]) -> None:
        """
        Analyze multiple TRON addresses and their connections.

        Args:
            addresses: List of TRON addresses to analyze
        """
        # Initialize stats
        self.stats["total_addresses"] = len(addresses)

        # Process each address
        with Progress(
            SpinnerColumn(),
            TextColumn("[progress.description]{task.description}"),
            BarColumn(complete_style="cyan", finished_style="bright_cyan"),
            TextColumn("[progress.percentage]{task.percentage:>3.0f}%"),
            MofNCompleteColumn(),
            TimeElapsedColumn(),
            TimeRemainingColumn()
        ) as progress:
            task = progress.add_task("[bold cyan]Analyzing addresses...", total=len(addresses))

            for address in addresses:
                address_data = self.process_address(address)
                self.addresses_data[address] = address_data

                # Update stats
                if address_data.get("valid", False):
                    self.stats["valid_addresses"] += 1
                if address_data.get("exists", False):
                    self.stats["active_addresses"] += 1
                    self.stats["total_transactions"] += address_data.get("transactions_count", 0)
                if address_data.get("account_info", {}).get("is_exchange", False):
                    self.stats["exchanges_found"] += 1
                if address_data.get("is_malicious", False):
                    self.stats["malicious_addresses"] += 1
                if address_data.get("heuristics", {}).get("risk_score", 0) >= 50:
                    self.stats["high_risk_addresses"] += 1

                progress.update(task, advance=1)

        # Find connections between the analyzed addresses
        self.find_connections()

        # Update connection stats
        self.stats["total_connections"] = len(self.connections)

    def find_connections(self) -> None:
        """Find connections between the analyzed addresses and organize the results."""
        all_connections = []

        # Process each address to find connections to other addresses in our list
        for address, data in self.addresses_data.items():
            if not data.get("valid", False) or not data.get("exists", False):
                continue

            if "analysis" not in data or "connections" not in data["analysis"]:
                continue

            # Check if any connections are to other addresses in our list
            for conn_addr, conn_data in data["analysis"]["connections"].items():
                if conn_addr in self.addresses_data:
                    # This is a connection between two addresses in our list
                    connection = {
                        "from_address": address,
                        "to_address": conn_addr,
                        "trx_sent": conn_data.get("sent", 0),
                        "trx_received": conn_data.get("received", 0),
                        "sent_count": conn_data.get("sent_count", 0),
                        "received_count": conn_data.get("received_count", 0),
                        "strength": conn_data.get("strength", 0),
                        "token_transfers": bool(conn_data.get("tokens_sent") or conn_data.get("tokens_received"))
                    }
                    all_connections.append(connection)

        self.connections = all_connections

    def create_advanced_network_visualization(self, output_file: str = "tron_network") -> str:
        """
        Create an advanced interactive network visualization with search functionality.

        Args:
            output_file: Base name for output HTML file

        Returns:
            Path to the generated advanced HTML file
        """
        if not self.connections or len(self.connections) == 0:
            logger.warning("No connections to visualize. Skipping network graph creation.")
            return ""

        if CleanTronNetworkGenerator is None:
            logger.warning("Clean Network Generator not available. Using basic visualization.")
            return self.create_network_visualization(output_file)

        # Initialize the clean generator
        generator = CleanTronNetworkGenerator()

        # Prepare addresses data in the expected format
        addresses_data = {}
        for address, data in self.addresses_data.items():
            if data.get("exists", False):
                # Extract relevant information
                balance = data.get("account_info", {}).get("balance", 0) / 1_000_000  # Convert to TRX
                txn_count = data.get("transactions_count", 0)

                # Extract wallet type and risk from heuristics
                wallet_type = "Unknown"
                risk_score = 0
                if "heuristics" in data:
                    wallet_type = data["heuristics"].get("wallet_type", "unknown").capitalize()
                    risk_score = data["heuristics"].get("risk_score", 0)

                # Check if this is an exchange
                is_exchange = data.get("account_info", {}).get("is_exchange", False)
                exchange_name = data.get("account_info", {}).get("exchange_name", None)

                if is_exchange:
                    wallet_type = "Exchange"

                # Get token information
                tokens = data.get("account_info", {}).get("tokens", {})
                token_count = len(tokens)

                # Activity level based on transaction count
                if txn_count > 1000:
                    activity_level = "High"
                elif txn_count > 100:
                    activity_level = "Medium"
                else:
                    activity_level = "Low"

                addresses_data[address] = {
                    "wallet_type": wallet_type,
                    "balance_trx": balance,
                    "risk_score": risk_score,
                    "transactions_count": txn_count,
                    "activity_level": activity_level,
                    "is_exchange": is_exchange,
                    "exchange_name": exchange_name,
                    "token_count": token_count,
                    "tokens": tokens
                }

        # Prepare connections data
        connections_data = []
        for conn in self.connections:
            source = conn["from_address"]
            target = conn["to_address"]

            # Only include connections where both addresses exist in our data
            if source in addresses_data and target in addresses_data:
                amount = conn["trx_sent"] + conn["trx_received"]
                count = conn["sent_count"] + conn["received_count"]

                connections_data.append({
                    "from_address": source,
                    "to_address": target,
                    "amount": amount,
                    "count": count,
                    "trx_sent": conn["trx_sent"],
                    "trx_received": conn["trx_received"],
                    "token_transfers": conn.get("token_transfers", False)
                })

        # Create the advanced visualization
        try:
            filename = generator.create_graph(
                addresses_data, 
                connections_data, 
                f"{output_file}_interactive"
            )

            # Copy to reports folder
            reports_dir = Path("results/reports")
            reports_dir.mkdir(parents=True, exist_ok=True)

            import shutil
            report_filename = reports_dir / Path(filename).name
            shutil.copy2(filename, report_filename)

            logger.info(f"Advanced network visualization saved to {filename}")
            logger.info(f"Report copy saved to {report_filename}")
            return filename

        except Exception as e:
            logger.error(f"Error creating advanced network visualization: {str(e)}")
            # Fall back to basic visualization
            return self.create_network_visualization(output_file)

    def create_network_visualization(self, output_file: str = "tron_network") -> str:
        """
        Create an interactive network visualization of wallet connections.

        Args:
            output_file: Base name for output HTML file

        Returns:
            Path to the generated HTML file or empty string if no connections
        """
        if not self.connections or len(self.connections) == 0:
            logger.warning("No connections to visualize. Skipping network graph creation.")
            return ""

        # Create a timestamp for the filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        html_file = f"{output_file}_graph_{timestamp}.html"

        # Create a directed graph
        G = nx.DiGraph()

        # Add nodes (addresses)
        for address, data in self.addresses_data.items():
            if data.get("exists", False):
                # Prepare node attributes
                balance = data.get("account_info", {}).get("balance", 0)
                txn_count = data.get("transactions_count", 0)

                # Extract wallet type and risk if available
                wallet_type = "Unknown"
                risk_score = 0
                if "heuristics" in data:
                    wallet_type = data["heuristics"].get("wallet_type", "unknown").capitalize()
                    risk_score = data["heuristics"].get("risk_score", 0)

                # Get exchange info if available
                is_exchange = data.get("account_info", {}).get("is_exchange", False)
                exchange_name = data.get("account_info", {}).get("exchange_name", None)

                # Get token information (top tokens by balance)
                token_info = ""
                tokens = data.get("account_info", {}).get("tokens", {})
                if tokens:
                    # Sort tokens by balance and take top 5
                    top_tokens = []
                    for token_addr, token_data in tokens.items():
                        if isinstance(token_data, dict) and "name" in token_data and "balance" in token_data:
                            top_tokens.append(token_data)

                    # Sort by balance (descending)
                    top_tokens = sorted(top_tokens, key=lambda x: x.get("balance", 0), reverse=True)[:5]

                    if top_tokens:
                        token_info = "\nTop Tokens:\n"
                        for token in top_tokens:
                            token_symbol = token.get("symbol", "???")
                            token_balance = token.get("balance", 0)
                            token_info += f"• {token_symbol}: {token_balance:,}\n"

                # Format title/hover text
                title = (
                    f"Address: {address}\n"
                    f"Balance: {balance/1_000_000:.2f} TRX\n"
                    f"Transactions: {txn_count}\n"
                    f"Type: {wallet_type}\n"
                    f"Risk Score: {risk_score}"
                )

                # Add exchange information if available
                if is_exchange and exchange_name:
                    title += f"\nExchange: {exchange_name}"

                # Add token information if available
                if token_info:
                    title += token_info

                # Determine color based on wallet type
                color_map = {
                    "Exchange": "#3498db",  # Blue
                    "Personal": "#2ecc71",  # Green
                    "Contract": "#e74c3c",  # Red
                    "Mining": "#f39c12",    # Orange
                    "Unknown": "#9b59b6"    # Purple
                }

                # Default to Unknown color if not found
                color = color_map.get(wallet_type, color_map["Unknown"])

                # Prepare the label
                label = f"{address[:6]}...{address[-4:]}"

                # Add exchange tag if this is an exchange
                if is_exchange and exchange_name:
                    label = f"{exchange_name}: {label}"

                # Add symbols of top tokens if any
                top_token_symbols = []
                if tokens:
                    for token_addr, token_data in tokens.items():
                        if isinstance(token_data, dict) and "symbol" in token_data:
                            top_token_symbols.append(token_data["symbol"])
                    # Take top 3 token symbols
                    if top_token_symbols:
                        top_token_symbols = top_token_symbols[:3]

                # Add token symbols to label if any
                if top_token_symbols:
                    label += f" ({', '.join(top_token_symbols)})"

                # Add the node with properties
                G.add_node(
                    address, 
                    title=title,
                    label=label,
                    color=color,
                    size=(10 + min(txn_count/10, 30)),  # Scale node size based on transaction count
                    font={"color": "white"}  # Ensure label is visible on colored nodes
                )

        # Add edges (connections)
        for conn in self.connections:
            source = conn["from_address"]
            target = conn["to_address"]
            weight = conn["sent_count"] + conn["received_count"]
            value = conn["trx_sent"] + conn["trx_received"]

            # Only add edges between nodes that exist in the graph
            if source in G.nodes and target in G.nodes:
                # Check if this connection involves token transfers
                has_tokens = conn.get("token_transfers", False)

                # Get token details if available
                token_details = ""
                if has_tokens:
                    # Find the connection data in the original analysis
                    source_data = self.addresses_data.get(source, {})
                    if "analysis" in source_data and "connections" in source_data["analysis"]:
                        conn_data = source_data["analysis"]["connections"].get(target, {})

                        # Add token sent information
                        tokens_sent = conn_data.get("tokens_sent", {})
                        if tokens_sent:
                            token_details += "\nTokens Sent:\n"
                            for token_symbol, amount in tokens_sent.items():
                                token_details += f"• {token_symbol}: {amount:,.2f}\n"

                        # Add token received information
                        tokens_received = conn_data.get("tokens_received", {})
                        if tokens_received:
                            token_details += "\nTokens Received:\n"
                            for token_symbol, amount in tokens_received.items():
                                token_details += f"• {token_symbol}: {amount:,.2f}\n"

                # Prepare edge attributes
                title = f"Transactions: {weight}\nTotal: {value:.2f} TRX"

                # Add token details to title if available
                if token_details:
                    title += token_details

                # Determine edge color based on transaction type
                edge_color = "#555555"  # Default gray
                if has_tokens:
                    edge_color = "#3498db"  # Blue for token transfers

                # Add the edge with properties
                G.add_edge(
                    source, 
                    target, 
                    title=title,
                    value=weight,  # Line thickness based on transaction count
                    arrows="to",   # Show direction of funds
                    color=edge_color
                )

        try:
            # Create pyvis network
            net = Network(height="800px", width="100%", directed=True, notebook=False)

            # Count exchanges and token types
            exchange_count = 0
            token_types_found = set()
            for addr, data in self.addresses_data.items():
                if data.get("account_info", {}).get("is_exchange", False):
                    exchange_count += 1

                # Get token types from account info
                tokens = data.get("account_info", {}).get("tokens", {})
                for token_addr, token_data in tokens.items():
                    if isinstance(token_data, dict) and "type" in token_data:
                        token_types_found.add(token_data["type"])

                # Also check transaction types
                if "analysis" in data and "metrics" in data["analysis"]:
                    transaction_types = data["analysis"]["metrics"].get("transaction_types", {})
                    if transaction_types:
                        for tx_type in transaction_types.keys():
                            if "Token" in tx_type:
                                token_types_found.add("Token Transfer")

            # Create a descriptive heading with analysis details
            active_nodes = sum(1 for addr, data in self.addresses_data.items() if data.get("exists", False))
            timestamp = datetime.now().strftime("%Y-%m-%d %Y%m%d %H:%M:%S")

            heading = f"TRON Wallet Network Analysis - {timestamp}<br>"
            heading += f"<span style='font-size:0.9em'>Analyzed {active_nodes} wallets with {len(self.connections)} connections</span>"

            # Add additional metrics
            if exchange_count > 0 or token_types_found:
                heading += f"<div style='margin-top:5px; font-size:0.8em;'>"
                if exchange_count > 0:
                    heading += f"Found {exchange_count} exchange{'s' if exchange_count > 1 else ''} • "
                if token_types_found:
                    heading += f"{len(token_types_found)} token type{'s' if len(token_types_found) > 1 else ''}"
                heading += "</div>"

            # Add a color legend for node types
            heading += "<div style='margin-top:10px; font-size:0.8em; text-align:center;'>"
            heading += "<span style='color:#3498db;'>&#9679;</span> Exchange &nbsp;"
            heading += "<span style='color:#2ecc71;'>&#9679;</span> Personal &nbsp;"
            heading += "<span style='color:#e74c3c;'>&#9679;</span> Contract &nbsp;"
            heading += "<span style='color:#f39c12;'>&#9679;</span> Mining &nbsp;"
            heading += "<span style='color:#9b59b6;'>&#9679;</span> Unknown"
            heading += "</div>"

            # Add legend for connection types
            heading += "<div style='margin-top:5px; font-size:0.8em; text-align:center;'>"
            heading += "<span style='color:#555555;'>——</span> TRX Transfer &nbsp;"
            heading += "<span style='color:#3498db;'>——</span> Token Transfer"
            heading += "</div>"

            net.heading = heading

            # Set graph options
            net.set_options("""
            {
              "nodes": {
                "shape": "dot",
                "font": {
                  "size": 14,
                  "face": "Roboto"
                }
              },
              "edges": {
                "color": {
                  "inherit": false
                },
                "smooth": {
                  "enabled": true,
                  "type": "dynamic"
                }
              },
              "physics": {
                "stabilization": {
                  "enabled": true,
                  "iterations": 100
                },
                "barnesHut": {
                  "gravitationalConstant": -80000,
                  "springConstant": 0.001,
                  "springLength": 200
                }
              },
              "interaction": {
                "navigationButtons": true,
                "keyboard": true
              }
            }
            """)

            # Load the NetworkX graph
            net.from_nx(G)

            # Save the visualization to an HTML file
            net.save_graph(html_file)

            logger.info(f"Network visualization saved to {html_file}")

            # Attempt to open the graph in a browser
            try:
                webbrowser.open('file://' + os.path.abspath(html_file))
            except Exception as e:
                logger.debug(f"Could not open browser automatically: {str(e)}")

            return html_file

        except Exception as e:
            logger.error(f"Error creating network visualization: {str(e)}")
            return ""

    def export_to_csv(self, output_file: str, format_type: str = "csv") -> List[str]:
        """
        Export analysis results to various formats.

        Args:
            output_file: Base name for output files
            format_type: Format type, one of "csv", "json", or "all"

        Returns:
            List of paths to the exported files
        """
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")

        # Export address data
        addresses_data = []
        for address, data in self.addresses_data.items():
            if not data.get("valid", False):
                addresses_data.append({
                    "address": address,
                    "valid": False,
                    "balance_trx": 0,
                    "transactions_count": 0,
                    "unique_connections": 0,
                    "sent_volume": 0,
                    "received_volume": 0,
                    "error": data.get("error", "Invalid address")
                })
                continue

            if not data.get("exists", False):
                addresses_data.append({
                    "address": address,
                    "valid": True,
                    "exists": False,
                    "balance_trx": 0,
                    "transactions_count": 0,
                    "unique_connections": 0,
                    "sent_volume": 0,
                    "received_volume": 0,
                    "error": data.get("error", "Address has no activity")
                })
                continue

            # Extract relevant metrics
            metrics = data.get("analysis", {}).get("metrics", {})
            address_row = {
                "address": address,
                "valid": True,
                "exists": True,
                "balance_trx": data.get("account_info", {}).get("balance", 0),
                "transactions_count": data.get("transactions_count", 0),
                "unique_connections": metrics.get("unique_connections", 0),
                "sent_volume": metrics.get("sent_volume", 0),
                "received_volume": metrics.get("received_volume", 0),
                "sent_count": metrics.get("sent_count", 0),
                "received_count": metrics.get("received_count", 0)
            }

            # Add heuristics data if available
            if "heuristics" in data:
                heuristics = data["heuristics"]
                address_row.update({
                    "wallet_type": heuristics.get("wallet_type", "unknown"),
                    "wallet_subtype": heuristics.get("wallet_subtype", ""),
                    "risk_score": heuristics.get("risk_score", 0),
                    "patterns": len(heuristics.get("transaction_patterns", [])),
                    "active_period_days": heuristics.get("stats", {}).get("active_period_days", 0)
                })

            addresses_data.append(address_row)

        # Create DataFrames
        addresses_df = pd.DataFrame(addresses_data)
        connections_df = pd.DataFrame(self.connections) if self.connections else pd.DataFrame()

        # Set up file paths for different formats
        base_addresses = f"{output_file}_addresses_{timestamp}"
        base_connections = f"{output_file}_connections_{timestamp}"
        base_heuristics = f"{output_file}_heuristics_{timestamp}"

        exported_files = []

        # Export based on format type
        if format_type in ["csv", "all"]:
            # Export to CSV
            addresses_csv = f"{base_addresses}.csv"
            addresses_df.to_csv(addresses_csv, index=False)
            exported_files.append(addresses_csv)

            if not self.connections:
                logger.warning("No connections found between the analyzed addresses.")
            else:
                connections_csv = f"{base_connections}.csv"
                connections_df.to_csv(connections_csv, index=False)
                exported_files.append(connections_csv)

            # Export heuristics data if we have any
            heuristics_data = []
            for address, data in self.addresses_data.items():
                if data.get("exists", False) and "heuristics" in data:
                    h_data = data["heuristics"]

                    # Extract risk indicators
                    risk_indicators = []
                    for ri in h_data.get("risk_indicators", []):
                        risk_indicators.append(f"{ri.get('type', '')}: {ri.get('details', '')}")

                    # Extract patterns
                    patterns = []
                    for p in h_data.get("transaction_patterns", []):
                        patterns.append(f"{p.get('type', '')}: {p.get('details', '')}")

                    # Add to heuristics data
                    heuristics_data.append({
                        "address": address,
                        "wallet_type": h_data.get("wallet_type", "unknown"),
                        "wallet_subtype": h_data.get("wallet_subtype", ""),
                        "type_confidence": h_data.get("type_confidence", 0),
                        "risk_score": h_data.get("risk_score", 0),
                        "unique_incoming": h_data.get("stats", {}).get("unique_incoming_addresses", 0),
                        "unique_outgoing": h_data.get("stats", {}).get("unique_outgoing_addresses", 0),
                        "token_types": h_data.get("stats", {}).get("token_types", 0),
                        "avg_incoming": h_data.get("stats", {}).get("avg_incoming_value", 0),
                        "avg_outgoing": h_data.get("stats", {}).get("avg_outgoing_value", 0),
                        "io_ratio": h_data.get("stats", {}).get("incoming_to_outgoing_ratio", 0),
                        "active_days": h_data.get("stats", {}).get("active_period_days", 0),
                        "risk_indicators": "; ".join(risk_indicators),
                        "patterns": "; ".join(patterns)
                    })

            if heuristics_data:
                heuristics_df = pd.DataFrame(heuristics_data)
                heuristics_csv = f"{base_heuristics}.csv"
                heuristics_df.to_csv(heuristics_csv, index=False)
                exported_files.append(heuristics_csv)

        if format_type in ["json", "all"]:
            # Export full data to JSON
            full_data = {
                "meta": {
                    "timestamp": datetime.now().isoformat(),
                    "addresses_count": len(self.addresses_data),
                    "connections_count": len(self.connections),
                    "active_addresses": sum(1 for data in self.addresses_data.values() if data.get("exists", False)),
                    "analyzer_version": "2.0",
                    "analysis_depth": self.depth,
                    "max_transactions_per_address": self.max_transactions
                },
                "addresses": self.addresses_data,
                "connections": self.connections,
                "summary_statistics": {
                    "total_addresses": len(self.addresses_data),
                    "valid_addresses": sum(1 for data in self.addresses_data.values() if data.get("valid", False)),
                    "active_addresses": sum(1 for data in self.addresses_data.values() if data.get("exists", False)),
                    "total_transactions": sum(data.get("transactions_count", 0) for data in self.addresses_data.values()),
                    "total_connections": len(self.connections),
                    "exchanges_found": sum(1 for data in self.addresses_data.values() if data.get("account_info", {}).get("is_exchange", False)),
                    "malicious_addresses": sum(1 for data in self.addresses_data.values() if data.get("is_malicious", False)),
                    "high_risk_addresses": sum(1 for data in self.addresses_data.values() if data.get("heuristics", {}).get("risk_score", 0) >= 50)
                }
            }

            # Ensure directory exists
            Path("results/reports").mkdir(parents=True, exist_ok=True)

            json_file = f"results/reports/{output_file}_full_{timestamp}.json"
            with open(json_file, 'w') as f:
                json.dump(full_data, f, indent=2, default=str)

            exported_files.append(json_file)
            logger.info(f"JSON data exported to {json_file}")

        # Generate detailed text report in results/reports/
        try:
            logger.info("Generating detailed text report...")
            text_report_file = f"results/reports/{output_file}_detailed_report_{timestamp}.txt"
            self._generate_text_report(text_report_file)
            exported_files.append(text_report_file)
        except Exception as e:
            logger.error(f"Failed to generate text report: {str(e)}")

        # Generate interactive story reports
        try:
            from interactive_story_report import InteractiveStoryReportGenerator
            interactive_generator_available = True
        except ImportError:
            interactive_generator_available = False

        if interactive_generator_available:
            try:
                # Create story generator if available
                story_generator = None
                if FixedTransactionStoryGenerator is not None:
                    story_generator = FixedTransactionStoryGenerator(self)

                # Create interactive report generator with proper data structure
                interactive_generator = InteractiveStoryReportGenerator(self, story_generator)

                # Ensure data structure compatibility - normalize data formats
                for addr, data in self.addresses_data.items():
                    if not data.get("exists", False):
                        continue

                    # Ensure both anomaly_score and heuristics.risk_score are available
                    if 'heuristics' in data and isinstance(data['heuristics'], dict) and 'risk_score' in data['heuristics']:
                        # Add anomaly_score if missing for backward compatibility
                        if 'anomaly_score' not in data:
                            data['anomaly_score'] = data['heuristics']['risk_score']
                    elif 'anomaly_score' in data and 'heuristics' not in data:
                        # Create heuristics structure if missing
                        data['heuristics'] = {
                            'risk_score': data['anomaly_score'],
                            'wallet_type': 'unknown',
                            'risk_indicators': data.get('risk_factors', []),
                            'transaction_patterns': []
                        }
                    else:
                        # Default values for missing data
                        if 'anomaly_score' not in data:
                            data['anomaly_score'] = 0
                        if 'heuristics' not in data:
                            data['heuristics'] = {
                                'risk_score': 0,
                                'wallet_type': 'unknown',
                                'risk_indicators': [],
                                'transaction_patterns': []
                            }

                # Generate comprehensive interactive report
                logger.info("Creating enhanced interactive HTML report...")
                interactive_html = interactive_generator.generate_interactive_report(output_file)
                exported_files.append(str(interactive_html))

                # Generate all available report formats
                logger.info("Generating additional report formats...")
                all_reports = interactive_generator.generate_all_reports(output_file)
                for report_type, report_path in all_reports.items():
                    if report_path not in exported_files:
                        exported_files.append(str(report_path))

            except Exception as e:
                logger.error(f"Failed to generate interactive reports: {str(e)}")
                logger.debug(traceback.format_exc())
                # Continue with fallback generation
        else:
            # Fallback to basic transaction story generation
            if FixedTransactionStoryGenerator is not None:
                try:
                    # Create a transaction story generator
                    story_generator = FixedTransactionStoryGenerator(self)

                    # Generate the narrative summary
                    logger.info("Generating transaction story narrative...")
                    narrative_summary = story_generator.generate_narrative_summary()

                    # Generate PDF report
                    logger.info("Creating PDF report with transaction story...")
                    pdf_file = story_generator.generate_pdf_report(narrative_summary, output_file)
                    exported_files.append(str(pdf_file))

                    # Generate HTML report
                    logger.info("Creating HTML report with transaction story...")
                    html_file, weasy_pdf = story_generator.generate_html_report(narrative_summary, output_file)
                    exported_files.append(str(html_file))
                    exported_files.append(str(weasy_pdf))

                except Exception as e:
                    logger.error(f"Failed to generate transaction story: {str(e)}")
                    logger.debug(traceback.format_exc())
            else:
                logger.warning("Report generators are not available. Skipping enhanced report generation.")

        # Print summary of exported files
        for f in exported_files:
            logger.info(f"Exported data to {f}")

        return exported_files

    def generate_transaction_story(self, output_file: str = "tron_analysis") -> List[str]:
        """
        Generate a narrative transaction story based on the analysis results.

        Args:
            output_file: Base name for output files

        Returns:
            List of paths to the generated story files
        """
        if TransactionStoryGenerator is None:
            logger.error("TransactionStoryGenerator is not available. Make sure transaction_story.py is in the same directory.")
            return []

        if not self.addresses_data:
            logger.warning("No data available for transaction story generation")
            return []

        try:
            # Create a transaction story generator
            story_generator = TransactionStoryGenerator(self)

            # Generate the narrative summary
            logger.info("Generating transaction story narrative...")
            narrative_summary = story_generator.generate_narrative_summary()

            # Generate PDF report
            logger.info("Creating PDF report with transaction story...")
            pdf_file = story_generator.generate_pdf_report(narrative_summary, output_file)

            # Generate HTML report
            logger.info("Creating HTML report with transaction story...")
            html_file, weasy_pdf = story_generator.generate_html_report(narrative_summary, output_file)

            report_files = [str(pdf_file), str(html_file), str(weasy_pdf)]

            # Print summary of generated files
            for f in report_files:
                logger.info(f"Generated transaction story report: {f}")

            return report_files

        except Exception as e:
            logger.error(f"Failed to generate transaction story: {str(e)}")
            logger.debug(traceback.format_exc())
            return []

    def _generate_text_report(self, output_file: str) -> None:
        """Generate a detailed text report of the analysis results."""
        with open(output_file, 'w', encoding='utf-8') as f:
            # Header
            f.write("=" * 80 + "\n")
            f.write("TRON WALLET ANALYSIS REPORT\n")
            f.write(f"Generated on: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")

            # Summary statistics
            valid_addresses = sum(1 for data in self.addresses_data.values() if data.get("valid", False))
            active_addresses = sum(1 for data in self.addresses_data.values() if data.get("exists", False))

            f.write("SUMMARY STATISTICS\n")
            f.write("-" * 40 + "\n")
            f.write(f"Total Addresses Analyzed: {len(self.addresses_data)}\n")
            f.write(f"Valid Addresses: {valid_addresses}\n")
            f.write(f"Active Addresses: {active_addresses}\n")
            f.write(f"Connections Found: {len(self.connections)}\n\n")

            # Detailed address analysis
            f.write("DETAILED ADDRESS ANALYSIS\n")
            f.write("-" * 80 + "\n\n")

            for address, data in self.addresses_data.items():
                f.write(f"Address: {address}\n")
                f.write("-" * 60 + "\n")

                if not data.get("valid", False):
                    f.write(f"Status: INVALID - {data.get('error', 'Unknown error')}\n\n")
                    continue

                if not data.get("exists", False):
                    f.write(f"Status: NOT FOUND - {data.get('error', 'Address has no activity')}\n\n")
                    continue

                # Basic info
                account_info = data.get("account_info", {})
                f.write(f"Status: ACTIVE\n")
                f.write(f"Balance: {account_info.get('balance', 0):.6f} TRX\n")
                f.write(f"Transactions: {data.get('transactions_count', 0)}\n")

                # Exchange info
                if account_info.get("is_exchange", False):
                    f.write(f"Exchange: {account_info.get('exchange_name', 'Unknown')}\n")

                # Analysis metrics
                analysis = data.get("analysis", {})
                metrics = analysis.get("metrics", {})
                f.write(f"Sent Volume: {metrics.get('sent_volume', 0):.6f} TRX\n")
                f.write(f"Received Volume: {metrics.get('received_volume', 0):.6f} TRX\n")
                f.write(f"Unique Connections: {metrics.get('unique_connections', 0)}\n")

                # Transaction types
                tx_types = metrics.get("transaction_types", {})
                if tx_types:
                    f.write("Transaction Types:\n")
                    for tx_type, count in tx_types.items():
                        f.write(f"  - {tx_type}: {count}\n")

                # Tokens
                tokens_sent = metrics.get("tokens_sent", {})
                tokens_received = metrics.get("tokens_received", {})
                if tokens_sent or tokens_received:
                    f.write("Token Activity:\n")
                    for token, amount in tokens_sent.items():
                        f.write(f"  - Sent {amount:.6f} {token}\n")
                    for token, amount in tokens_received.items():
                        f.write(f"  - Received {amount:.6f} {token}\n")

                # Exchanges interacted
                exchanges = metrics.get("exchanges_interacted", [])
                if exchanges:
                    f.write(f"Exchanges Interacted: {', '.join(exchanges)}\n")

                # Heuristics analysis
                heuristics = data.get("heuristics", {})
                if heuristics:
                    f.write(f"Wallet Type: {heuristics.get('wallet_type', 'unknown').title()}\n")
                    f.write(f"Risk Score: {heuristics.get('risk_score', 0)}/100\n")

                    risk_indicators = heuristics.get("risk_indicators", [])
                    if risk_indicators:
                        f.write("Risk Indicators:\n")
                        for indicator in risk_indicators:
                            f.write(f"  - {indicator.get('type', 'unknown')}: {indicator.get('details', '')}\n")

                    patterns = heuristics.get("transaction_patterns", [])
                    if patterns:
                        f.write("Transaction Patterns:\n")
                        for pattern in patterns:
                            f.write(f"  - {pattern.get('type', 'unknown')}: {pattern.get('details', '')}\n")

                f.write("\n")

            # Connections summary
            if self.connections:
                f.write("CONNECTION ANALYSIS\n")
                f.write("-" * 80 + "\n\n")
                for conn in self.connections:
                    f.write(f"From: {conn['from_address']}\n")
                    f.write(f"To: {conn['to_address']}\n")
                    f.write(f"TRX Sent: {conn['trx_sent']:.6f}\n")
                    f.write(f"TRX Received: {conn['trx_received']:.6f}\n")
                    f.write(f"Transaction Count: {conn['sent_count'] + conn['received_count']}\n")
                    f.write(f"Strength: {conn['strength']:.2f}\n")
                    f.write("-" * 40 + "\n")

    def _export_json_data(self, filename):
        """Export all analysis data to JSON format."""
        # Convert connections list to proper format
        connections_list = []
        if isinstance(self.connections, list):
            connections_list = self.connections
        elif isinstance(self.connections, dict):
            for key, conn in self.connections.items():
                connections_list.append({
                    "from_address": conn.get("from_address", ""),
                    "to_address": conn.get("to_address", ""),
                    "amount": conn.get("amount", 0),
                    "count": conn.get("count", 1),
                    "strength": conn.get("strength", 0),
                    "types": conn.get("types", {})
                })

        data = {
            "analysis_metadata": {
                "timestamp": datetime.now().isoformat(),
                "analyzer_version": "2.0",
                "total_addresses": len(self.addresses_data),
                "total_connections": len(connections_list),
                "analysis_depth": self.depth,
                "max_transactions_per_address": self.max_transactions
            },
            "addresses": self.addresses_data,
            "connections": connections_list,
            "summary_statistics": self._generate_summary_stats()
        }

        # Ensure directory exists
        Path(filename).parent.mkdir(parents=True, exist_ok=True)

        with open(filename, 'w', encoding='utf-8') as f:
            json.dump(data, f, indent=2, ensure_ascii=False, default=str)

        logger.info(f"JSON data exported to: {filename}")

    def display_summary(self) -> None:
        """Display a summary of the analysis results in the terminal."""
        valid_addresses = sum(1 for data in self.addresses_data.values() if data.get("valid", False))
        active_addresses = sum(1 for data in self.addresses_data.values() if data.get("exists", False))

        # Create summary table
        table = Table(title="TRON Wallet Analysis Summary", box=box.ROUNDED)
        table.add_column("Metric", style="cyan")
        table.add_column("Value", style="green")

        table.add_row("Total Addresses Analyzed", str(len(self.addresses_data)))
        table.add_row("Valid Addresses", str(valid_addresses))
        table.add_row("Active Addresses", str(active_addresses))
        table.add_row("Connections Found", str(len(self.connections)))

        # Add cache statistics if used
        if self.use_cache:
            try:
                cache_files = list(CACHE_DIR.glob("*.json"))
                table.add_row("Cache Files", str(len(cache_files)))
                table.add_row("Cache Size", f"{sum(f.stat().st_size for f in cache_files) / 1024:.2f} KB")
            except Exception:
                pass

        console.print(table)

        # Display wallet type distribution
        wallet_types = {}
        for addr, data in self.addresses_data.items():
            if data.get("exists", False) and "heuristics" in data:
                wallet_type = data["heuristics"].get("wallet_type", "unknown")
                wallet_types[wallet_type] = wallet_types.get(wallet_type, 0) + 1

        if wallet_types:
            type_table = Table(title="Wallet Types Distribution", box=box.ROUNDED)
            type_table.add_column("Type", style="cyan")
            type_table.add_column("Count", style="green")
            type_table.add_column("Percentage", style="yellow")

            total = sum(wallet_types.values())
            for wtype, count in sorted(wallet_types.items(), key=lambda x: x[1], reverse=True):
                type_table.add_row(
                    wtype.capitalize(),
                    str(count),
                    f"{(count/total)*100:.1f}%"
                )

            console.print(type_table)

        # Display transaction type distribution
        tx_types = {}
        for addr, data in self.addresses_data.items():
            if data.get("exists", False) and "analysis" in data:
                if "metrics" in data["analysis"] and "transaction_types" in data["analysis"]["metrics"]:
                    transaction_types = data["analysis"]["metrics"].get("transaction_types", {})
                    for tx_type, count in transaction_types.items():
                        tx_types[tx_type] = tx_types.get(tx_type, 0) + count

        if tx_types:
            tx_table = Table(title="Transaction Types Distribution", box=box.ROUNDED)
            tx_table.add_column("Transaction Type", style="cyan")
            tx_table.add_column("Count", style="green")
            tx_table.add_column("Percentage", style="yellow")

            total_txs = sum(tx_types.values())
            for tx_type, count in sorted(tx_types.items(), key=lambda x: x[1], reverse=True):
                tx_table.add_row(
                    tx_type,
                    str(count),
                    f"{(count/total_txs)*100:.1f}%"
                )

            console.print(tx_table)

        # Display token distribution
        token_info = {}
        for addr, data in self.addresses_data.items():
            if not data.get("exists", False):
                continue

            # From account_info tokens
            tokens = data.get("account_info", {}).get("tokens", {})
            for token_addr, token_data in tokens.items():
                if isinstance(token_data, dict) and "symbol" in token_data:
                    token_symbol = token_data.get("symbol", "???")
                    token_name = token_data.get("name", "Unknown")
                    token_type = token_data.get("type", "Unknown")
                    balance = token_data.get("balance", 0)

                    if token_symbol not in token_info:
                        token_info[token_symbol] = {
                            "name": token_name,
                            "type": token_type,
                            "addresses": [],
                            "total_balance": 0
                        }
                    token_info[token_symbol]["addresses"].append(addr[:8] + "..." + addr[-6:])
                    token_info[token_symbol]["total_balance"] += balance

            # From transaction metrics
            if "analysis" in data and "metrics" in data["analysis"]:
                # Tokens sent
                tokens_sent = data["analysis"]["metrics"].get("tokens_sent", {})
                for token_symbol in tokens_sent.keys():
                    if token_symbol != "TRX" and token_symbol not in token_info:
                        token_info[token_symbol] = {
                            "name": "From Transactions",
                            "type": "Token Transfer",
                            "addresses": [addr[:8] + "..." + addr[-6:]],
                            "total_balance": 0
                        }

                # Tokens received
                tokens_received = data["analysis"]["metrics"].get("tokens_received", {})
                for token_symbol in tokens_received.keys():
                    if token_symbol != "TRX" and token_symbol not in token_info:
                        token_info[token_symbol] = {
                            "name": "From Transactions", 
                            "type": "Token Transfer",
                            "addresses": [addr[:8] + "..." + addr[-6:]],
                            "total_balance": 0
                        }

        if token_info:
            console.print(f"\n[bold cyan]TOKEN ANALYSIS:[/bold cyan]")
            # Group by token type
            token_types = {}
            for symbol, info in token_info.items():
                token_type = info["type"]
                if token_type not in token_types:
                    token_types[token_type] = []
                token_types[token_type].append((symbol, info))

            for token_type, tokens in token_types.items():
                console.print(f"[yellow]{token_type} Tokens:[/yellow]")
                for symbol, info in sorted(tokens, key=lambda x: len(x[1]["addresses"]), reverse=True)[:5]:
                    console.print(f"  • {symbol} ({info['name']}) - {len(info['addresses'])} address(es)")
                    if info["total_balance"] > 0:
                        console.print(f"    Total Balance: {info['total_balance']:,.2f}")

        console.print("\n" + "="*60)

        # If connections were found, show the top connections by strength
        if self.connections:
            connections_df = pd.DataFrame(self.connections)
            top_connections = connections_df.sort_values(by="strength", ascending=False).head(10)

            conn_table = Table(title="Top Connections by Strength", box=box.ROUNDED)
            conn_table.add_column("From", style="cyan")
            conn_table.add_column("To", style="cyan")
            conn_table.add_column("TRX Sent", style="green")
            conn_table.add_column("TRX Received", style="green")
            conn_table.add_column("Strength", style="magenta")

            for _, row in top_connections.iterrows():
                from_addr = row["from_address"]
                to_addr = row["to_address"]

                # Abbreviate addresses for display
                from_abbr = f"{from_addr[:6]}...{from_addr[-4:]}"
                to_abbr = f"{to_addr[:6]}...{to_addr[-4:]}"

                conn_table.add_row(
                    from_abbr,
                    to_abbr,
                    f"{row['trx_sent']:.2f}",
                    f"{row['trx_received']:.2f}",
                    f"{row['strength']:.2f}"
                )

            console.print(conn_table)

        # Show addresses with high risk scores
        high_risk_addresses = []
        for addr, data in self.addresses_data.items():
            if (data.get("exists", False) and "heuristics" in data and 
                data["heuristics"].get("risk_score", 0) >= 50):
                high_risk_addresses.append((
                    addr, 
                    data["heuristics"].get("risk_score", 0),
                    data["heuristics"].get("wallet_type", "unknown")
                ))

        if high_risk_addresses:
            risk_table = Table(title="High Risk Addresses", box=box.ROUNDED)
            risk_table.add_column("Address", style="cyan")
            risk_table.add_column("Risk Score", style="red")
            risk_table.add_column("Wallet Type", style="yellow")
            risk_table.add_column("Indicators", style="magenta")

            for addr, risk_score, wallet_type in sorted(high_risk_addresses, key=lambda x: x[1], reverse=True):
                # Get risk indicators
                indicators = []
                if "heuristics" in self.addresses_data[addr]:
                    indicators = self.addresses_data[addr]["heuristics"].get("risk_indicators", [])

                indicator_str = ", ".join(i.get("type", "unknown") for i in indicators[:3])
                if len(indicators) > 3:
                    indicator_str += f" (+{len(indicators)-3} more)"

                # Abbreviate address
                addr_abbr = f"{addr[:6]}...{addr[-4:]}"

                risk_table.add_row(
                    addr_abbr,
                    f"{risk_score}",
                    wallet_type.capitalize(),
                    indicator_str
                )

            console.print(risk_table)


def load_addresses_from_file(file_path: str) -> List[str]:
    """
    Load TRON addresses from a text file.

    Args:
        file_path: Path to the file containing addresses (one per line)

    Returns:
        List of TRON addresses
    """
    try:
        with open(file_path, 'r') as f:
            # Skip empty lines and comments (lines starting with #)
            addresses = [
                line.strip() for line in f 
                if line.strip() and not line.strip().startswith('#')
            ]

        logger.info(f"Loaded {len(addresses)} addresses from {file_path}")
        return addresses
    except Exception as e:
        logger.error(f"Error loading addresses from file: {str(e)}")
        return []


def main():
    """Main entry point for the script."""
    parser = argparse.ArgumentParser(
        description="Analyze TRON wallet addresses to identify connections.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )

    # Input options
    group = parser.add_mutually_exclusive_group(required=True)
    group.add_argument(
        "-a", "--addresses", 
        nargs="+", 
        help="TRON addresses to analyze"
    )
    group.add_argument(
        "-f", "--file", 
        help="File containing TRON addresses (one per line)"
    )

    # Analysis options
    parser.add_argument(
        "-o", "--output", 
        default="tron_analysis", 
        help="Base name for output files"
    )
    parser.add_argument(
        "-m", "--max-transactions", 
        type=int, 
        default=200, 
        help="Maximum number of transactions to fetch per address"
    )
    parser.add_argument(
        "-d", "--depth", 
        type=int, 
        default=1, 
        help="Depth of connection analysis (1 = direct connections only)"
    )
    parser.add_argument(
        "-w", "--min-weight", 
        type=float, 
        default=0.01, 
        help="Minimum transaction value (in TRX) to consider as a connection"
    )

    # Cache options
    parser.add_argument(
        "--no-cache", 
        action="store_true", 
        help="Disable caching of API results"
    )
    parser.add_argument(
        "--cache-ttl", 
        type=int, 
        default=3600, 
        help="Cache time-to-live in seconds"
    )
    parser.add_argument(
        "--clear-cache", 
        action="store_true", 
        help="Clear cache before running analysis"
    )

    # Export options
    parser.add_argument(
        "--format", 
        choices=["csv", "json", "all"], 
        default="csv", 
        help="Export format for results"
    )

    # Visualization options
    parser.add_argument(
        "--visualize", 
        action="store_true",
        help="Generate interactive network visualization of wallet connections"
    )

    # Transaction story options
    parser.add_argument(
        "--story",
        action="store_true",
        help="Generate narrative transaction story report (PDF and HTML)"
    )

    # Debug options
    parser.add_argument(
        "--debug", 
        action="store_true", 
        help="Enable debug logging"
    )
    parser.add_argument(
        "--quiet", 
        action="store_true", 
        help="Suppress non-essential output"
    )

    args = parser.parse_args()

    # Configure logging level
    if args.debug:
        logger.setLevel(logging.DEBUG)
    elif args.quiet:
        logger.setLevel(logging.WARNING)

    # Clear cache if requested
    if args.clear_cache:
        try:
            for cache_file in CACHE_DIR.glob("*.json"):
                cache_file.unlink()
            logger.info(f"Cache cleared ({CACHE_DIR})")
        except Exception as e:
            logger.error(f"Error clearing cache: {str(e)}")

    # Load addresses
    addresses = []
    if args.addresses:
        addresses = args.addresses
    elif args.file:
        addresses = load_addresses_from_file(args.file)

    if not addresses:
        logger.error("No valid addresses provided. Exiting.")
        return 1

    # Display initial information
    console.print(Panel(
        f"[bold green]TRON Wallet Analyzer[/bold green]\n" +
        f"Analyzing {len(addresses)} TRON addresses with maximum {args.max_transactions} transactions each",
        title="Analysis Starting",
        border_style="green"
    ))

    # Create and run the analyzer
    api_key = os.getenv("TRONGRID_API_KEY", "")
    analyzer = TronWalletAnalyzer(
        api_key=api_key,
        max_transactions=args.max_transactions,
        depth=args.depth,
        min_connection_weight=args.min_weight,
        use_cache=not args.no_cache,
        cache_ttl=args.cache_ttl
    )

    try:
        # Start timing the analysis
        start_time = time.time()

        # Analyze the addresses
        analyzer.analyze_addresses(addresses)

        # Calculate elapsed time
        elapsed_time = time.time() - start_time

        # Display analysis results
        analyzer.display_summary()

        # Export results in the requested format
        exported_files = analyzer.export_to_csv(args.output, format_type=args.format)

        # Generate network visualization if requested
        if args.visualize and analyzer.connections:
            viz_file = analyzer.create_network_visualization(args.output)
            if viz_file:
                exported_files.append(viz_file)
                console.print(f"[bold cyan]Network visualization created:[/bold cyan] {viz_file}")
                console.print("[bold yellow]The visualization will open in your browser if available.[/bold yellow]")

        # Generate transaction story if requested
        if args.story:
            console.print("[bold cyan]Generating transaction story reports...[/bold cyan]")
            story_files = analyzer.generate_transaction_story(args.output)
            if story_files:
                exported_files.extend(story_files)
                console.print(f"[bold green]Transaction story reports created: {len(story_files)} files[/bold green]")
                for f in story_files:
                    console.print(f"  - [cyan]{f}[/cyan]")
            else:
                console.print("[bold red]Failed to generate transaction story reports.[/bold red]")

        # Print completion message with timing information
        console.print(Panel(
            f"[bold green]Analysis completed successfully![/bold green]\n" +
            f"Time taken: {elapsed_time:.2f} seconds\n" +
            f"Files created: {len(exported_files)}",
            title="Analysis Complete",
            border_style="green"
        ))

    except KeyboardInterrupt:
        console.print("\n[bold red]Analysis interrupted by user.[/bold red]")
        return 1
    except Exception as e:
        console.print(Panel(
            f"[bold red]Error during analysis:[/bold red] {str(e)}",
            title="Error",
            border_style="red"
        ))
        if args.debug:
            console.print_exception()
        return 1

    return 0


if __name__ == "__main__":
    sys.exit(main())

def export_to_csv(self, output_file: str = "tron_network_analysis", format_type: str = "basic") -> List[str]:
        """
        Export analysis results to various formats.

        Args:
            output_file: Base name for output files
            format_type: Type of export ("basic", "detailed", "all")

        Returns:
            List of generated file paths
        """
        if not self.addresses_data:
            logger.warning("No data to export. Run analysis first.")
            return []

        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        exported_files = []

        # Create results directory
        results_dir = Path("results/reports")
        results_dir.mkdir(parents=True, exist_ok=True)

        try:
            # Generate text report
            report_file = results_dir / f"{output_file}_{timestamp}.txt"
            self.generate_text_report(str(report_file))
            exported_files.append(str(report_file))

            # Generate JSON export
            json_file = results_dir / f"{output_file}_data_{timestamp}.json"
            self.export_to_json(str(json_file))
            exported_files.append(str(json_file))

            # Generate Excel report if format is detailed or all
            if format_type in ("detailed", "all"):
                excel_file = results_dir / f"{output_file}_{timestamp}.xlsx"
                self.generate_excel_report(str(excel_file))
                exported_files.append(str(excel_file))

            # Generate network visualization
            viz_file = self.create_network_visualization(f"{output_file}_{timestamp}")
            if viz_file:
                exported_files.append(viz_file)

            # Generate comprehensive report for "all" format
            if format_type == "all" and ComprehensiveReportGenerator:
                try:
                    comp_generator = ComprehensiveReportGenerator(self)
                    comp_file = comp_generator.generate_comprehensive_report(f"{output_file}_{timestamp}")
                    if comp_file:
                        exported_files.append(comp_file)
                except Exception as e:
                    logger.warning(f"Could not generate comprehensive report: {str(e)}")

            logger.info(f"Analysis exported to {len(exported_files)} files")
            for file_path in exported_files:
                logger.info(f"  - {file_path}")

            return exported_files

        except Exception as e:
            logger.error(f"Error exporting data: {str(e)}")
            return []

def export_to_json(self, filename: str = "tron_analysis_data.json") -> None:
        """
        Export analysis data to JSON format.

        Args:
            filename: Output JSON filename
        """
        try:
            # Prepare data for JSON export
            export_data = {
                "metadata": {
                    "generated_at": datetime.now().isoformat(),
                    "analyzer": "TRON Wallet Analyzer",
                    "version": "1.0",
                    "total_addresses": len(self.addresses_data),
                    "total_connections": len(self.connections)
                },
                "addresses": {},
                "connections": self.connections,
                "statistics": self.stats
            }

            # Process addresses data
            for address, data in self.addresses_data.items():
                if data.get("valid", False):
                    export_data["addresses"][address] = {
                        "address": address,
                        "exists": data.get("exists", False),
                        "balance": data.get("account_info", {}).get("balance", 0),
                        "transactions_count": data.get("transactions_count", 0),
                        "wallet_type": data.get("heuristics", {}).get("wallet_type", "unknown"),
                        "risk_score": data.get("heuristics", {}).get("risk_score", 0),
                        "is_exchange": data.get("account_info", {}).get("is_exchange", False),
                        "exchange_name": data.get("account_info", {}).get("exchange_name", ""),
                        "is_malicious": data.get("is_malicious", False),
                        "tokens": data.get("account_info", {}).get("tokens", {}),
                        "analysis": data.get("analysis", {}),
                        "heuristics": data.get("heuristics", {})
                    }

            # Save to file
            with open(filename, 'w', encoding='utf-8') as f:
                json.dump(export_data, f, indent=2, ensure_ascii=False, default=str)

            console.print(f"[green]JSON data exported to {filename}[/green]")

        except Exception as e:
            logger.error(f"Error exporting to JSON: {str(e)}")
            console.print(f"[red]Failed to export JSON: {str(e)}[/red]")