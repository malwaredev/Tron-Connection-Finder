#!/usr/bin/env python3
"""
TRON Master Analyzer

A comprehensive analysis platform that integrates all enhanced features:
- Advanced wallet analysis with multi-API support
- ML-based anomaly detection
- Smart contract and multi-signature analysis
- Enhanced token classification
- Malicious address detection
- Transaction hash tracking
- Interactive visualization
"""

import os
import sys
import asyncio
import time
import argparse
from datetime import datetime
from pathlib import Path
from typing import List, Dict, Any, Tuple, Optional

# Import all the enhanced modules
from advanced_tron_analyzer import AdvancedTronAnalyzer, read_addresses_from_file
from ml_anomaly_detection import AnomalyDetector
from smart_contract_analyzer import SmartContractAnalyzer
# Import transaction_story only when needed to avoid dependency issues
try:
    from fixed_transaction_story import FixedTransactionStoryGenerator
    STORY_GENERATOR_AVAILABLE = True
except ImportError:
    FixedTransactionStoryGenerator = None
    STORY_GENERATOR_AVAILABLE = False

# Import interactive report generator
try:
    from interactive_story_report import InteractiveStoryReportGenerator
    INTERACTIVE_REPORT_AVAILABLE = True
except ImportError:
    InteractiveStoryReportGenerator = None
    INTERACTIVE_REPORT_AVAILABLE = False

# Optional imports - these databases enhance the analysis but aren't required
try:
    from malicious_addresses_database import MALICIOUS_ADDRESSES, get_address_information
    MALICIOUS_DB_AVAILABLE = True
except ImportError:
    MALICIOUS_ADDRESSES = {}
    MALICIOUS_DB_AVAILABLE = False
    def get_address_information(address): return None

try:
    from token_classification_database import KNOWN_TOKENS, get_token_info
    TOKEN_DB_AVAILABLE = True
except ImportError:
    KNOWN_TOKENS = {}
    TOKEN_DB_AVAILABLE = False
    def get_token_info(token_address): return None

try:
    from exchanges_database import (
        get_exchange_info, 
        is_exchange_address, 
        is_defi_address,
        get_all_exchanges
    )
    EXCHANGES_DB_AVAILABLE = True
except ImportError:
    EXCHANGES_DB_AVAILABLE = False
    def get_exchange_info(address): return None
    def is_exchange_address(address): return False
    def is_defi_address(address): return False
    def get_all_exchanges(): return {}

# Set up console for pretty output
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
from rich import box
from rich.progress import Progress, TextColumn, BarColumn, SpinnerColumn

console = Console()

class TronMasterAnalyzer:
    """Master analyzer integrating all enhanced TRON analysis capabilities."""
    
    def __init__(self, 
                 trongrid_api_key=None, 
                 tronscan_api_key=None, 
                 max_transactions=100,
                 max_depth=2,
                 use_cache=True,
                 checkpoint_interval=5,
                 anomaly_sensitivity=1.0):
        """
        Initialize the master analyzer with all enhanced modules.
        
        Args:
            trongrid_api_key: API key for TronGrid
            tronscan_api_key: API key for Tronscan
            max_transactions: Maximum transactions to fetch per address
            max_depth: Maximum depth for connection analysis
            use_cache: Whether to use caching for API results
            checkpoint_interval: Save checkpoint after processing this many addresses
            anomaly_sensitivity: Sensitivity multiplier for anomaly detection
        """
        # Get API keys from environment if not provided
        self.trongrid_api_key = trongrid_api_key or os.getenv("TRONGRID_API_KEY", "")
        self.tronscan_api_key = tronscan_api_key or os.getenv("TRONSCAN_API_KEY", "")
        
        # Initialize the core analyzer
        self.core_analyzer = AdvancedTronAnalyzer(
            trongrid_api_key=self.trongrid_api_key,
            tronscan_api_key=self.tronscan_api_key,
            max_transactions=max_transactions,
            depth=max_depth,
            use_cache=use_cache,
            checkpoint_interval=checkpoint_interval
        )
        
        # Initialize the ML-based anomaly detector
        self.anomaly_detector = AnomalyDetector(sensitivity=anomaly_sensitivity)
        
        # Initialize the smart contract analyzer
        self.contract_analyzer = SmartContractAnalyzer(
            trongrid_api_key=self.trongrid_api_key,
            tronscan_api_key=self.tronscan_api_key
        )
        
        # Create transaction story generator
        self.story_generator = None  # Will be initialized after analysis
        
        # Storage for analysis results
        self.analysis_results = {}
        self.contract_analysis = {}
        self.ml_analysis = {}
        
        # Print module availability
        self._print_module_status()
    
    def _print_module_status(self):
        """Print the status of available enhancement modules."""
        table = Table(title="TRON Master Analyzer Modules")
        table.add_column("Module", style="cyan")
        table.add_column("Status", justify="center")
        table.add_column("Description")
        
        # Core modules
        table.add_row(
            "Core Analyzer", 
            "[green]✓ Active[/green]", 
            "Basic wallet and transaction analysis"
        )
        
        # API availability
        trongrid_status = "[green]✓ Available[/green]" if self.trongrid_api_key else "[yellow]⚠️ Missing[/yellow]"
        tronscan_status = "[green]✓ Available[/green]" if self.tronscan_api_key else "[yellow]⚠️ Missing[/yellow]"
        
        table.add_row(
            "TronGrid API", 
            trongrid_status, 
            "Primary API for TRON blockchain data"
        )
        
        table.add_row(
            "Tronscan API", 
            tronscan_status, 
            "Alternative API for TRON blockchain data"
        )
        
        # Enhanced modules
        table.add_row(
            "ML Anomaly Detection", 
            "[green]✓ Active[/green]", 
            "Machine learning based suspicious activity detection"
        )
        
        table.add_row(
            "Smart Contract Analysis", 
            "[green]✓ Active[/green]", 
            "Smart contract and multi-signature transaction analysis"
        )
        
        # Optional databases
        malicious_db_status = "[green]✓ Available[/green]" if MALICIOUS_DB_AVAILABLE else "[yellow]⚠️ Missing[/yellow]"
        token_db_status = "[green]✓ Available[/green]" if TOKEN_DB_AVAILABLE else "[yellow]⚠️ Missing[/yellow]"
        
        table.add_row(
            "Malicious Address Database", 
            malicious_db_status, 
            f"{'Enhanced' if MALICIOUS_DB_AVAILABLE else 'Basic'} detection of malicious addresses"
        )
        
        table.add_row(
            "Token Classification Database", 
            token_db_status, 
            f"{'Enhanced' if TOKEN_DB_AVAILABLE else 'Basic'} token identification"
        )
        
        # Exchange database status
        exchange_db_status = "[green]✓ Available[/green]" if EXCHANGES_DB_AVAILABLE else "[yellow]⚠️ Missing[/yellow]"
        table.add_row(
            "Exchange Database", 
            exchange_db_status, 
            f"{'Enhanced' if EXCHANGES_DB_AVAILABLE else 'Basic'} exchange identification"
        )
        
        console.print(table)
    
    async def analyze_address_async(self, address: str) -> Dict[str, Any]:
        """
        Perform comprehensive analysis on a single address.
        
        Args:
            address: TRON address to analyze
            
        Returns:
            Dictionary with comprehensive analysis results
        """
        # Basic validation
        if not self.core_analyzer.validate_tron_address(address):
            return {
                "address": address,
                "valid": False,
                "error": "Invalid TRON address format"
            }
        
        with console.status(f"[cyan]Analyzing address {address}...[/cyan]"):
            # Get account information
            async with aiohttp.ClientSession() as session:
                account_info = await self.core_analyzer.fetch_account_info_async(session, address)
                
                if not account_info.get("exists", False):
                    return {
                        "address": address,
                        "valid": True,
                        "exists": False,
                        "error": "Address not found on blockchain"
                    }
                
                # Fetch transactions
                transactions = await self.core_analyzer.fetch_transactions_async(session, address)
            
            # Process transactions with core analyzer
            processed_data = self.core_analyzer.process_transactions(address, transactions)
            
            # ML-based anomaly detection
            ml_profile = self.anomaly_detector.build_address_profile(address, transactions)
            anomaly_score, risk_factors = self.anomaly_detector.calculate_anomaly_score(address, ml_profile)
            
            # Check for smart contract interactions
            contract_interactions = []
            contract_addresses = set()
            for tx in transactions:
                if tx.get("source") == "trongrid":
                    if tx.get("type") == "trx" and "raw_data" in tx:
                        raw_data = tx["raw_data"]
                        if "contract" in raw_data and raw_data["contract"]:
                            contract = raw_data["contract"][0]
                            if contract.get("type") == "TriggerSmartContract":
                                if "parameter" in contract and "value" in contract["parameter"]:
                                    value = contract["parameter"]["value"]
                                    if "contract_address" in value:
                                        contract_addresses.add(value["contract_address"])
                                        contract_interactions.append({
                                            "tx_hash": tx.get("txID", ""),
                                            "contract_address": value["contract_address"],
                                            "timestamp": raw_data.get("timestamp", 0)
                                        })
                
                elif tx.get("source") == "tronscan":
                    if tx.get("contractType") == "TriggerSmartContract":
                        if "contractData" in tx and "contract_address" in tx["contractData"]:
                            contract_addresses.add(tx["contractData"]["contract_address"])
                            contract_interactions.append({
                                "tx_hash": tx.get("hash", ""),
                                "contract_address": tx["contractData"]["contract_address"],
                                "timestamp": tx.get("timestamp", 0)
                            })
            
            # Enhanced token detection
            tokens = []
            for token_info in account_info.get("tokens", []):
                token_address = token_info.get("contract", "")
                if token_address and TOKEN_DB_AVAILABLE:
                    enhanced_info = get_token_info(token_address)
                    if enhanced_info:
                        tokens.append({
                            **token_info,
                            "name": enhanced_info.get("name", token_info.get("name", "Unknown")),
                            "symbol": enhanced_info.get("symbol", token_info.get("symbol", "???")),
                            "type": enhanced_info.get("type", "Unknown"),
                            "category": enhanced_info.get("category", "Unknown"),
                            "website": enhanced_info.get("website", ""),
                            "description": enhanced_info.get("description", "")
                        })
                    else:
                        tokens.append(token_info)
                else:
                    tokens.append(token_info)
            
            # Enhanced malicious address detection
            is_malicious = False
            malicious_info = {}
            
            if MALICIOUS_DB_AVAILABLE:
                malicious_info = get_address_information(address)
                if malicious_info:
                    is_malicious = True
            
            # Compile comprehensive result
            result = {
                "address": address,
                "valid": True,
                "exists": True,
                "balance": account_info.get("balance", 0),
                "api_source": account_info.get("api_source", "unknown"),
                "transactions_count": len(transactions),
                "tokens": tokens,
                
                # Basic analysis
                "connections": processed_data.get("connections", {}),
                "transaction_types": processed_data.get("transaction_types", {}),
                "transaction_hashes": processed_data.get("transaction_hashes", []),
                
                # ML analysis
                "ml_profile": ml_profile,
                "anomaly_score": anomaly_score,
                "risk_factors": risk_factors,
                
                # Smart contract analysis
                "contract_interactions": contract_interactions,
                "contract_addresses": list(contract_addresses),
                
                # Enhanced detection
                "is_exchange": account_info.get("is_exchange", False),
                "exchange_name": account_info.get("exchange_name", ""),
                "is_malicious": is_malicious,
                "malicious_info": malicious_info
            }
            
            # Determine wallet type
            wallet_type, type_details = self.core_analyzer.detect_wallet_type(result)
            result["wallet_type"] = wallet_type
            result["wallet_details"] = type_details
            
            # Store in instance
            self.analysis_results[address] = result
            
            return result
    
    async def analyze_addresses_async(self, addresses: List[str]) -> Dict[str, Any]:
        """
        Perform comprehensive analysis on multiple addresses.
        
        Args:
            addresses: List of TRON addresses to analyze
            
        Returns:
            Dictionary with comprehensive analysis results
        """
        # Validate addresses
        valid_addresses = []
        for addr in addresses:
            if self.core_analyzer.validate_tron_address(addr):
                valid_addresses.append(addr)
            else:
                console.print(f"[yellow]Invalid address format: {addr}[/yellow]")
        
        if not valid_addresses:
            console.print("[red]No valid addresses to analyze.[/red]")
            return {
                "success": False,
                "error": "No valid addresses provided"
            }
        
        # Use the core analyzer for basic analysis
        console.print(f"[green]Starting analysis of {len(valid_addresses)} addresses...[/green]")
        start_time = time.time()
        
        success = await self.core_analyzer.analyze_addresses_async(valid_addresses)
        
        if not success:
            return {
                "success": False,
                "error": "Core analysis failed"
            }
        
        # Get the results from core analyzer
        console.print("[cyan]Running ML-based anomaly detection...[/cyan]")
        addresses_data = self.core_analyzer.addresses_data
        connections = self.core_analyzer.connections
        transactions = self.core_analyzer.transactions
        
        # Collect all transactions for ML analysis
        all_transactions = []
        for address, data in addresses_data.items():
            # Try to get transactions from the core analyzer
            for tx_hash in data.get("transaction_hashes", []):
                if tx_hash in transactions:
                    all_transactions.append(transactions[tx_hash])
        
        # Run ML analysis
        ml_analysis = self.anomaly_detector.detect_anomalies(all_transactions, list(addresses_data.keys()))
        self.ml_analysis = ml_analysis
        
        # Analyze smart contracts if any
        contract_addresses = set()
        for address, data in addresses_data.items():
            for connection in data.get("connections", {}).values():
                # Check if the connection involves a contract interaction
                if connection.get("types", {}).get("TriggerSmartContract", 0) > 0:
                    from_addr = connection.get("from_address")
                    to_addr = connection.get("to_address")
                    # One of these is a contract address
                    contract_addresses.add(from_addr)
                    contract_addresses.add(to_addr)
        
        # Analyze contracts
        console.print("[cyan]Analyzing smart contracts...[/cyan]")
        contract_analysis = {}
        
        for contract_addr in contract_addresses:
            if contract_addr in addresses_data:
                # Run contract analysis
                contract_info = await self.contract_analyzer.analyze_contract_transactions(contract_addr, 10)
                if contract_info.get("found", False):
                    contract_analysis[contract_addr] = contract_info
        
        self.contract_analysis = contract_analysis
        
        # Update the results with the enhanced analysis
        for address, data in addresses_data.items():
            # Add ML analysis
            address_ml = ml_analysis.get("anomaly_scores", {}).get(address, {"score": 0, "risk_factors": []})
            data["anomaly_score"] = address_ml["score"]
            data["risk_factors"] = address_ml["risk_factors"]
            
            # Add enhanced malicious detection
            if MALICIOUS_DB_AVAILABLE:
                malicious_info = get_address_information(address)
                if malicious_info:
                    data["is_malicious"] = True
                    data["malicious_info"] = malicious_info
            
            # Add contract analysis
            if address in contract_analysis:
                data["contract_analysis"] = contract_analysis[address]
        
        # Generate transaction story if available
        if STORY_GENERATOR_AVAILABLE:
            self.story_generator = FixedTransactionStoryGenerator(self.core_analyzer)
        else:
            self.story_generator = None
        
        # Create enhanced visualization
        console.print("[cyan]Creating enhanced network visualization...[/cyan]")
        viz_file = self.core_analyzer.create_network_visualization("master_analysis")
        
        # Generate reports
        console.print("[cyan]Generating comprehensive reports...[/cyan]")
        report_result = self.core_analyzer.generate_detailed_report("master_analysis")
        
        # Handle different return formats
        if isinstance(report_result, tuple) and len(report_result) >= 2:
            excel_file, text_file = report_result[0], report_result[1]
        elif isinstance(report_result, (list, tuple)) and len(report_result) == 1:
            excel_file = report_result[0]
            text_file = None
        else:
            excel_file = report_result
            text_file = None
        
        # Generate a narrative summary if transaction story generator is available
        narrative_summary = None
        html_report = None
        pdf_report = None
        
        if self.story_generator:
            try:
                console.print("[cyan]Generating narrative transaction stories...[/cyan]")
                narrative_summary = self.story_generator.generate_narrative_summary()
                html_report = self.story_generator.generate_html_report(narrative_summary, "master_analysis")
                pdf_report = self.story_generator.generate_pdf_report(narrative_summary, "master_analysis")
            except Exception as e:
                console.print(f"[yellow]Warning: Story generation failed: {str(e)}[/yellow]")
                html_report = None
                pdf_report = None
        
        # Generate interactive report if available
        interactive_report = None
        if INTERACTIVE_REPORT_AVAILABLE:
            try:
                console.print("[cyan]Generating interactive HTML report...[/cyan]")
                interactive_generator = InteractiveStoryReportGenerator(self.core_analyzer, self.story_generator)
                interactive_report = interactive_generator.generate_interactive_report("master_analysis")
            except Exception as e:
                console.print(f"[yellow]Warning: Interactive report generation failed: {str(e)}[/yellow]")
        
        # Return the complete analysis result
        runtime = time.time() - start_time
        
        return {
            "success": True,
            "runtime": runtime,
            "addresses_analyzed": len(addresses_data),
            "connections_found": len(connections),
            "transactions_processed": len(transactions),
            "visualization_file": viz_file,
            "excel_report": excel_file,
            "text_report": text_file if text_file else "No text report generated",
            "narrative_html": html_report,
            "narrative_pdf": pdf_report,
            "interactive_report": interactive_report,
            "high_risk_addresses": ml_analysis.get("risk_categories", {}).get("high_risk", []),
            "suspicious_patterns": ml_analysis.get("suspected_layering", [])
        }
    
    def analyze_addresses(self, addresses: List[str]) -> Dict[str, Any]:
        """
        Analyze TRON addresses (synchronous wrapper for async function).
        
        Args:
            addresses: List of TRON addresses to analyze
            
        Returns:
            Dictionary with analysis results
        """
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(self.analyze_addresses_async(addresses))
    
    def analyze_address(self, address: str) -> Dict[str, Any]:
        """
        Analyze a single TRON address (synchronous wrapper for async function).
        
        Args:
            address: TRON address to analyze
            
        Returns:
            Dictionary with analysis results
        """
        loop = asyncio.get_event_loop()
        return loop.run_until_complete(self.analyze_address_async(address))
    
    def get_transaction_stories(self) -> Dict[str, str]:
        """
        Get narrative stories about the analyzed transactions.
        
        Returns:
            Dictionary with narrative text sections
        """
        if not self.story_generator:
            return {"error": "Analysis not run or story generator not initialized"}
        
        return self.story_generator.generate_narrative_summary()
    
    def generate_risk_report(self) -> str:
        """
        Generate a specialized report focusing on high-risk activities.
        
        Returns:
            Path to the generated risk report
        """
        if not self.ml_analysis:
            return "ML analysis not available"
        
        # Get high risk addresses
        high_risk = self.ml_analysis.get("risk_categories", {}).get("high_risk", [])
        
        if not high_risk:
            console.print("[yellow]No high-risk addresses found in the analysis.[/yellow]")
            return None
        
        # Generate timestamp for the filename
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"results/reports/risk_report_{timestamp}.txt"
        
        with open(filename, 'w') as f:
            f.write("=" * 80 + "\n")
            f.write(f"TRON NETWORK RISK ANALYSIS REPORT - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
            f.write("=" * 80 + "\n\n")
            
            f.write(f"HIGH RISK ADDRESSES: {len(high_risk)}\n")
            f.write("-" * 80 + "\n\n")
            
            # Write details for each high risk address
            for address in high_risk:
                anomaly_score = self.ml_analysis.get("anomaly_scores", {}).get(address, {}).get("score", 0)
                risk_factors = self.ml_analysis.get("anomaly_scores", {}).get(address, {}).get("risk_factors", [])
                
                address_data = self.core_analyzer.addresses_data.get(address, {})
                wallet_type = address_data.get("wallet_type", "Unknown")
                wallet_details = address_data.get("wallet_details", "")
                balance = address_data.get("balance", 0)
                
                f.write(f"Address: {address}\n")
                f.write(f"  Risk Score: {anomaly_score}/100\n")
                f.write(f"  Wallet Type: {wallet_type} ({wallet_details})\n")
                f.write(f"  Balance: {balance:.2f} TRX\n")
                
                if risk_factors:
                    f.write("  Risk Factors:\n")
                    for factor in risk_factors:
                        f.write(f"    - {factor}\n")
                
                # Add malicious address info if available
                if MALICIOUS_DB_AVAILABLE:
                    malicious_info = get_address_information(address)
                    if malicious_info:
                        f.write("  [MALICIOUS ADDRESS DETECTED]\n")
                        f.write(f"    Type: {malicious_info.get('type', 'Unknown')}\n")
                        f.write(f"    Confidence: {malicious_info.get('confidence', 0)*100:.1f}%\n")
                        f.write(f"    Description: {malicious_info.get('description', '')}\n")
                        if "reference" in malicious_info:
                            f.write(f"    Reference: {malicious_info.get('reference', '')}\n")
                
                # Add contract interactions if any
                if "contract_analysis" in address_data:
                    contract_info = address_data["contract_analysis"]
                    f.write("  [SMART CONTRACT DETAILS]\n")
                    f.write(f"    Contract Type: {contract_info.get('contract_type', 'Unknown')}\n")
                    f.write(f"    Transaction Count: {contract_info.get('transaction_count', 0)}\n")
                    
                    # Most used functions
                    most_used = contract_info.get("most_used_functions", [])
                    if most_used:
                        f.write("    Most Used Functions:\n")
                        for func, count in most_used:
                            f.write(f"      - {func}: {count} calls\n")
                
                f.write("\n" + "-" * 80 + "\n\n")
            
            # Write information about suspicious patterns
            suspected_layering = self.ml_analysis.get("suspected_layering", [])
            if suspected_layering:
                f.write("\nSUSPICIOUS TRANSACTION PATTERNS\n")
                f.write("-" * 80 + "\n\n")
                f.write(f"Detected {len(suspected_layering)} potential layering patterns.\n\n")
                
                for i, path in enumerate(suspected_layering[:5]):  # Show top 5
                    f.write(f"Pattern {i+1}:\n")
                    f.write(f"  Path Length: {len(path)} hops\n")
                    f.write(f"  Addresses: {' -> '.join(path)}\n\n")
            
            # Write information about central addresses
            central_addresses = self.ml_analysis.get("central_addresses", [])
            if central_addresses:
                f.write("\nCENTRAL HUB ADDRESSES\n")
                f.write("-" * 80 + "\n\n")
                f.write("These addresses play a central role in the analyzed transaction network:\n\n")
                
                for addr, centrality in central_addresses:
                    wallet_type = self.core_analyzer.addresses_data.get(addr, {}).get("wallet_type", "Unknown")
                    f.write(f"Address: {addr}\n")
                    f.write(f"  Centrality Score: {centrality:.2f}\n")
                    f.write(f"  Wallet Type: {wallet_type}\n")
                    
                    if MALICIOUS_DB_AVAILABLE and get_address_information(addr):
                        f.write("  [WARNING] This central address is flagged as potentially malicious.\n")
                    
                    f.write("\n")
        
        console.print(f"[green]Risk report generated: {filename}[/green]")
        return filename

def main():
    """Run the TRON Master Analyzer."""
    parser = argparse.ArgumentParser(description="TRON Master Analyzer")
    
    parser.add_argument(
        "-f", "--file", 
        type=str, 
        help="File containing TRON addresses to analyze"
    )
    
    parser.add_argument(
        "-a", "--addresses", 
        nargs="+", 
        help="List of TRON addresses to analyze"
    )
    
    parser.add_argument(
        "-t", "--transactions", 
        type=int, 
        default=50, 
        help="Maximum transactions to fetch per address (default: 50)"
    )
    
    parser.add_argument(
        "-d", "--depth", 
        type=int, 
        default=2, 
        help="Connection analysis depth (default: 2)"
    )
    
    parser.add_argument(
        "--no-cache", 
        action="store_true", 
        help="Disable caching of API responses"
    )
    
    parser.add_argument(
        "--clear-cache", 
        action="store_true", 
        help="Clear the cache before running"
    )
    
    parser.add_argument(
        "-s", "--sensitivity",
        type=float,
        default=1.0,
        help="Sensitivity for anomaly detection (default: 1.0)"
    )
    
    parser.add_argument(
        "-r", "--risk-report",
        action="store_true",
        help="Generate specialized risk report"
    )
    
    parser.add_argument(
        "--trongrid-key",
        type=str,
        help="TronGrid API key (overrides environment variable)"
    )
    
    parser.add_argument(
        "--tronscan-key",
        type=str,
        help="Tronscan API key (overrides environment variable)"
    )
    
    parser.add_argument(
        "--api-keys-file",
        type=str,
        help="Path to file containing API keys (one per line: TRONGRID_API_KEY=key\\nTRONSCAN_API_KEY=key)"
    )
    
    parser.add_argument(
        "--comprehensive-report",
        action="store_true",
        help="Generate a comprehensive single-file report in both HTML and PDF formats"
    )
    
    args = parser.parse_args()
    
    # Get API keys from all possible sources
    trongrid_api_key = ""
    tronscan_api_key = ""
    
    # 1. First check environment variables
    trongrid_api_key = os.environ.get("TRONGRID_API_KEY", "")
    tronscan_api_key = os.environ.get("TRONSCAN_API_KEY", "")
    
    # 2. Check if keys are provided in a file
    if args.api_keys_file:
        try:
            with open(args.api_keys_file, 'r') as f:
                for line in f:
                    line = line.strip()
                    if line.startswith("TRONGRID_API_KEY="):
                        trongrid_api_key = line.split("=", 1)[1]
                    elif line.startswith("TRONSCAN_API_KEY="):
                        tronscan_api_key = line.split("=", 1)[1]
            console.print(f"[green]Loaded API keys from {args.api_keys_file}[/green]")
        except Exception as e:
            console.print(f"[yellow]Error loading API keys from file: {str(e)}[/yellow]")
    
    # 3. Command line arguments override everything
    if args.trongrid_key:
        trongrid_api_key = args.trongrid_key
    
    if args.tronscan_key:
        tronscan_api_key = args.tronscan_key
    
    # Initialize the analyzer
    analyzer = TronMasterAnalyzer(
        trongrid_api_key=trongrid_api_key,
        tronscan_api_key=tronscan_api_key,
        max_transactions=args.transactions,
        max_depth=args.depth,
        use_cache=not args.no_cache,
        anomaly_sensitivity=args.sensitivity
    )
    
    # Clear cache if requested
    if args.clear_cache:
        analyzer.core_analyzer.clear_cache()
    
    # Get addresses to analyze
    addresses = []
    
    if args.file:
        file_addresses = read_addresses_from_file(args.file)
        if file_addresses:
            addresses.extend(file_addresses)
    
    if args.addresses:
        for addr in args.addresses:
            if addr not in addresses:
                addresses.append(addr)
    
    # If no addresses specified, try standard files
    if not addresses:
        # Try additional_addresses.txt
        additional_addresses = read_addresses_from_file("additional_addresses.txt")
        if additional_addresses:
            addresses.extend(additional_addresses)
        
        # Try TRX.txt
        trx_addresses = read_addresses_from_file("TRX.txt")
        if trx_addresses:
            addresses.extend([addr for addr in trx_addresses if addr not in addresses])
        
        # Try sample_addresses.txt
        sample_addresses = read_addresses_from_file("sample_addresses.txt")
        if sample_addresses:
            addresses.extend([addr for addr in sample_addresses if addr not in addresses])
    
    if not addresses:
        console.print("[red]No addresses found to analyze. Please provide addresses.[/red]")
        return
    
    # Run the analysis
    result = analyzer.analyze_addresses(addresses)
    
    if result["success"]:
        console.print(Panel(
            f"[green]Analysis complete![/green]\n\n"
            f"[cyan]Addresses analyzed:[/cyan] {result['addresses_analyzed']}\n"
            f"[cyan]Connections found:[/cyan] {result['connections_found']}\n"
            f"[cyan]Transactions processed:[/cyan] {result['transactions_processed']}\n"
            f"[cyan]Runtime:[/cyan] {result['runtime']:.2f} seconds\n\n"
            f"[cyan]Visualization:[/cyan] {result['visualization_file']}\n"
            f"[cyan]Excel Report:[/cyan] {result['excel_report']}\n"
            f"[cyan]Text Report:[/cyan] {result['text_report']}"
            + (f"\n[cyan]HTML Narrative:[/cyan] {result['narrative_html']}" if result.get('narrative_html') else "")
            + (f"\n[cyan]PDF Narrative:[/cyan] {result['narrative_pdf']}" if result.get('narrative_pdf') else ""),
            title="Analysis Results",
            border_style="green"
        ))
        
        # Generate risk report if requested
        if args.risk_report:
            analyzer.generate_risk_report()
            
        # If comprehensive report is requested
        if args.comprehensive_report:
            try:
                from comprehensive_report_generator import ComprehensiveReportGenerator
                
                # Try to import transaction story generator, but continue if not available
                story_generator = None
                try:
                    from transaction_story import TransactionStoryGenerator
                    story_generator = TransactionStoryGenerator(analyzer.core_analyzer)
                    console.print("[cyan]Successfully initialized transaction story generator[/cyan]")
                except ImportError:
                    console.print("[yellow]Transaction story generator not available - reports will be generated without narrative features[/yellow]")
                except Exception as e:
                    console.print(f"[yellow]Warning: Could not initialize story generator: {str(e)}[/yellow]")
                
                # Create and generate comprehensive report
                report_generator = ComprehensiveReportGenerator(analyzer.core_analyzer, story_generator)
                reports = report_generator.generate_all_reports()
                
                if reports:
                    success_msg = f"[green]Comprehensive reports generated successfully![/green]\n\n"
                    if reports.get('html'):
                        success_msg += f"[cyan]HTML Report:[/cyan] {reports.get('html')}\n"
                    if reports.get('pdf'):
                        success_msg += f"[cyan]PDF Report:[/cyan] {reports.get('pdf')}\n"
                    
                    console.print(Panel(
                        success_msg,
                        title="Comprehensive Report Generation",
                        border_style="green"
                    ))
            except ImportError as e:
                console.print(f"[yellow]Could not generate comprehensive report: {str(e)}[/yellow]")
                console.print("[yellow]Make sure required libraries are installed: pip install jinja2 fpdf matplotlib[/yellow]")
            except Exception as e:
                console.print(f"[red]Error generating comprehensive report: {str(e)}[/red]")
    else:
        console.print(f"[red]Analysis failed: {result.get('error', 'Unknown error')}[/red]")

if __name__ == "__main__":
    # Import aiohttp here to avoid module issues
    import aiohttp
    main()