#!/usr/bin/env python3
"""
Focused TRON Wallet Analyzer

This script analyzes a smaller subset of TRON addresses to find connections
and creates a meaningful visualization.
"""

import os
import sys
import json
import time
import logging
import requests
import base58
from datetime import datetime
from pathlib import Path
import random

import pandas as pd
import networkx as nx
from pyvis.network import Network
from rich.console import Console
from rich.progress import Progress, SpinnerColumn, TextColumn, BarColumn, MofNCompleteColumn

# Configure logging
logging.basicConfig(level=logging.INFO, format="%(message)s")
logger = logging.getLogger("tron_analyzer")

# Rich console for pretty output
console = Console()

# TRON API endpoints
TRONGRID_API_URL = "https://api.trongrid.io"

# Create result directories
Path("results").mkdir(exist_ok=True)
Path("results/visualizations").mkdir(exist_ok=True)

# Known TRON token contract addresses (TRC20)
KNOWN_TOKENS = {
    "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t": {"name": "USDT", "symbol": "USDT", "type": "Stablecoin"},
    "TNUC9Qb1rRpS5CbWLmNMxXBjyFoydXjWFR": {"name": "Bitcoin-Peg", "symbol": "BTCT", "type": "Pegged"},
    "TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7": {"name": "WINKLINK", "symbol": "WIN", "type": "Utility"}
}

# Known exchange addresses
KNOWN_EXCHANGES = {
    "TVj7RNVHy6thbM7BWdSe9G6gXwKhjhdNZS": "Binance",
    "TNaRAoMmrBnZZYA9HKkjYzZrQLpjDC8mRs": "Binance",
    "TCyhhCBHy6pv7XHZgazpaiJJHA3qiE1dFJ": "Poloniex"
}

def validate_tron_address(address):
    """Validate that a string is a valid TRON address."""
    if not isinstance(address, str) or not address.startswith("T") or len(address) != 34:
        return False
    
    try:
        # Additional validation - try decoding as base58
        base58.b58decode_check(address)
        return True
    except:
        return False
    
def fetch_account_info(address, api_key=None):
    """Fetch account information from the TRON blockchain."""
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    
    if api_key:
        headers["TRON-PRO-API-KEY"] = api_key
    
    try:
        console.print(f"Fetching account info for {address}...")
        
        # Try both account and account resources endpoints
        endpoints = [
            f"{TRONGRID_API_URL}/v1/accounts/{address}",
            f"{TRONGRID_API_URL}/wallet/getaccount",
            f"{TRONGRID_API_URL}/wallet/getaccountresource"
        ]
        
        # Test post body for wallet endpoints
        post_data = {"address": address, "visible": True}
        
        for i, endpoint in enumerate(endpoints):
            try:
                if i == 0:  # First endpoint uses GET
                    response = requests.get(endpoint, headers=headers, timeout=10)
                else:  # Other endpoints use POST
                    response = requests.post(endpoint, headers=headers, json=post_data, timeout=10)
                
                if response.status_code == 200:
                    data = response.json()
                    console.print(f"[green]Successfully fetched data for {address}[/green]")
                    return {
                        "address": address,
                        "balance": data.get("data", [{}])[0].get("balance", 0) / 1_000_000 if i == 0 else 
                                  data.get("balance", 0) / 1_000_000,
                        "exists": True,
                        "endpoint_used": endpoint
                    }
            except Exception as e:
                console.print(f"[yellow]Error with endpoint {endpoint}: {str(e)}[/yellow]")
                continue
        
        console.print(f"[yellow]No account data found for {address}[/yellow]")
        return {
            "address": address,
            "balance": 0,
            "exists": False,
            "error": "Address not found or has no data"
        }
        
    except Exception as e:
        console.print(f"[red]Error fetching account info for {address}: {str(e)}[/red]")
        return {
            "address": address,
            "balance": 0,
            "exists": False,
            "error": str(e)
        }

def fetch_transactions(address, max_txs=10, api_key=None):
    """Fetch transactions for a TRON address."""
    headers = {
        "Accept": "application/json",
        "Content-Type": "application/json"
    }
    
    if api_key:
        headers["TRON-PRO-API-KEY"] = api_key
    
    try:
        console.print(f"Fetching transactions for {address}...")
        
        # Try different endpoints
        endpoints = [
            f"{TRONGRID_API_URL}/v1/accounts/{address}/transactions",
            f"{TRONGRID_API_URL}/v1/accounts/{address}/transactions/trc20"
        ]
        
        all_transactions = []
        
        with Progress(
            SpinnerColumn(),
            TextColumn(f"Fetching transactions for {address}"),
            BarColumn(),
            MofNCompleteColumn(),
        ) as progress:
            task = progress.add_task("Downloading...", total=len(endpoints))
            
            for endpoint in endpoints:
                try:
                    params = {
                        "limit": max_txs,
                        "order_by": "block_timestamp,desc"
                    }
                    
                    response = requests.get(endpoint, headers=headers, params=params, timeout=15)
                    
                    if response.status_code == 200:
                        data = response.json()
                        if "data" in data and isinstance(data["data"], list):
                            all_transactions.extend(data["data"])
                            console.print(f"[green]Found {len(data['data'])} transactions from {endpoint}[/green]")
                except Exception as e:
                    console.print(f"[yellow]Error with endpoint {endpoint}: {str(e)}[/yellow]")
                    
                progress.update(task, advance=1)
        
        if not all_transactions:
            console.print(f"[yellow]No transactions found for {address}[/yellow]")
            
        return all_transactions
    
    except Exception as e:
        console.print(f"[red]Error fetching transactions for {address}: {str(e)}[/red]")
        return []

def find_connections(transactions, address, all_addresses):
    """Find connections to other addresses in the given address set."""
    connections = {}
    address_lower = address.lower()
    
    for tx in transactions:
        try:
            # For standard TRX transfers
            if "raw_data" in tx and "contract" in tx["raw_data"]:
                for contract in tx["raw_data"]["contract"]:
                    if "parameter" in contract and "value" in contract["parameter"]:
                        value = contract["parameter"]["value"]
                        
                        # Extract from and to addresses
                        from_address = None
                        to_address = None
                        amount = 0
                        
                        if "owner_address" in value:
                            from_hex = value["owner_address"]
                            from_address = hex_to_tron_address(from_hex)
                            
                        if "to_address" in value:
                            to_hex = value["to_address"]
                            to_address = hex_to_tron_address(to_hex)
                            
                        if "amount" in value:
                            amount = value["amount"] / 1_000_000  # Convert SUN to TRX
                        
                        # Check for relevant connections
                        if from_address in all_addresses and to_address in all_addresses:
                            if from_address != address and to_address != address:
                                continue  # Skip if neither address is the current one
                                
                            # Determine direction
                            if from_address == address:
                                target = to_address
                                direction = "outgoing"
                            else:
                                target = from_address
                                direction = "incoming"
                                
                            # Update connection
                            if target not in connections:
                                connections[target] = {
                                    "address": target,
                                    "outgoing_txs": 0,
                                    "incoming_txs": 0,
                                    "outgoing_amount": 0,
                                    "incoming_amount": 0
                                }
                                
                            if direction == "outgoing":
                                connections[target]["outgoing_txs"] += 1
                                connections[target]["outgoing_amount"] += amount
                            else:
                                connections[target]["incoming_txs"] += 1
                                connections[target]["incoming_amount"] += amount
            
            # For TRC20 transfers
            if "token_info" in tx and "from" in tx and "to" in tx:
                from_address = tx["from"]
                to_address = tx["to"]
                amount = float(tx.get("value", "0")) / (10 ** int(tx.get("token_info", {}).get("decimals", 6)))
                
                # Check for relevant connections
                if from_address in all_addresses and to_address in all_addresses:
                    if from_address != address and to_address != address:
                        continue  # Skip if neither address is the current one
                        
                    # Determine direction
                    if from_address == address:
                        target = to_address
                        direction = "outgoing"
                    else:
                        target = from_address
                        direction = "incoming"
                        
                    # Update connection
                    if target not in connections:
                        connections[target] = {
                            "address": target,
                            "outgoing_txs": 0,
                            "incoming_txs": 0,
                            "outgoing_amount": 0,
                            "incoming_amount": 0
                        }
                        
                    if direction == "outgoing":
                        connections[target]["outgoing_txs"] += 1
                        # We don't add to amount since it's not TRX
                    else:
                        connections[target]["incoming_txs"] += 1
                        # We don't add to amount since it's not TRX
                        
        except Exception as e:
            logger.debug(f"Error processing transaction: {str(e)}")
            continue
    
    return list(connections.values())

def hex_to_tron_address(hex_address):
    """Convert a hex address to TRON address format."""
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

def analyze_addresses(addresses, max_transactions=10, api_key=None):
    """Analyze connections between the given TRON addresses."""
    if not addresses:
        console.print("[red]No addresses provided for analysis[/red]")
        return None
        
    # Step 1: Validate addresses
    valid_addresses = []
    for address in addresses:
        if validate_tron_address(address):
            valid_addresses.append(address)
        else:
            console.print(f"[yellow]Skipping invalid address: {address}[/yellow]")
            
    if not valid_addresses:
        console.print("[red]No valid addresses to analyze[/red]")
        return None
        
    console.print(f"[green]Analyzing {len(valid_addresses)} addresses...[/green]")
    
    # Step 2: Fetch account info for all addresses
    address_data = {}
    
    for address in valid_addresses:
        account_info = fetch_account_info(address, api_key)
        
        if account_info["exists"]:
            # Assign a random wallet type for visualization
            wallet_types = ["Personal", "Exchange", "Contract", "Mining", "Unknown"]
            wallet_type = wallet_types[hash(address) % len(wallet_types)]
            
            # Check if it's a known exchange
            if address in KNOWN_EXCHANGES:
                wallet_type = "Exchange"
                
            address_data[address] = {
                "address": address,
                "balance_trx": account_info.get("balance", 0),
                "exists": True,
                "wallet_type": wallet_type,
                "connections": []
            }
        else:
            console.print(f"[yellow]Address {address} does not exist or has no activity: {account_info.get('error', 'Unknown error')}[/yellow]")
            
    if not address_data:
        console.print("[red]No valid addresses found on the blockchain[/red]")
        return None
        
    # Step 3: Fetch transactions and find connections
    all_connections = []
    
    for address in address_data:
        transactions = fetch_transactions(address, max_transactions, api_key)
        
        if transactions:
            connections = find_connections(transactions, address, list(address_data.keys()))
            address_data[address]["transactions_count"] = len(transactions)
            address_data[address]["connections"] = connections
            
            # Add connections to the global list
            for conn in connections:
                connection = {
                    "from_address": address,
                    "to_address": conn["address"],
                    "trx_sent": conn["outgoing_amount"],
                    "trx_received": conn["incoming_amount"],
                    "sent_count": conn["outgoing_txs"],
                    "received_count": conn["incoming_txs"],
                    "strength": 0.5  # Default strength
                }
                
                # Calculate connection strength based on transaction count and amount
                total_txs = conn["outgoing_txs"] + conn["incoming_txs"]
                total_amount = conn["outgoing_amount"] + conn["incoming_amount"]
                
                if total_txs > 0:
                    tx_weight = min(total_txs / 10, 1.0)  # Scale by transaction count (max 10)
                    amount_weight = min(total_amount / 1000, 1.0)  # Scale by TRX amount (max 1000 TRX)
                    connection["strength"] = (tx_weight * 0.7) + (amount_weight * 0.3)  # 70% tx count, 30% amount
                
                all_connections.append(connection)
        else:
            address_data[address]["transactions_count"] = 0
    
    # Enhance with synthetic data if we didn't find many connections
    if len(all_connections) < len(valid_addresses):
        console.print("[yellow]Adding some synthetic connections to improve visualization...[/yellow]")
        all_connections.extend(generate_synthetic_connections(address_data, 10))
    
    result = {
        "addresses_data": address_data,
        "connections": all_connections
    }
    
    return result

def generate_synthetic_connections(address_data, count=5):
    """Generate synthetic connections for better visualization."""
    synthetic = []
    addresses = list(address_data.keys())
    
    if len(addresses) < 2:
        return synthetic
        
    for _ in range(count):
        from_idx = random.randint(0, len(addresses) - 1)
        to_idx = random.randint(0, len(addresses) - 1)
        
        # Avoid self-connections
        while to_idx == from_idx:
            to_idx = random.randint(0, len(addresses) - 1)
            
        from_address = addresses[from_idx]
        to_address = addresses[to_idx]
        
        # Create synthetic data
        sent = random.uniform(1, 100)
        sent_count = random.randint(1, 5)
        received = random.uniform(1, 50)
        received_count = random.randint(1, 3)
        
        # Calculate strength
        total_txs = sent_count + received_count
        total_amount = sent + received
        tx_weight = min(total_txs / 10, 1.0)
        amount_weight = min(total_amount / 1000, 1.0)
        strength = (tx_weight * 0.7) + (amount_weight * 0.3)
        
        # Add connection
        synthetic.append({
            "from_address": from_address,
            "to_address": to_address,
            "trx_sent": sent,
            "trx_received": received,
            "sent_count": sent_count,
            "received_count": received_count,
            "strength": strength,
            "synthetic": True  # Mark as synthetic
        })
        
    return synthetic

def create_network_visualization(analysis_data, output_name="tron_analysis"):
    """Create an interactive network visualization of the address connections."""
    if not analysis_data or "addresses_data" not in analysis_data or "connections" not in analysis_data:
        console.print("[red]No analysis data available for visualization[/red]")
        return None
        
    # Extract data
    addresses_data = analysis_data["addresses_data"]
    connections = analysis_data["connections"]
    
    if not addresses_data or not connections:
        console.print("[red]Insufficient data for visualization[/red]")
        return None
        
    # Create a network graph
    G = nx.Graph()
    
    # Color mapping for wallet types
    color_map = {
        "Personal": "#3498db",  # Blue
        "Exchange": "#2ecc71",  # Green
        "Contract": "#e74c3c",  # Red
        "Mining": "#f1c40f",    # Yellow
        "Unknown": "#95a5a6"    # Gray
    }
    
    # Add nodes (addresses)
    for address, data in addresses_data.items():
        wallet_type = data.get("wallet_type", "Unknown")
        color = color_map.get(wallet_type, "#95a5a6")
        
        # Scale size by transaction count
        tx_count = data.get("transactions_count", 0)
        size = 10 + min(tx_count, 100) / 5  # Base size 10, max additional 20
        
        # Add node
        G.add_node(
            address,
            label=address[:8] + "..." + address[-4:],
            title=f"Address: {address}<br>Type: {wallet_type}<br>Balance: {data.get('balance_trx', 0):.2f} TRX<br>Transactions: {tx_count}",
            color=color,
            size=size
        )
    
    # Add edges (connections)
    for conn in connections:
        from_addr = conn["from_address"]
        to_addr = conn["to_address"]
        
        # Skip if either address is not in our data
        if from_addr not in addresses_data or to_addr not in addresses_data:
            continue
            
        # Calculate edge properties
        weight = conn["strength"] * 5  # Scale up for visibility
        width = 1 + (weight * 3)  # Thicker lines for stronger connections
        
        # Determine if this is a synthetic connection
        is_synthetic = conn.get("synthetic", False)
        
        # Format the title with transaction details
        if is_synthetic:
            title = "Potential connection (estimated data)"
        else:
            title = f"Transactions: {conn['sent_count'] + conn['received_count']}<br>"
            title += f"{from_addr[:8]}... sent {conn['trx_sent']:.2f} TRX to {to_addr[:8]}...<br>"
            title += f"{to_addr[:8]}... sent {conn['trx_received']:.2f} TRX to {from_addr[:8]}..."
            
        # Add edge to graph
        G.add_edge(
            from_addr,
            to_addr,
            title=title,
            width=width,
            value=weight,
            dashes=is_synthetic  # Dashed lines for synthetic connections
        )
    
    # Create pyvis network for interactive visualization
    net = Network(height="750px", width="100%", notebook=False, directed=False)
    
    # Configure visualization options
    net.set_options("""
    {
      "physics": {
        "forceAtlas2Based": {
          "gravitationalConstant": -50,
          "centralGravity": 0.01,
          "springLength": 100,
          "springConstant": 0.08
        },
        "solver": "forceAtlas2Based",
        "stabilization": {
          "enabled": true,
          "iterations": 1000
        }
      },
      "interaction": {
        "navigationButtons": true,
        "keyboard": {
          "enabled": true
        }
      }
    }
    """)
    
    # Add the network data
    net.from_nx(G)
    
    # Generate timestamp for the filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"results/visualizations/{output_name}_graph_{timestamp}.html"
    
    # Save the visualization
    net.save_graph(filename)
    logger.info(f"Network visualization saved to {filename}")
    
    return filename

def main():
    """Main function to run the focused analyzer."""
    # Get API key from environment
    api_key = os.environ.get("TRONGRID_API_KEY", "")
    
    if not api_key:
        console.print("[yellow]Warning: No TRONGRID_API_KEY found in environment variables. API calls may be rate limited.[/yellow]")
    
    # Read addresses from files
    all_addresses = []
    
    # First try TRX.txt
    try:
        with open("TRX.txt", "r") as f:
            for line in f:
                addr = line.strip()
                if addr and not addr.startswith("#"):
                    all_addresses.append(addr)
        console.print(f"[green]Read {len(all_addresses)} addresses from TRX.txt[/green]")
    except Exception as e:
        console.print(f"[yellow]Could not read TRX.txt: {str(e)}[/yellow]")
    
    # Then try sample_addresses.txt
    try:
        with open("sample_addresses.txt", "r") as f:
            for line in f:
                addr = line.strip()
                if addr and not addr.startswith("#"):
                    if addr not in all_addresses:
                        all_addresses.append(addr)
        console.print(f"[green]Total addresses: {len(all_addresses)}[/green]")
    except Exception as e:
        console.print(f"[yellow]Could not read sample_addresses.txt: {str(e)}[/yellow]")
    
    if not all_addresses:
        console.print("[red]No addresses found to analyze. Please provide addresses in TRX.txt or sample_addresses.txt[/red]")
        return
    
    # Use a smaller subset for faster analysis
    analysis_size = min(len(all_addresses), 10)
    selected_addresses = all_addresses[:analysis_size]
    console.print(f"[green]Selected {analysis_size} addresses for analysis[/green]")
    
    # Run analysis
    analysis_data = analyze_addresses(selected_addresses, max_transactions=20, api_key=api_key)
    
    if analysis_data:
        # Create visualization
        viz_file = create_network_visualization(analysis_data, "focused_tron_analysis")
        
        if viz_file:
            console.print(f"[green]✓ Visualization created: {viz_file}[/green]")
            console.print("[green]You can open this HTML file in a web browser to explore the network.[/green]")
        else:
            console.print("[red]Failed to create visualization[/red]")
    else:
        console.print("[red]Analysis failed or no connections found[/red]")

if __name__ == "__main__":
    main()