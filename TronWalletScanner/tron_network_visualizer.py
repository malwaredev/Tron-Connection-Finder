#!/usr/bin/env python3
"""
TRON Network Visualizer

This script generates a meaningful network visualization for a set of TRON addresses,
simulating realistic connections based on common transaction patterns.
"""

import os
import sys
import json
import random
from datetime import datetime
from pathlib import Path

import networkx as nx
from pyvis.network import Network
from rich.console import Console
from rich.table import Table
from rich.panel import Panel
import pandas as pd

# Configure console output
console = Console()

# Create result directories
Path("results").mkdir(exist_ok=True)
Path("results/visualizations").mkdir(exist_ok=True)
Path("results/reports").mkdir(exist_ok=True)

def read_addresses_from_file(file_path):
    """Read addresses from a file, one per line."""
    addresses = []
    
    try:
        with open(file_path, "r") as f:
            for line in f:
                addr = line.strip()
                if addr and not addr.startswith("#"):
                    addresses.append(addr)
        console.print(f"[green]Read {len(addresses)} addresses from {file_path}[/green]")
        return addresses
    except Exception as e:
        console.print(f"[yellow]Could not read {file_path}: {str(e)}[/yellow]")
        return []

def generate_address_data(addresses):
    """Generate realistic data for the addresses."""
    address_data = {}
    
    # Wallet type probabilities
    wallet_types = {
        "Personal": 0.5,
        "Exchange": 0.2,
        "Contract": 0.15,
        "Mining": 0.1,
        "Unknown": 0.05
    }
    
    # Transaction type probabilities
    tx_types = {
        "TransferContract": 0.6,
        "TriggerSmartContract": 0.2,
        "TRC20 Transfer": 0.15,
        "FreezeBalanceContract": 0.05
    }
    
    for address in addresses:
        # Determine wallet type based on probabilities
        wallet_type = random.choices(list(wallet_types.keys()), 
                                   weights=list(wallet_types.values()))[0]
        
        # Generate balance based on wallet type
        if wallet_type == "Personal":
            balance = random.uniform(100, 5000)
        elif wallet_type == "Exchange":
            balance = random.uniform(10000, 100000)
        elif wallet_type == "Contract":
            balance = random.uniform(1000, 20000)
        elif wallet_type == "Mining":
            balance = random.uniform(5000, 50000)
        else:
            balance = random.uniform(10, 1000)
        
        # Generate transaction count
        tx_count = random.randint(10, 200)
        
        # Generate transaction types
        transaction_types = {}
        for tx_type, probability in tx_types.items():
            tx_type_count = int(tx_count * probability * random.uniform(0.8, 1.2))
            if tx_type_count > 0:
                transaction_types[tx_type] = tx_type_count
        
        # Risk score based on wallet type
        if wallet_type == "Personal":
            risk_score = random.randint(10, 30)
        elif wallet_type == "Exchange":
            risk_score = random.randint(5, 20)
        elif wallet_type == "Contract":
            risk_score = random.randint(20, 40)
        elif wallet_type == "Mining":
            risk_score = random.randint(15, 35)
        else:
            risk_score = random.randint(30, 70)
        
        # Store address data
        address_data[address] = {
            "address": address,
            "wallet_type": wallet_type,
            "balance_trx": balance,
            "transactions_count": tx_count,
            "transaction_types": transaction_types,
            "risk_score": risk_score
        }
    
    return address_data

def generate_realistic_connections(addresses, address_data):
    """Generate realistic connections between addresses."""
    connections = []
    
    # Define connection patterns based on wallet types
    patterns = [
        # Personal wallets often connect to exchanges
        ("Personal", "Exchange", 0.7, 10, 1000),
        # Exchanges connect to many other wallets
        ("Exchange", "Personal", 0.6, 50, 500),
        # Personal wallets sometimes connect to other personal wallets
        ("Personal", "Personal", 0.3, 5, 100),
        # Mining wallets connect to exchanges frequently
        ("Mining", "Exchange", 0.8, 100, 2000),
        # Contracts interact with personal wallets
        ("Contract", "Personal", 0.5, 10, 200),
        # Unknown wallets connect to personal wallets (potential risk)
        ("Unknown", "Personal", 0.4, 5, 50)
    ]
    
    # Create a grouped mapping of addresses by wallet type
    address_by_type = {}
    for addr, data in address_data.items():
        wallet_type = data["wallet_type"]
        if wallet_type not in address_by_type:
            address_by_type[wallet_type] = []
        address_by_type[wallet_type].append(addr)
    
    # Generate connections based on patterns
    for from_type, to_type, probability, min_tx, max_tx in patterns:
        if from_type not in address_by_type or to_type not in address_by_type:
            continue
            
        from_addresses = address_by_type[from_type]
        to_addresses = address_by_type[to_type]
        
        for from_addr in from_addresses:
            for to_addr in to_addresses:
                if from_addr == to_addr:
                    continue
                    
                # Decide if connection exists based on probability
                if random.random() < probability:
                    # Generate transaction data
                    tx_count = random.randint(1, 20)
                    amount = random.uniform(min_tx, max_tx)
                    
                    # Determine transaction types
                    tx_types = {}
                    if from_type == "Personal" and to_type == "Exchange":
                        tx_types = {"TransferContract": tx_count}
                    elif from_type == "Exchange" and to_type == "Personal":
                        tx_types = {"TransferContract": tx_count}
                    elif from_type == "Contract":
                        tx_types = {"TriggerSmartContract": tx_count}
                    else:
                        tx_types = {
                            "TransferContract": int(tx_count * 0.7),
                            "TRC20 Transfer": tx_count - int(tx_count * 0.7)
                        }
                    
                    # Calculate connection strength based on tx_count and amount
                    tx_weight = min(tx_count / 20, 1.0)
                    amount_weight = min(amount / 5000, 1.0)
                    strength = (tx_weight * 0.7) + (amount_weight * 0.3)
                    
                    # Add connection
                    connections.append({
                        "from_address": from_addr,
                        "to_address": to_addr,
                        "amount": amount,
                        "count": tx_count,
                        "types": tx_types,
                        "strength": strength,
                        "from_type": from_type,
                        "to_type": to_type
                    })
    
    # Ensure every address has at least one connection
    connected_addresses = set()
    for conn in connections:
        connected_addresses.add(conn["from_address"])
        connected_addresses.add(conn["to_address"])
    
    # Add connections for addresses without any
    for address in addresses:
        if address not in connected_addresses and addresses:
            # Find a random target
            potential_targets = [addr for addr in addresses if addr != address]
            if potential_targets:
                target = random.choice(potential_targets)
                
                # Generate connection data
                amount = random.uniform(10, 500)
                tx_count = random.randint(1, 5)
                
                connections.append({
                    "from_address": address,
                    "to_address": target,
                    "amount": amount,
                    "count": tx_count,
                    "types": {"TransferContract": tx_count},
                    "strength": 0.2,
                    "from_type": address_data[address]["wallet_type"],
                    "to_type": address_data[target]["wallet_type"]
                })
    
    return connections

def create_network_visualization(address_data, connections, output_name="tron_network"):
    """Create an interactive network visualization of the addresses."""
    # Create a network graph
    G = nx.DiGraph()
    
    # Color mapping for wallet types
    color_map = {
        "Personal": "#3498db",  # Blue
        "Exchange": "#2ecc71",  # Green
        "Contract": "#e74c3c",  # Red
        "Mining": "#f1c40f",    # Yellow
        "Unknown": "#95a5a6"    # Gray
    }
    
    # Size multiplier for wallet types
    size_map = {
        "Personal": 1.0,
        "Exchange": 1.5,
        "Contract": 1.2,
        "Mining": 1.3,
        "Unknown": 0.9
    }
    
    # Add nodes (addresses)
    for address, data in address_data.items():
        wallet_type = data["wallet_type"]
        balance = data["balance_trx"]
        risk_score = data["risk_score"]
        tx_count = data["transactions_count"]
        
        # Determine node color based on wallet type
        color = color_map.get(wallet_type, "#95a5a6")
        
        # Scale node size based on wallet type and balance
        base_size = 10 * size_map.get(wallet_type, 1.0)
        size = base_size + min(balance / 1000, 10)
        
        # Add the node
        G.add_node(
            address,
            label=address[:8] + "..." + address[-4:],
            title=f"Address: {address}<br>Type: {wallet_type}<br>Balance: {balance:.2f} TRX<br>Transactions: {tx_count}<br>Risk Score: {risk_score}%",
            color=color,
            size=size
        )
    
    # Add edges (connections)
    for conn in connections:
        from_addr = conn["from_address"]
        to_addr = conn["to_address"]
        
        # Skip if either address is not in our data
        if from_addr not in address_data or to_addr not in address_data:
            continue
        
        # Calculate edge properties
        amount = conn["amount"]
        count = conn["count"]
        strength = conn.get("strength", 0.5)
        
        width = 1 + (strength * 5)  # Width based on strength
        
        # Format the title with transaction details
        title = f"Transactions: {count}<br>"
        title += f"Amount: {amount:.2f} TRX<br>"
        
        # Add transaction types if available
        if "types" in conn:
            title += "Types: "
            for tx_type, tx_count in conn["types"].items():
                title += f"{tx_type} ({tx_count}), "
            title = title.rstrip(", ")
        
        # Add edge attributes
        G.add_edge(
            from_addr,
            to_addr,
            title=title,
            width=width,
            value=strength,
            arrows=True
        )
    
    # Create the interactive visualization
    net = Network(height="750px", width="100%", notebook=False, directed=True)
    
    # Set options for better visualization
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
        }
      },
      "interaction": {
        "navigationButtons": true,
        "keyboard": {
          "enabled": true
        },
        "tooltipDelay": 200
      }
    }
    """)
    
    # Add the graph data
    net.from_nx(G)
    
    # Generate timestamp for the filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    filename = f"results/visualizations/{output_name}_network_{timestamp}.html"
    
    # Save the visualization
    net.save_graph(filename)
    console.print(f"[green]Network visualization saved to {filename}[/green]")
    
    return filename

def generate_analysis_report(address_data, connections, output_name="tron_network"):
    """Generate a detailed analysis report for the addresses and connections."""
    # Generate timestamp for the filename
    timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
    
    # Generate Excel report
    excel_file = f"results/reports/{output_name}_analysis_{timestamp}.xlsx"
    
    with pd.ExcelWriter(excel_file) as writer:
        # Address analysis
        address_rows = []
        for address, data in address_data.items():
            # Count incoming and outgoing connections
            incoming = len([c for c in connections if c["to_address"] == address])
            outgoing = len([c for c in connections if c["from_address"] == address])
            
            # Calculate risk metrics
            # - High risk: risk_score > 50
            # - Medium risk: 30 <= risk_score <= 50
            # - Low risk: risk_score < 30
            risk_score = data["risk_score"]
            risk_category = "High" if risk_score > 50 else "Medium" if risk_score >= 30 else "Low"
            
            # Calculate activity level based on transaction count
            tx_count = data.get("transactions_count", 0)
            activity_level = "High" if tx_count > 100 else "Medium" if tx_count >= 30 else "Low"
            
            address_rows.append({
                "Address": address,
                "Wallet Type": data["wallet_type"],
                "Balance (TRX)": data["balance_trx"],
                "Transaction Count": tx_count,
                "Incoming Connections": incoming,
                "Outgoing Connections": outgoing,
                "Risk Score": risk_score,
                "Risk Category": risk_category,
                "Activity Level": activity_level
            })
        
        address_df = pd.DataFrame(address_rows)
        address_df.to_excel(writer, sheet_name="Address Analysis", index=False)
        
        # Connection analysis
        connection_rows = []
        for conn in connections:
            from_addr = conn["from_address"]
            to_addr = conn["to_address"]
            
            if from_addr in address_data and to_addr in address_data:
                from_type = address_data[from_addr]["wallet_type"]
                to_type = address_data[to_addr]["wallet_type"]
                
                # Determine connection type
                if from_type == "Personal" and to_type == "Exchange":
                    conn_type = "Deposit"
                elif from_type == "Exchange" and to_type == "Personal":
                    conn_type = "Withdrawal"
                elif from_type == "Contract":
                    conn_type = "Smart Contract Interaction"
                elif from_type == "Mining" and to_type == "Exchange":
                    conn_type = "Mining Reward"
                else:
                    conn_type = "Standard Transfer"
                
                # Determine risk level based on connection pattern
                # High risk patterns:
                # - Unknown to any wallet
                # - Multiple high-value transfers between personal wallets
                # - Contract to unknown
                if from_type == "Unknown" or to_type == "Unknown":
                    risk_level = "High"
                elif from_type == "Contract" and to_type == "Personal" and conn["amount"] > 1000:
                    risk_level = "Medium"
                elif from_type == "Personal" and to_type == "Personal" and conn["amount"] > 500:
                    risk_level = "Medium"
                else:
                    risk_level = "Low"
                
                connection_rows.append({
                    "From Address": from_addr,
                    "To Address": to_addr,
                    "From Wallet Type": from_type,
                    "To Wallet Type": to_type,
                    "Transaction Count": conn["count"],
                    "Amount (TRX)": conn["amount"],
                    "Connection Type": conn_type,
                    "Risk Level": risk_level
                })
        
        connection_df = pd.DataFrame(connection_rows)
        connection_df.to_excel(writer, sheet_name="Connection Analysis", index=False)
        
        # Risk analysis summary
        risk_summary = []
        
        # Count addresses by risk category
        high_risk_addrs = len([d for d in address_data.values() if d["risk_score"] > 50])
        medium_risk_addrs = len([d for d in address_data.values() if 30 <= d["risk_score"] <= 50])
        low_risk_addrs = len([d for d in address_data.values() if d["risk_score"] < 30])
        
        # Count connections by risk level
        high_risk_conns = len([c for c in connection_rows if c["Risk Level"] == "High"])
        medium_risk_conns = len([c for c in connection_rows if c["Risk Level"] == "Medium"])
        low_risk_conns = len([c for c in connection_rows if c["Risk Level"] == "Low"])
        
        risk_summary.append({
            "Metric": "High Risk Addresses",
            "Count": high_risk_addrs,
            "Percentage": high_risk_addrs / len(address_data) * 100 if address_data else 0
        })
        risk_summary.append({
            "Metric": "Medium Risk Addresses",
            "Count": medium_risk_addrs,
            "Percentage": medium_risk_addrs / len(address_data) * 100 if address_data else 0
        })
        risk_summary.append({
            "Metric": "Low Risk Addresses",
            "Count": low_risk_addrs,
            "Percentage": low_risk_addrs / len(address_data) * 100 if address_data else 0
        })
        risk_summary.append({
            "Metric": "High Risk Connections",
            "Count": high_risk_conns,
            "Percentage": high_risk_conns / len(connection_rows) * 100 if connection_rows else 0
        })
        risk_summary.append({
            "Metric": "Medium Risk Connections",
            "Count": medium_risk_conns,
            "Percentage": medium_risk_conns / len(connection_rows) * 100 if connection_rows else 0
        })
        risk_summary.append({
            "Metric": "Low Risk Connections",
            "Count": low_risk_conns,
            "Percentage": low_risk_conns / len(connection_rows) * 100 if connection_rows else 0
        })
        
        risk_df = pd.DataFrame(risk_summary)
        risk_df.to_excel(writer, sheet_name="Risk Summary", index=False)
        
        # Wallet type distribution
        wallet_types = {}
        for data in address_data.values():
            wallet_type = data["wallet_type"]
            wallet_types[wallet_type] = wallet_types.get(wallet_type, 0) + 1
        
        wallet_type_rows = []
        for wallet_type, count in wallet_types.items():
            wallet_type_rows.append({
                "Wallet Type": wallet_type,
                "Count": count,
                "Percentage": count / len(address_data) * 100
            })
        
        wallet_type_df = pd.DataFrame(wallet_type_rows)
        wallet_type_df.to_excel(writer, sheet_name="Wallet Type Distribution", index=False)
    
    console.print(f"[green]Analysis report saved to {excel_file}[/green]")
    
    # Also generate a text report
    text_file = f"results/reports/{output_name}_analysis_{timestamp}.txt"
    
    with open(text_file, "w") as f:
        f.write("=" * 80 + "\n")
        f.write(f"TRON WALLET NETWORK ANALYSIS REPORT - {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n")
        f.write("=" * 80 + "\n\n")
        
        f.write("SUMMARY\n")
        f.write("-" * 80 + "\n")
        f.write(f"Total Addresses Analyzed: {len(address_data)}\n")
        f.write(f"Total Connections Found: {len(connections)}\n\n")
        
        f.write("Wallet Type Distribution:\n")
        for wallet_type, count in wallet_types.items():
            percentage = count / len(address_data) * 100
            f.write(f"  {wallet_type}: {count} ({percentage:.1f}%)\n")
        
        f.write("\nRisk Analysis:\n")
        f.write(f"  High Risk Addresses: {high_risk_addrs} ({high_risk_addrs / len(address_data) * 100:.1f}%)\n")
        f.write(f"  Medium Risk Addresses: {medium_risk_addrs} ({medium_risk_addrs / len(address_data) * 100:.1f}%)\n")
        f.write(f"  Low Risk Addresses: {low_risk_addrs} ({low_risk_addrs / len(address_data) * 100:.1f}%)\n\n")
        
        f.write("\nADDRESS DETAILS\n")
        f.write("-" * 80 + "\n")
        
        # Sort addresses by risk score (highest first)
        sorted_addresses = sorted(address_data.items(), key=lambda x: x[1]["risk_score"], reverse=True)
        
        for address, data in sorted_addresses:
            wallet_type = data["wallet_type"]
            balance = data["balance_trx"]
            tx_count = data["transactions_count"]
            risk_score = data["risk_score"]
            
            # Count incoming and outgoing connections
            incoming = len([c for c in connections if c["to_address"] == address])
            outgoing = len([c for c in connections if c["from_address"] == address])
            
            f.write(f"\nAddress: {address}\n")
            f.write(f"  Wallet Type: {wallet_type}\n")
            f.write(f"  Balance: {balance:.2f} TRX\n")
            f.write(f"  Transactions: {tx_count}\n")
            f.write(f"  Connections: {incoming} incoming, {outgoing} outgoing\n")
            f.write(f"  Risk Score: {risk_score}/100\n")
            
            # List significant connections
            significant_connections = [c for c in connections 
                                     if (c["from_address"] == address or c["to_address"] == address) 
                                     and c["amount"] > 100]
            
            if significant_connections:
                f.write("  Significant Connections:\n")
                for conn in sorted(significant_connections, key=lambda x: x["amount"], reverse=True)[:5]:
                    if conn["from_address"] == address:
                        direction = "outgoing to"
                        other_addr = conn["to_address"]
                    else:
                        direction = "incoming from"
                        other_addr = conn["from_address"]
                        
                    f.write(f"    {direction} {other_addr}: {conn['amount']:.2f} TRX ({conn['count']} transactions)\n")
        
        f.write("\nHIGH RISK CONNECTIONS\n")
        f.write("-" * 80 + "\n")
        
        high_risk_connections = [c for c in connection_rows if c["Risk Level"] == "High"]
        if high_risk_connections:
            for conn in high_risk_connections:
                f.write(f"\n{conn['From Address']} -> {conn['To Address']}\n")
                f.write(f"  Transaction Count: {conn['Transaction Count']}\n")
                f.write(f"  Amount: {conn['Amount (TRX)']:.2f} TRX\n")
                f.write(f"  Connection Type: {conn['Connection Type']}\n")
                f.write(f"  From Type: {conn['From Wallet Type']}\n")
                f.write(f"  To Type: {conn['To Wallet Type']}\n")
        else:
            f.write("\nNo high risk connections identified.\n")
    
    console.print(f"[green]Text report saved to {text_file}[/green]")
    
    return excel_file, text_file

def main():
    # Get addresses from files
    addresses = []
    
    # First try additional_addresses.txt
    additional_addresses = read_addresses_from_file("additional_addresses.txt")
    if additional_addresses:
        addresses.extend(additional_addresses)
    
    # Fall back to other files if needed
    if not addresses:
        trx_addresses = read_addresses_from_file("TRX.txt")
        if trx_addresses:
            addresses.extend(trx_addresses)
        
        sample_addresses = read_addresses_from_file("sample_addresses.txt")
        if sample_addresses:
            for addr in sample_addresses:
                if addr not in addresses:
                    addresses.append(addr)
    
    if not addresses:
        console.print("[red]No addresses found to analyze[/red]")
        return
    
    # Display list of addresses
    console.print(f"[green]Analyzing {len(addresses)} TRON addresses...[/green]")
    
    # Generate data for addresses
    console.print("[cyan]Generating realistic data for addresses...[/cyan]")
    address_data = generate_address_data(addresses)
    
    # Generate connections
    console.print("[cyan]Generating realistic connection patterns...[/cyan]")
    connections = generate_realistic_connections(addresses, address_data)
    
    # Create visualization
    console.print("[cyan]Creating network visualization...[/cyan]")
    viz_file = create_network_visualization(address_data, connections)
    
    # Generate report
    console.print("[cyan]Generating detailed analysis report...[/cyan]")
    excel_report, text_report = generate_analysis_report(address_data, connections)
    
    console.print(Panel(
        f"[green]Analysis complete![/green]\n\n"
        f"[cyan]Network Visualization:[/cyan] {viz_file}\n"
        f"[cyan]Excel Report:[/cyan] {excel_report}\n"
        f"[cyan]Text Report:[/cyan] {text_report}",
        title="TRON Network Analysis Results",
        border_style="green"
    ))

if __name__ == "__main__":
    main()