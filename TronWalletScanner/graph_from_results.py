#!/usr/bin/env python3
"""
Graph Generator from Advanced TRON Analyzer Results
Generates interactive network graphs from the JSON output of advanced_tron_analyzer.py
"""

import json
import argparse
from pathlib import Path
from datetime import datetime
from clean_network_generator import CleanTronNetworkGenerator

def load_analysis_results(json_file_path):
    """Load analysis results from JSON file."""
    try:
        with open(json_file_path, 'r') as f:
            data = json.load(f)
        return data
    except Exception as e:
        print(f"Error loading JSON file: {e}")
        return None

def convert_to_graph_format(analysis_data):
    """Convert analysis data to format expected by graph generator."""
    addresses_data = {}
    connections_data = []
    
    # Extract addresses data
    raw_addresses = analysis_data.get('addresses', {})
    for address, data in raw_addresses.items():
        if not data.get('exists', False):
            continue
            
        addresses_data[address] = {
            'wallet_type': data.get('wallet_type', 'Unknown'),
            'balance_trx': data.get('balance', 0),
            'risk_score': data.get('anomaly_score', 0),
            'transactions_count': data.get('transactions_count', 0),
            'is_exchange': data.get('is_exchange', False),
            'exchange_name': data.get('exchange_name', ''),
            'is_defi': data.get('is_defi', False),
            'defi_name': data.get('defi_name', ''),
            'is_malicious': data.get('is_malicious', False),
            'malicious_info': data.get('malicious_info', {}),
            'wallet_details': data.get('wallet_details', ''),
            'whale_tier': data.get('whale_tier', ''),
            'activity_tier': data.get('activity_tier', ''),
            'wealth_tier': data.get('wealth_tier', '')
        }
    
    # Extract connections data
    raw_connections = analysis_data.get('connections', [])
    for conn in raw_connections:
        if isinstance(conn, dict):
            connections_data.append({
                'from_address': conn.get('from_address'),
                'to_address': conn.get('to_address'),
                'amount': conn.get('amount', 0),
                'count': conn.get('count', 1),
                'trx_sent': conn.get('amount', 0),
                'trx_received': 0,
                'strength': conn.get('strength', 0),
                'types': conn.get('types', {})
            })
    
    return addresses_data, connections_data

def generate_graph_from_results(json_file_path, output_name=None):
    """Generate interactive graph from analysis results JSON."""
    print(f"Loading analysis results from: {json_file_path}")
    
    # Load the analysis data
    analysis_data = load_analysis_results(json_file_path)
    if not analysis_data:
        print("Failed to load analysis data")
        return None
    
    # Convert to graph format
    addresses_data, connections_data = convert_to_graph_format(analysis_data)
    
    print(f"Found {len(addresses_data)} addresses and {len(connections_data)} connections")
    
    if not addresses_data:
        print("No addresses found in the analysis data")
        return None
    
    # Generate output name if not provided
    if not output_name:
        json_path = Path(json_file_path)
        output_name = f"graph_from_{json_path.stem}"
    
    # Create the graph
    generator = CleanTronNetworkGenerator()
    try:
        graph_file = generator.create_graph(addresses_data, connections_data, output_name)
        print(f"✓ Interactive graph generated: {graph_file}")
        return graph_file
    except Exception as e:
        print(f"Error generating graph: {e}")
        return None

def main():
    """Main function for command-line usage."""
    parser = argparse.ArgumentParser(
        description="Generate interactive network graph from advanced TRON analyzer JSON results",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter
    )
    
    parser.add_argument(
        "json_file",
        help="Path to the JSON results file from advanced_tron_analyzer.py"
    )
    parser.add_argument(
        "-o", "--output",
        help="Output name for the graph (without extension)"
    )
    
    args = parser.parse_args()
    
    # Check if file exists
    json_path = Path(args.json_file)
    if not json_path.exists():
        print(f"Error: JSON file not found: {args.json_file}")
        return
    
    # Generate the graph
    result = generate_graph_from_results(args.json_file, args.output)
    if result:
        print(f"\nGraph generation complete!")
        print(f"View the interactive graph: {result}")
    else:
        print("Graph generation failed.")

if __name__ == "__main__":
    main()