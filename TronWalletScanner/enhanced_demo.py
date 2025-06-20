#!/usr/bin/env python3
"""
Enhanced TRON Wallet Analyzer Demo
Demonstrates the comprehensive exchange integration and intelligence gathering capabilities.
"""

import os
import json
import sys
from pathlib import Path

# Add current directory to path
sys.path.insert(0, str(Path(__file__).parent))

from tron_wallet_analyzer import TronWalletAnalyzer

def run_comprehensive_demo():
    """Run a comprehensive demo of the enhanced TRON wallet analyzer."""
    
    # Sample TRON addresses for testing (using real addresses from the database)
    test_addresses = [
        "TLa2f6VPqDgRE67v1736s7bJ8Ray5wYjU7",  # WINKLINK token contract
        "TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t",  # USDT contract  
        "TVj7RNVHy6thbM7BWdSe9G6gXwKhjhdNZS",  # Binance exchange
        "TQZskDJJRGAHifeJ5LaQTKuefKF5Pwcfq8"   # Huobi exchange
    ]
    
    print("="*80)
    print("ENHANCED TRON WALLET ANALYZER DEMO")
    print("="*80)
    print("Features:")
    print("• Comprehensive exchange detection")
    print("• DeFi protocol identification") 
    print("• Token contract analysis")
    print("• Risk assessment and malicious address detection")
    print("• Enhanced transaction intelligence")
    print("• Network visualization")
    print("="*80)
    
    # Initialize analyzer
    analyzer = TronWalletAnalyzer(max_transactions=10)
    
    results = {}
    
    for i, address in enumerate(test_addresses, 1):
        print(f"\n[{i}/{len(test_addresses)}] Analyzing: {address}")
        print("-" * 60)
        
        try:
            # Analyze the address
            result = analyzer.analyze_wallet(address)
            
            if "error" in result:
                print(f"Error: {result['error']}")
                continue
            
            # Display comprehensive results
            account_info = result.get('account_info', {})
            classification = result.get('classification', {})
            statistics = result.get('statistics', {})
            
            print(f"Address Type: {classification.get('type', 'Unknown')}")
            print(f"Balance: {account_info.get('balance', 0):.2f} TRX")
            print(f"Transactions: {statistics.get('total_transactions', 0)}")
            print(f"Connections: {statistics.get('total_connections', 0)}")
            print(f"Exchange Connections: {statistics.get('exchange_connections', 0)}")
            print(f"DeFi Connections: {statistics.get('defi_connections', 0)}")
            
            # Display enhanced intelligence if available
            if 'high_risk_transactions' in statistics:
                print(f"High Risk Transactions: {statistics['high_risk_transactions']}")
                print(f"Risk Percentage: {statistics.get('risk_percentage', 0):.1f}%")
                print(f"Verification Rate: {statistics.get('verification_rate', 0):.1f}%")
            
            # Show exchange verification status
            if classification.get('exchange_verified'):
                print("Exchange Status: VERIFIED")
            elif classification.get('is_high_risk'):
                print("Risk Status: HIGH RISK")
            
            results[address] = result
            
        except Exception as e:
            print(f"Analysis failed: {str(e)}")
    
    # Export comprehensive results
    print("\n" + "="*80)
    print("EXPORTING RESULTS")
    print("="*80)
    
    # JSON Export
    json_file = analyzer.export_to_json(".", "demo_analysis")
    if json_file:
        print(f"JSON exported: {json_file}")
    
    # CSV Export  
    csv_file = analyzer.export_to_csv(".", "demo_analysis")
    if csv_file:
        print(f"CSV exported: {csv_file}")
    
    # Network Visualization
    viz_file = analyzer.generate_network_visualization(".", "demo_network")
    if viz_file:
        print(f"Network visualization: {viz_file}")
    
    print("\n" + "="*80)
    print("DEMO COMPLETED SUCCESSFULLY")
    print("="*80)
    print("The enhanced TRON wallet analyzer now provides:")
    print("• Comprehensive exchange and DeFi detection")
    print("• Advanced risk assessment capabilities")
    print("• Token contract intelligence")
    print("• Malicious address identification")
    print("• Enhanced transaction analysis")
    print("• Interactive network visualizations")
    print("="*80)

if __name__ == "__main__":
    run_comprehensive_demo()