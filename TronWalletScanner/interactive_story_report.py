#!/usr/bin/env python3
"""
Interactive Story Report Generator for TRON Wallet Analyzer

This module creates professional, interactive HTML reports with enhanced visualizations,
transaction stories, and comprehensive analysis summaries. The reports include:
- Executive summary with key metrics
- Interactive charts and visualizations
- Detailed address analysis with risk assessments
- Network connection graphs
- Transaction pattern analysis
- Professional styling with Bootstrap and Chart.js
"""

import os
import json
import time
from datetime import datetime, timedelta
from pathlib import Path
from typing import Dict, List, Any, Optional, Tuple
import base64
import io

# Simple console output without rich dependency
class SimpleConsole:
    def print(self, text, **kwargs):
        if isinstance(text, str):
            print(text)
        else:
            print(str(text))

console = SimpleConsole()

# Ensure results directories exist
RESULTS_DIR = Path("results")
REPORT_DIR = Path("results/reports")
VIZ_DIR = Path("results/visualizations")

for directory in [RESULTS_DIR, REPORT_DIR, VIZ_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

class InteractiveStoryReportGenerator:
    """Generates comprehensive interactive HTML reports with story-telling capabilities."""

    def __init__(self, analyzer, story_generator=None):
        """
        Initialize the interactive report generator.

        Args:
            analyzer: The TRON analyzer instance with analysis data
            story_generator: Optional TransactionStoryGenerator instance
        """
        self.analyzer = analyzer
        self.story_generator = story_generator
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.generation_time = datetime.now().strftime("%B %d, %Y at %H:%M UTC")

    def _calculate_summary_stats(self) -> Dict[str, Any]:
        """Calculate summary statistics from analyzer data."""
        addresses_analyzed = len(self.analyzer.addresses_data)
        active_addresses = sum(1 for data in self.analyzer.addresses_data.values() 
                             if data.get("exists", False))
        connections_found = len(self.analyzer.connections)

        # Calculate total volume and transaction counts
        total_volume = 0
        total_transactions = 0
        risk_scores = []
        wallet_types = {}
        exchange_count = 0

        for address, data in self.analyzer.addresses_data.items():
            if not data.get("exists", False):
                continue

            # Add transaction count
            total_transactions += data.get("transactions_count", 0)

            # Add volume data - handle different data structures
            if "analysis" in data and "metrics" in data["analysis"]:
                metrics = data["analysis"]["metrics"]
                total_volume += metrics.get("sent_volume", 0) + metrics.get("received_volume", 0)

            # Collect heuristics data - handle both anomaly_score and heuristics.risk_score
            risk_score = 0
            if "heuristics" in data:
                heuristics = data["heuristics"]
                risk_score = heuristics.get("risk_score", 0)
                wallet_type = heuristics.get("wallet_type", "unknown")
            elif "anomaly_score" in data:
                # Handle direct anomaly_score attribute
                risk_score = data.get("anomaly_score", 0)
                wallet_type = "unknown"
            else:
                # Fallback for data without heuristics or anomaly_score
                wallet_type = "unknown"

            if risk_score > 0:
                risk_scores.append(risk_score)
            else:
                risk_scores.append(0)

            wallet_types[wallet_type] = wallet_types.get(wallet_type, 0) + 1

            # Check for exchange addresses
            account_info = data.get("account_info", {})
            if account_info.get("is_exchange", False):
                exchange_count += 1

        # Calculate risk distribution
        high_risk_count = sum(1 for score in risk_scores if score >= 75)
        medium_risk_count = sum(1 for score in risk_scores if 25 <= score < 75)
        low_risk_count = sum(1 for score in risk_scores if score < 25)
        avg_risk_score = sum(risk_scores) / len(risk_scores) if risk_scores else 0

        # Find exchange addresses - comprehensive check
        exchange_count = 0
        exchanges_found = set()

        # Make sure addresses_data exists
        if not hasattr(self.analyzer, 'addresses_data'):
            self.analyzer.addresses_data = {}

        for address, data in self.analyzer.addresses_data.items():
            if not data.get("exists", False):
                continue

            is_exchange = False

            # Check account_info for exchange flag
            account_info = data.get("account_info", {})
            if account_info.get("is_exchange", False):
                is_exchange = True
                exchange_name = account_info.get("exchange_name", "Unknown Exchange")
                exchanges_found.add(exchange_name)

            # Check wallet type classification from heuristics
            if "heuristics" in data:
                wallet_type = data["heuristics"].get("wallet_type", "")
                if wallet_type.lower() == "exchange":
                    is_exchange = True
                    exchanges_found.add("Detected Exchange")

            # Check if address is in exchange database - use try/except for safety
            try:
                from exchanges_database import get_exchange_info
                exchange_info = get_exchange_info(address)
                if exchange_info:
                    is_exchange = True
                    exchanges_found.add(exchange_info.get("name", "Unknown Exchange"))
            except:
                pass

            # Check known exchanges list - safer attribute access
            try:
                if hasattr(self.analyzer, 'KNOWN_EXCHANGES') and address in self.analyzer.KNOWN_EXCHANGES:
                    is_exchange = True
                    exchanges_found.add(self.analyzer.KNOWN_EXCHANGES[address])
            except:
                pass

            if is_exchange:
                exchange_count += 1

        # Update wallet types to ensure exchange count is accurate
        if exchange_count > 0 and wallet_types.get("exchange", 0) < exchange_count:
            wallet_types["exchange"] = exchange_count

        return {
            "addresses_analyzed": addresses_analyzed,
            "active_addresses": active_addresses,
            "connections_found": connections_found,
            "total_volume": round(total_volume, 2),
            "total_transactions": total_transactions,
            "high_risk_count": high_risk_count,
            "medium_risk_count": medium_risk_count,
            "low_risk_count": low_risk_count,
            "avg_risk_score": round(avg_risk_score, 1),
            "wallet_types": wallet_types,
            "exchange_count": exchange_count,
            "exchange_percentage": round((exchange_count / active_addresses * 100), 1) if active_addresses > 0 else 0
        }

    def _generate_address_cards_html(self, stats: Dict[str, Any]) -> str:
        """Generate HTML for address cards with detailed information."""
        address_cards = []

        for address, data in self.analyzer.addresses_data.items():
            if not data.get("exists", False):
                continue

            # Get basic info
            account_info = data.get("account_info", {})
            balance = round(account_info.get("balance", 0), 2)
            transactions_count = data.get("transactions_count", 0)

            # Get analysis metrics
            analysis = data.get("analysis", {})
            metrics = analysis.get("metrics", {})
            volume = round(metrics.get("sent_volume", 0) + metrics.get("received_volume", 0), 2)

            # Get heuristics - handle both formats
            if "heuristics" in data:
                heuristics = data.get("heuristics", {})
                risk_score = heuristics.get("risk_score", 0)
                wallet_type = heuristics.get("wallet_type", "unknown").title()
            else:
                # Handle direct anomaly_score attribute
                risk_score = data.get("anomaly_score", 0)
                wallet_type = "Unknown"

            # Determine risk level and CSS class
            if risk_score >= 75:
                risk_level = "high"
                risk_class = "danger"
                risk_text = "High"
            elif risk_score >= 25:
                risk_level = "medium" 
                risk_class = "warning"
                risk_text = "Medium"
            else:
                risk_level = "low"
                risk_class = "success"
                risk_text = "Low"

            # Truncate address for display
            display_address = f"{address[:20]}...{address[-6:]}"

            address_card = f'''
                        <div class="col-md-6">
                            <div class="address-card {risk_level}-risk">
                                <h6><i class="fas fa-wallet"></i> {display_address}</h6>

                                <div class="row mt-2">
                                    <div class="col-4">
                                        <small class="text-muted">Balance</small>
                                        <div>{balance} TRX</div>
                                    </div>
                                    <div class="col-4">
                                        <small class="text-muted">Transactions</small>
                                        <div>{transactions_count}</div>
                                    </div>
                                    <div class="col-4">
                                        <small class="text-muted">Volume</small>
                                        <div>{volume} TRX</div>
                                    </div>
                                </div>
                                <div class="mt-2">
                                    <span class="badge bg-{risk_class}">
                                        Risk: {risk_text}
                                    </span>
                                    <span class="badge bg-secondary">
                                        Type: {wallet_type}
                                    </span>
                                </div>
                            </div>
                        </div>
                '''
            address_cards.append(address_card)

        return "\n".join(address_cards)

    def _generate_network_analysis_html(self) -> str:
        """Generate HTML for network analysis section."""
        if not self.analyzer.connections:
            return '''
                <div class="alert alert-info">
                    <i class="fas fa-info-circle"></i>
                    No direct connections found between the analyzed addresses.
                    This could indicate the addresses operate independently or connections
                    exist beyond the analyzed transaction depth.
                </div>
            '''

        # Analyze connection patterns
        connection_types = {}
        total_connection_value = 0
        unique_pairs = set()

        for conn in self.analyzer.connections:
            conn_type = conn.get("type", "unknown")
            connection_types[conn_type] = connection_types.get(conn_type, 0) + 1

            amount = float(conn.get("amount", 0))
            total_connection_value += amount

            # Track unique address pairs
            from_addr = conn.get("from_address", "")
            to_addr = conn.get("to_address", "") 
            pair = tuple(sorted([from_addr, to_addr]))
            unique_pairs.add(pair)

        # Generate connection type breakdown
        type_breakdown = []
        for conn_type, count in connection_types.items():
            percentage = (count / len(self.analyzer.connections)) * 100
            type_breakdown.append(f'''
                <div class="col-md-4">
                    <div class="connection-stat">
                        <h5>{count}</h5>
                        <p>{conn_type.replace('_', ' ').title()}</p>
                        <small>{percentage:.1f}% of connections</small>
                    </div>
                </div>
            ''')

        return f'''
            <div class="row mb-4">
                <div class="col-md-3">
                    <div class="connection-stat">
                        <h4>{len(self.analyzer.connections)}</h4>
                        <p>Total Connections</p>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="connection-stat">
                        <h4>{len(unique_pairs)}</h4>
                        <p>Unique Address Pairs</p>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="connection-stat">
                        <h4>{round(total_connection_value, 2)}</h4>
                        <p>Total Connection Value (TRX)</p>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="connection-stat">
                        <h4>{round(total_connection_value / len(self.analyzer.connections), 2) if self.analyzer.connections else 0}</h4>
                        <p>Average Transaction Value</p>
                    </div>
                </div>
            </div>

            <h5>Connection Types</h5>
            <div class="row">
                {"".join(type_breakdown)}
            </div>
        '''

    def _generate_risk_analysis_html(self, stats: Dict[str, Any]) -> str:
        """Generate HTML for risk analysis section."""
        risk_addresses = []

        for address, data in self.analyzer.addresses_data.items():
            if not data.get("exists", False):
                continue

            # Handle both heuristics and direct anomaly_score formats
            if "heuristics" in data:
                heuristics = data.get("heuristics", {})
                risk_score = heuristics.get("risk_score", 0)
                wallet_type = heuristics.get("wallet_type", "unknown").title()
                risk_indicators = heuristics.get("risk_indicators", [])
                patterns = heuristics.get("transaction_patterns", [])
            else:
                risk_score = data.get("anomaly_score", 0)
                wallet_type = "Unknown"
                risk_indicators = data.get("risk_factors", [])
                patterns = []

            if risk_score >= 25:  # Medium or high risk

                risk_level = "High" if risk_score >= 75 else "Medium"
                risk_class = "danger" if risk_score >= 75 else "warning"

                # Create risk factors list
                risk_factors = []
                for indicator in risk_indicators[:3]:  # Show top 3 indicators
                    risk_factors.append(f"<li>{indicator.get('details', '')}</li>")

                pattern_list = []
                for pattern in patterns[:2]:  # Show top 2 patterns
                    pattern_list.append(f"<li>{pattern.get('details', '')}</li>")

                display_address = f"{address[:20]}...{address[-6:]}"

                risk_card = f'''
                    <div class="col-md-6 mb-3">
                        <div class="card border-{risk_class}">
                            <div class="card-header bg-{risk_class} text-white">
                                <h6 class="mb-0">{display_address}</h6>
                            </div>
                            <div class="card-body">
                                <div class="row">
                                    <div class="col-6">
                                        <strong>Risk Score:</strong> {risk_score}/100
                                    </div>
                                    <div class="col-6">
                                        <strong>Type:</strong> {wallet_type}
                                    </div>
                                </div>

                                {"<div class='mt-2'><strong>Risk Factors:</strong><ul>" + "".join(risk_factors) + "</ul></div>" if risk_factors else ""}
                                {"<div class='mt-2'><strong>Patterns:</strong><ul>" + "".join(pattern_list) + "</ul></div>" if pattern_list else ""}
                            </div>
                        </div>
                    </div>
                '''
                risk_addresses.append(risk_card)

        if not risk_addresses:
            return '''
                <div class="alert alert-success">
                    <i class="fas fa-check-circle"></i>
                    No high or medium risk addresses detected in this analysis.
                    All analyzed addresses show normal transaction patterns.
                </div>
            '''

        return f'''
            <div class="row">
                {"".join(risk_addresses)}
            </div>
        '''

    def _create_html_template(self) -> str:
        """Create the enhanced HTML template for the interactive report."""
        return '''<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <link href="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/css/bootstrap.min.css" rel="stylesheet">
    <link href="https://cdnjs.cloudflare.com/ajax/libs/font-awesome/6.0.0/css/all.min.css" rel="stylesheet">
    <script src="https://cdn.jsdelivr.net/npm/chart.js"></script>
    <style>
        body { 
            background: linear-gradient(135deg, #667eea 0%, #764ba2 100%);
            min-height: 100vh;
            font-family: 'Segoe UI', Tahoma, Geneva, Verdana, sans-serif;
        }
        .main-container {
            background: rgba(255, 255, 255, 0.95);
            border-radius: 15px;
            box-shadow: 0 20px 40px rgba(0,0,0,0.1);
            backdrop-filter: blur(10px);
            margin: 20px auto;
            max-width: 1200px;
        }
        .metric-card {
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            border-radius: 10px;
            padding: 20px;
            margin: 10px 0;
            box-shadow: 0 5px 15px rgba(0,0,0,0.2);
            transition: transform 0.2s;
        }
        .metric-card:hover {
            transform: translateY(-2px);
        }
        .risk-high { color: #dc3545; font-weight: bold; }
        .risk-medium { color: #ffc107; font-weight: bold; }
        .risk-low { color: #28a745; font-weight: bold; }
        .address-card {
            border: 1px solid #dee2e6;
            border-radius: 8px;
            padding: 15px;
            margin: 10px 0;
            transition: box-shadow 0.2s;
        }
        .address-card:hover {
            box-shadow: 0 4px 8px rgba(0,0,0,0.1);
        }
        .address-card.high-risk {
            border-left: 4px solid #dc3545;
            background-color: #fff5f5;
        }
        .address-card.medium-risk {
            border-left: 4px solid #ffc107;
            background-color: #fffbf0;
        }
        .address-card.low-risk {
            border-left: 4px solid #28a745;
            background-color: #f0fff4;
        }
        .chart-container {
            position: relative;
            height: 400px;
            margin: 20px 0;
        }
        .connection-graph {
            background: #f8f9fa;
            border-radius: 8px;
            padding: 20px;
            margin: 20px 0;
        }
        .nav-pills .nav-link.active {
            background: linear-gradient(135deg, #667eea, #764ba2);
        }
        .section-header {
            background: linear-gradient(135deg, #667eea, #764ba2);
            color: white;
            padding: 15px;
            border-radius: 10px;
            margin: 20px 0;
        }
        .connection-stat {
            text-align: center;
            padding: 15px;
            background: #f8f9fa;
            border-radius: 8px;
            margin: 5px 0;
        }
        .insight-card {
            background: #e3f2fd;
            border-left: 4px solid #2196f3;
            padding: 15px;
            margin: 10px 0;
            border-radius: 5px;
        }
        .timeline-item {
            border-left: 2px solid #667eea;
            padding-left: 20px;
            margin: 15px 0;
            position: relative;
        }
        .timeline-item::before {
            content: '';
            position: absolute;
            left: -6px;
            top: 0;
            width: 10px;
            height: 10px;
            border-radius: 50%;
            background: #667eea;
        }
    </style>
</head>
<body>
    <div class="container-fluid">
        <div class="main-container p-4">
            <div class="text-center mb-4">
                <h1 class="display-4 mb-3">
                    <i class="fas fa-chart-network text-primary"></i>
                    {{ title }}
                </h1>
                <p class="lead">{{ subtitle }}</p>
                <p class="text-muted">Generated on {{ generation_time }}</p>
            </div>

            <!-- Executive Summary -->
            <div class="section-header">
                <h2><i class="fas fa-chart-line"></i> Executive Summary</h2>
            </div>

            <div class="row">
                <div class="col-md-3">
                    <div class="metric-card text-center">
                        <i class="fas fa-wallet fa-2x mb-2"></i>
                        <h3>{{ stats.addresses_analyzed }}</h3>
                        <p>Addresses Analyzed</p>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="metric-card text-center">
                        <i class="fas fa-coins fa-2x mb-2"></i>
                        <h3>{{ stats.total_volume }}</h3>
                        <p>Total Volume (TRX)</p>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="metric-card text-center">
                        <i class="fas fa-network-wired fa-2x mb-2"></i>
                        <h3>{{ stats.connections_found }}</h3>
                        <p>Connections Found</p>
                    </div>
                </div>
                <div class="col-md-3">
                    <div class="metric-card text-center">
                        <i class="fas fa-exclamation-triangle fa-2x mb-2"></i>
                        <h3>{{ stats.high_risk_count }}</h3>
                        <p>High-Risk Addresses</p>
                    </div>
                </div>
            </div>

            <!-- Navigation Tabs -->
            <ul class="nav nav-pills nav-justified my-4" id="analysisTab" role="tablist">
                <li class="nav-item" role="presentation">
                    <button class="nav-link active" id="overview-tab" data-bs-toggle="pill" data-bs-target="#overview" type="button">
                        <i class="fas fa-chart-pie"></i> Overview
                    </button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" id="addresses-tab" data-bs-toggle="pill" data-bs-target="#addresses" type="button">
                        <i class="fas fa-list"></i> Addresses
                    </button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" id="network-tab" data-bs-toggle="pill" data-bs-target="#network" type="button">
                        <i class="fas fa-project-diagram"></i> Network
                    </button>
                </li>
                <li class="nav-item" role="presentation">
                    <button class="nav-link" id="risk-tab" data-bs-toggle="pill" data-bs-target="#risk" type="button">
                        <i class="fas fa-shield-alt"></i> Risk Assessment
                    </button>
                </li>
            </ul>

            <!-- Tab Content -->
            <div class="tab-content" id="analysisTabContent">
                <!-- Overview Tab -->
                <div class="tab-pane fade show active" id="overview" role="tabpanel">
                    <div class="row">
                        <div class="col-md-6">
                            <div class="chart-container">
                                <canvas id="riskChart"></canvas>
                            </div>
                        </div>
                        <div class="col-md-6">
                            <div class="chart-container">
                                <canvas id="volumeChart"></canvas>
                            </div>
                        </div>
                    </div>

                    <div class="row mt-4">
                        <div class="col-12">
                            <h4>Key Insights</h4>
                            <div class="insight-card">
                                <ul class="mb-0">
                                    <li>Analysis covers {{ stats.addresses_analyzed }} TRON addresses with {{ stats.active_addresses }} active addresses</li>
                                    <li>Total transaction volume: {{ stats.total_volume }} TRX</li>
                                    <li>Average risk score: {{ stats.avg_risk_score }}/100</li>
                                    <li>Network density: {{ stats.connections_found }} connections between addresses</li>
                                    <li>Exchange addresses: {{ stats.exchange_count }} ({{ stats.exchange_percentage }}%)</li>
                                </ul>
                            </div>
                        </div>
                    </div>
                </div>

                <!-- Addresses Tab -->
                <div class="tab-pane fade" id="addresses" role="tabpanel">
                    <h4>Address Analysis</h4>
                    <div class="row">
                        {{ address_cards }}
                    </div>
                </div>

                <!-- Network Tab -->
                <div class="tab-pane fade" id="network" role="tabpanel">
                    <h4>Network Analysis</h4>
                    {{ network_analysis }}
                </div>

                <!-- Risk Assessment Tab -->
                <div class="tab-pane fade" id="risk" role="tabpanel">
                    <h4>Risk Assessment</h4>
                    {{ risk_analysis }}
                </div>
            </div>
        </div>
    </div>

    <script src="https://cdn.jsdelivr.net/npm/bootstrap@5.1.3/dist/js/bootstrap.bundle.min.js"></script>
    <script>
        // Risk Distribution Chart
        const riskCtx = document.getElementById('riskChart').getContext('2d');
        new Chart(riskCtx, {
            type: 'doughnut',
            data: {
                labels: ['Low Risk (0-24)', 'Medium Risk (25-74)', 'High Risk (75-100)'],
                datasets: [{
                    data: [{{ stats.low_risk_count }}, {{ stats.medium_risk_count }}, {{ stats.high_risk_count }}],
                    backgroundColor: ['#28a745', '#ffc107', '#dc3545'],
                    borderWidth: 2,
                    borderColor: '#fff'
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: {
                        display: true,
                        text: 'Risk Score Distribution'
                    },
                    legend: {
                        position: 'bottom'
                    }
                }
            }
        });

        // Volume Chart (Wallet Types)
        const volumeCtx = document.getElementById('volumeChart').getContext('2d');
        const walletTypes = {{ wallet_type_labels | safe }};
        const walletCounts = {{ wallet_type_counts | safe }};

        new Chart(volumeCtx, {
            type: 'bar',
            data: {
                labels: walletTypes,
                datasets: [{
                    label: 'Number of Addresses',
                    data: walletCounts,
                    backgroundColor: [
                        '#667eea', '#764ba2', '#f093fb', '#f5576c',
                        '#4facfe', '#00f2fe', '#43e97b', '#38f9d7'
                    ],
                    borderWidth: 1
                }]
            },
            options: {
                responsive: true,
                maintainAspectRatio: false,
                plugins: {
                    title: {
                        display: true,
                        text: 'Wallet Type Distribution'
                    }
                },
                scales: {
                    y: {
                        beginAtZero: true,
                        ticks: {
                            stepSize: 1
                        }
                    }
                }
            }
        });
    </script>
</body>
</html>'''

    def generate_interactive_report(self, output_name: str = "tron_analysis") -> str:
        """
        Generate a comprehensive interactive HTML report.

        Args:
            output_name: Base name for the output file

        Returns:
            Path to the generated HTML report
        """
        console.print("Generating Interactive Story Report...")

        # Calculate summary statistics
        console.print("Calculating summary statistics...")
        stats = self._calculate_summary_stats()

        # Generate address cards
        console.print("Generating address analysis...")
        address_cards = self._generate_address_cards_html(stats)

        # Generate network analysis
        console.print("Analyzing network connections...")
        network_analysis = self._generate_network_analysis_html()

        # Generate risk analysis
        console.print("Performing risk assessment...")
        risk_analysis = self._generate_risk_analysis_html(stats)

        # Prepare chart data
        console.print("Preparing chart data...")
        wallet_type_labels = list(stats["wallet_types"].keys())
        wallet_type_counts = list(stats["wallet_types"].values())

        # Prepare template variables
        template_vars = {
            "title": "Enhanced TRON Wallet Analysis",
            "subtitle": "Comprehensive Analysis Report",
            "generation_time": self.generation_time,
            "stats": stats,
            "address_cards": address_cards,
            "network_analysis": network_analysis,
            "risk_analysis": risk_analysis,
            "wallet_type_labels": json.dumps(wallet_type_labels),
            "wallet_type_counts": json.dumps(wallet_type_counts)
        }

        # Generate HTML from template
        console.print("Rendering HTML template...")
        html_template = self._create_html_template()

        # Enhanced template replacement with proper handling
        html_content = html_template

        # Replace all template variables systematically
        # First replace the simple variables
        html_content = html_content.replace("{{ title }}", str(template_vars.get("title", "TRON Wallet Analysis")))
        html_content = html_content.replace("{{ subtitle }}", str(template_vars.get("subtitle", "Analysis Report")))
        html_content = html_content.replace("{{ generation_time }}", str(template_vars.get("generation_time", "Unknown")))

        # Replace stats variables one by one
        stats_data = template_vars.get("stats", {})
        html_content = html_content.replace("{{ stats.addresses_analyzed }}", str(stats_data.get("addresses_analyzed", 0)))
        html_content = html_content.replace("{{ stats.active_addresses }}", str(stats_data.get("active_addresses", 0)))
        html_content = html_content.replace("{{ stats.total_volume }}", str(stats_data.get("total_volume", 0)))
        html_content = html_content.replace("{{ stats.connections_found }}", str(stats_data.get("connections_found", 0)))
        html_content = html_content.replace("{{ stats.high_risk_count }}", str(stats_data.get("high_risk_count", 0)))
        html_content = html_content.replace("{{ stats.medium_risk_count }}", str(stats_data.get("medium_risk_count", 0)))
        html_content = html_content.replace("{{ stats.low_risk_count }}", str(stats_data.get("low_risk_count", 0)))
        html_content = html_content.replace("{{ stats.avg_risk_score }}", str(stats_data.get("avg_risk_score", 0)))
        html_content = html_content.replace("{{ stats.exchange_count }}", str(stats_data.get("exchange_count", 0)))
        html_content = html_content.replace("{{ stats.exchange_percentage }}", str(stats_data.get("exchange_percentage", 0)))

        # Replace content sections
        html_content = html_content.replace("{{ address_cards }}", str(template_vars.get("address_cards", "")))
        html_content = html_content.replace("{{ network_analysis }}", str(template_vars.get("network_analysis", "")))
        html_content = html_content.replace("{{ risk_analysis }}", str(template_vars.get("risk_analysis", "")))

        # Replace chart data
        html_content = html_content.replace("{{ wallet_type_labels | safe }}", template_vars.get("wallet_type_labels", "[]"))
        html_content = html_content.replace("{{ wallet_type_counts | safe }}", template_vars.get("wallet_type_counts", "[]"))

        # Create the output file
        console.print("Saving report file...")
        output_file = REPORT_DIR / f"{output_name}_story_interactive_{self.timestamp}.html"

        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)

        console.print(f"Interactive report generated successfully!")
        console.print(f"Location: {output_file}")
        console.print(f"File size: {output_file.stat().st_size / 1024:.1f} KB")

        return str(output_file)

    def generate_all_reports(self, output_name: str = "tron_analysis") -> Dict[str, str]:
        """
        Generate all available report formats.

        Args:
            output_name: Base name for output files

        Returns:
            Dictionary with paths to all generated reports
        """

        reports = {}

        # Generate interactive HTML report
        html_report = self.generate_interactive_report(output_name)
        reports["interactive_html"] = html_report

        # Generate basic HTML report using comprehensive generator if available
        try:
            from comprehensive_report_generator import ComprehensiveReportGenerator
            comprehensive_gen = ComprehensiveReportGenerator(self.analyzer, self.story_generator)
            basic_html = comprehensive_gen.generate_html_report()
            reports["basic_html"] = basic_html

            # Try to generate PDF as well
            try:
                pdf_report = comprehensive_gen.generate_pdf_report()
                if pdf_report:
                    reports["pdf"] = pdf_report
            except Exception as e:
                console.print(f"Warning: PDF generation failed: {str(e)}")

        except ImportError:
            console.print("Warning: Comprehensive report generator not available")

        return reports

def main():
    """
    Example usage of the interactive story report generator.
    """
    print("Interactive Story Report Generator")
    print("This tool creates professional, interactive HTML reports")
    print("with enhanced visualizations and story-telling capabilities.")
    print()
    print("This module is designed to be used with the TRON Wallet Analyzer.")
    print("Import and use InteractiveStoryReportGenerator class in your analysis workflow.")

if __name__ == "__main__":
    main()