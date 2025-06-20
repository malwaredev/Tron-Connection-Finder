#!/usr/bin/env python3
"""
Comprehensive Report Generator for TRON Wallet Analyzer

This module generates detailed, integrated reports in both PDF and HTML formats 
that combine all analysis data from multiple modules into a single document.
"""

import os
import time
import json
from datetime import datetime
from pathlib import Path
import base64
from typing import Dict, List, Any, Optional

# HTML and PDF generation libraries
from jinja2 import Environment, FileSystemLoader, Template
from fpdf import FPDF
import pandas as pd

# Visualization helpers (imported conditionally later)
# We'll try to import matplotlib only when needed to avoid import errors

# Rich for console output
from rich.console import Console
from rich.panel import Panel

# Create console for output
console = Console()

# Ensure results directories exist
RESULTS_DIR = Path("results")
REPORT_DIR = Path("results/reports")
VIZ_DIR = Path("results/visualizations")
RESOURCE_DIR = Path("results/resources")

for directory in [RESULTS_DIR, REPORT_DIR, VIZ_DIR, RESOURCE_DIR]:
    directory.mkdir(parents=True, exist_ok=True)

class ComprehensiveReportGenerator:
    """Generates comprehensive PDF and HTML reports that include all analysis data."""
    
    def __init__(self, analyzer, story_generator=None):
        """
        Initialize the report generator.
        
        Args:
            analyzer: The TRON analyzer instance with analysis data
            story_generator: Optional TransactionStoryGenerator instance
        """
        self.analyzer = analyzer
        self.story_generator = story_generator
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        
        # Create a Jinja environment
        self.html_template = self._create_html_template()
    
    def _create_html_template(self) -> str:
        """Create the HTML template for the comprehensive report."""
        return """
<!DOCTYPE html>
<html lang="en">
<head>
    <meta charset="UTF-8">
    <meta name="viewport" content="width=device-width, initial-scale=1.0">
    <title>{{ title }}</title>
    <style>
        body {
            font-family: Arial, sans-serif;
            line-height: 1.6;
            color: #333;
            max-width: 1200px;
            margin: 0 auto;
            padding: 20px;
        }
        h1, h2, h3, h4 {
            color: #2a4b8d;
        }
        .header {
            background-color: #f8f9fa;
            padding: 20px;
            margin-bottom: 30px;
            border-radius: 5px;
            border-left: 5px solid #2a4b8d;
        }
        .section {
            margin-bottom: 30px;
            padding: 20px;
            background-color: #fff;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .subsection {
            margin: 20px 0;
            padding-left: 15px;
            border-left: 3px solid #6c757d;
        }
        table {
            border-collapse: collapse;
            width: 100%;
            margin: 20px 0;
        }
        th, td {
            border: 1px solid #ddd;
            padding: 8px 12px;
            text-align: left;
        }
        th {
            background-color: #f2f2f2;
        }
        tr:nth-child(even) {
            background-color: #f9f9f9;
        }
        .risk-high {
            color: #dc3545;
            font-weight: bold;
        }
        .risk-medium {
            color: #fd7e14;
        }
        .risk-low {
            color: #28a745;
        }
        .card {
            border: 1px solid #ddd;
            border-radius: 5px;
            padding: 15px;
            margin: 10px 0;
            background-color: #f8f9fa;
        }
        .summary-stats {
            display: flex;
            flex-wrap: wrap;
            justify-content: space-between;
            margin: 20px 0;
        }
        .stat-box {
            background-color: #f8f9fa;
            border-radius: 5px;
            padding: 15px;
            margin: 10px;
            flex: 1 0 200px;
            text-align: center;
            box-shadow: 0 2px 3px rgba(0,0,0,0.1);
        }
        .stat-box h3 {
            margin: 0;
            font-size: 16px;
            color: #6c757d;
        }
        .stat-box .value {
            font-size: 24px;
            font-weight: bold;
            color: #2a4b8d;
            margin: 10px 0;
        }
        .chart-container {
            width: 100%;
            max-width: 800px;
            margin: 20px auto;
        }
        .visualization {
            width: 100%;
            height: 600px;
            border: none;
            margin: 20px 0;
        }
        .footer {
            text-align: center;
            margin-top: 40px;
            padding: 20px;
            color: #6c757d;
            font-size: 0.9em;
        }
        .wallet-card {
            margin-bottom: 20px;
            padding: 15px;
            border-radius: 5px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .wallet-personal {
            border-left: 5px solid #3498db;
        }
        .wallet-exchange {
            border-left: 5px solid #2ecc71;
        }
        .wallet-contract {
            border-left: 5px solid #e74c3c;
        }
        .wallet-mining {
            border-left: 5px solid #f1c40f;
        }
        .wallet-dex {
            border-left: 5px solid #9b59b6;
        }
        .wallet-whale {
            border-left: 5px solid #1abc9c;
        }
        .wallet-unknown {
            border-left: 5px solid #95a5a6;
        }
        .transaction-list {
            max-height: 300px;
            overflow-y: auto;
            border: 1px solid #ddd;
            border-radius: 3px;
            padding: 10px;
        }
        .badge {
            display: inline-block;
            padding: 3px 7px;
            font-size: 12px;
            font-weight: bold;
            border-radius: 3px;
            margin-right: 5px;
        }
        .badge-blue {
            background-color: #e7f5ff;
            color: #3498db;
        }
        .badge-green {
            background-color: #e8f8f5;
            color: #2ecc71;
        }
        .badge-red {
            background-color: #fdedeb;
            color: #e74c3c;
        }
        .badge-yellow {
            background-color: #fef9e7;
            color: #f1c40f;
        }
        .badge-purple {
            background-color: #f4ecf7;
            color: #9b59b6;
        }
        .connection-table {
            font-size: 0.9em;
        }
        .tooltip {
            position: relative;
            display: inline-block;
            border-bottom: 1px dotted #666;
            cursor: help;
        }
        .tooltip .tooltiptext {
            visibility: hidden;
            width: 300px;
            background-color: #555;
            color: #fff;
            text-align: left;
            border-radius: 6px;
            padding: 10px;
            position: absolute;
            z-index: 1;
            bottom: 125%;
            left: 50%;
            margin-left: -150px;
            opacity: 0;
            transition: opacity 0.3s;
            font-size: 0.9em;
        }
        .tooltip:hover .tooltiptext {
            visibility: visible;
            opacity: 1;
        }
        .malicious-warning {
            background-color: #fff3cd;
            color: #856404;
            padding: 10px 15px;
            border-radius: 3px;
            margin: 10px 0;
            border-left: 5px solid #ffc107;
        }
        .token-list {
            display: flex;
            flex-wrap: wrap;
            gap: 10px;
            margin: 10px 0;
        }
        .token-item {
            background-color: #f8f9fa;
            border-radius: 3px;
            padding: 5px 10px;
            font-size: 0.9em;
            border: 1px solid #ddd;
        }
        @media print {
            .section {
                break-inside: avoid;
                page-break-inside: avoid;
            }
            body {
                font-size: 10pt;
            }
            h1 {
                font-size: 18pt;
            }
            h2 {
                font-size: 14pt;
            }
            h3 {
                font-size: 12pt;
            }
        }
    </style>
</head>
<body>
    <div class="header">
        <h1>{{ title }}</h1>
        <p>Generated: {{ generation_time }}</p>
        <p>Analysis Runtime: {{ runtime }} seconds</p>
    </div>
    
    <div class="section">
        <h2>Summary</h2>
        <div class="summary-stats">
            <div class="stat-box">
                <h3>Addresses Analyzed</h3>
                <div class="value">{{ stats.addresses_analyzed }}</div>
            </div>
            <div class="stat-box">
                <h3>Connections Found</h3>
                <div class="value">{{ stats.connections_found }}</div>
            </div>
            <div class="stat-box">
                <h3>Transactions Processed</h3>
                <div class="value">{{ stats.transactions_processed }}</div>
            </div>
            <div class="stat-box">
                <h3>High Risk Addresses</h3>
                <div class="value {% if stats.high_risk_count > 0 %}risk-high{% else %}risk-low{% endif %}">
                    {{ stats.high_risk_count }}
                </div>
            </div>
        </div>
        
        <h3>Wallet Type Distribution</h3>
        {% if charts.wallet_types %}
        <div class="chart-container">
            <img src="data:image/png;base64,{{ charts.wallet_types }}" alt="Wallet Type Distribution" style="width:100%">
        </div>
        {% else %}
        <div class="card">
            <p>Chart not available. Distribution summary:</p>
            <ul>
            {% for wallet_type, count in stats.wallet_type_counts.items() %}
                <li><strong>{{ wallet_type }}:</strong> {{ count }} ({{ (count / stats.addresses_analyzed * 100)|round(1) }}%)</li>
            {% endfor %}
            </ul>
        </div>
        {% endif %}
        
        <h3>Risk Score Distribution</h3>
        {% if charts.risk_scores %}
        <div class="chart-container">
            <img src="data:image/png;base64,{{ charts.risk_scores }}" alt="Risk Score Distribution" style="width:100%">
        </div>
        {% else %}
        <div class="card">
            <p>Chart not available. Risk summary:</p>
            <ul>
                <li><strong>Low Risk (0-24):</strong> {{ stats.low_risk_count }} addresses</li>
                <li><strong>Medium Risk (25-74):</strong> {{ stats.medium_risk_count }} addresses</li>
                <li><strong>High Risk (75-100):</strong> {{ stats.high_risk_count }} addresses</li>
            </ul>
        </div>
        {% endif %}
    </div>
    
    {% if visualization_file %}
    <div class="section">
        <h2>Network Visualization</h2>
        <p>Interactive network graph of connections between analyzed addresses.</p>
        <iframe class="visualization" src="{{ visualization_file }}"></iframe>
        <p><a href="{{ visualization_file }}" target="_blank">Open visualization in a new tab</a></p>
    </div>
    {% endif %}
    
    {% if high_risk_addresses %}
    <div class="section">
        <h2>High Risk Addresses</h2>
        {% for address, data in high_risk_addresses.items() %}
        <div class="card">
            <h3>{{ address }}</h3>
            <p><strong>Risk Score:</strong> <span class="risk-high">{{ data.anomaly_score }}/100</span></p>
            <p><strong>Wallet Type:</strong> {{ data.wallet_type }} ({{ data.wallet_details }})</p>
            <p><strong>Balance:</strong> {{ data.balance }} TRX</p>
            {% if data.is_malicious %}
            <div class="malicious-warning">
                <strong>WARNING:</strong> This address is flagged as potentially malicious.
                <p><strong>Type:</strong> {{ data.malicious_info.type }}</p>
                <p><strong>Confidence:</strong> {{ data.malicious_info.confidence * 100 }}%</p>
                <p><strong>Description:</strong> {{ data.malicious_info.description }}</p>
                {% if data.malicious_info.reference %}
                <p><strong>Reference:</strong> {{ data.malicious_info.reference }}</p>
                {% endif %}
            </div>
            {% endif %}
            <h4>Risk Factors:</h4>
            <ul>
            {% for factor in data.risk_factors %}
                <li>{{ factor }}</li>
            {% endfor %}
            </ul>
        </div>
        {% endfor %}
    </div>
    {% endif %}
    
    <div class="section">
        <h2>Address Details</h2>
        {% for address, data in addresses.items() %}
        <div class="wallet-card wallet-{{ data.wallet_type|lower }}">
            <h3>{{ address }}</h3>
            <p>
                <span class="badge badge-blue">{{ data.wallet_type }}</span>
                {% if data.is_exchange %}
                <span class="badge badge-green">Exchange: {{ data.exchange_name }}</span>
                {% endif %}
                {% if data.is_malicious %}
                <span class="badge badge-red">Malicious</span>
                {% endif %}
                <span class="badge {% if data.anomaly_score >= 75 %}badge-red{% elif data.anomaly_score >= 25 %}badge-yellow{% else %}badge-green{% endif %}">
                    Risk: {{ data.anomaly_score }}/100
                </span>
            </p>
            <div class="subsection">
                <h4>Basic Information</h4>
                <p><strong>Balance:</strong> {{ data.balance }} TRX</p>
                <p><strong>Transactions:</strong> {{ data.transactions_count }}</p>
                <p><strong>API Source:</strong> {{ data.api_source }}</p>
            </div>
            
            {% if data.tokens and data.tokens|length > 0 %}
            <div class="subsection">
                <h4>Tokens</h4>
                <div class="token-list">
                {% for token in data.tokens %}
                    <div class="token-item">
                        <strong>{{ token.symbol if token.symbol else "???" }}</strong>: 
                        {{ token.balance|round(2) }}
                        {% if token.name and token.name != token.symbol %}
                        <span class="tooltip">ℹ️
                            <span class="tooltiptext">
                                {{ token.name }}<br>
                                {% if token.category %}Category: {{ token.category }}<br>{% endif %}
                                {% if token.description %}{{ token.description }}{% endif %}
                            </span>
                        </span>
                        {% endif %}
                    </div>
                {% endfor %}
                </div>
            </div>
            {% endif %}
            
            {% if data.risk_factors and data.risk_factors|length > 0 %}
            <div class="subsection">
                <h4>Risk Factors</h4>
                <ul>
                {% for factor in data.risk_factors %}
                    <li>{{ factor }}</li>
                {% endfor %}
                </ul>
            </div>
            {% endif %}
            
            {% if data.connections and data.connections|length > 0 %}
            <div class="subsection">
                <h4>Significant Connections</h4>
                <table class="connection-table">
                    <tr>
                        <th>Direction</th>
                        <th>Address</th>
                        <th>Amount (TRX)</th>
                        <th>Transactions</th>
                    </tr>
                    {% for conn_key, conn in data.connections.items() %}
                    <tr>
                        <td>{% if conn.from_address == address %}Outgoing{% else %}Incoming{% endif %}</td>
                        <td>{% if conn.from_address == address %}{{ conn.to_address }}{% else %}{{ conn.from_address }}{% endif %}</td>
                        <td>{{ conn.total_amount|round(2) }}</td>
                        <td>{{ conn.count }}</td>
                    </tr>
                    {% endfor %}
                </table>
            </div>
            {% endif %}
            
            {% if data.contract_analysis %}
            <div class="subsection">
                <h4>Smart Contract Analysis</h4>
                <p><strong>Contract Type:</strong> {{ data.contract_analysis.contract_type }}</p>
                <p><strong>Transaction Count:</strong> {{ data.contract_analysis.transaction_count }}</p>
                <p><strong>Unique Callers:</strong> {{ data.contract_analysis.unique_callers }}</p>
                
                {% if data.contract_analysis.most_used_functions %}
                <h5>Most Used Functions:</h5>
                <ul>
                {% for func in data.contract_analysis.most_used_functions %}
                    <li>{{ func[0] }}: {{ func[1] }} calls</li>
                {% endfor %}
                </ul>
                {% endif %}
            </div>
            {% endif %}
        </div>
        {% endfor %}
    </div>
    
    {% if narrative %}
    <div class="section">
        <h2>Transaction Stories</h2>
        <div class="subsection">
            <h3>Network Overview</h3>
            <p>{{ narrative.network }}</p>
        </div>
        
        {% if narrative.wallet_stories %}
        <div class="subsection">
            <h3>Wallet Stories</h3>
            {% for address, story in narrative.wallet_stories.items() %}
            <div class="card">
                <h4>{{ address }}</h4>
                <p>{{ story }}</p>
            </div>
            {% endfor %}
        </div>
        {% endif %}
        
        {% if narrative.recommendations %}
        <div class="subsection">
            <h3>Recommendations</h3>
            <ul>
            {% for recommendation in narrative.recommendations %}
                <li>{{ recommendation }}</li>
            {% endfor %}
            </ul>
        </div>
        {% endif %}
    </div>
    {% endif %}
    
    <div class="footer">
        <p>Generated by TRON Wallet Analyzer on {{ generation_time }}</p>
        <p>Version 2.0.0</p>
    </div>
</body>
</html>
        """
    
    def _generate_wallet_types_chart(self, addresses_data: Dict[str, Dict]) -> str:
        """Generate a chart showing the distribution of wallet types."""
        try:
            # Try to import matplotlib
            import matplotlib.pyplot as plt
            
            # Count wallet types
            wallet_types = {}
            for address, data in addresses_data.items():
                wallet_type = data.get("wallet_type", "Unknown")
                wallet_types[wallet_type] = wallet_types.get(wallet_type, 0) + 1
            
            # Create the chart
            plt.figure(figsize=(10, 6))
            colors = ['#3498db', '#2ecc71', '#e74c3c', '#f1c40f', '#9b59b6', '#1abc9c', '#95a5a6']
            
            labels = list(wallet_types.keys())
            sizes = list(wallet_types.values())
            
            # Sort by size (largest first)
            sorted_data = sorted(zip(labels, sizes, colors[:len(labels)]), key=lambda x: x[1], reverse=True)
            labels, sizes, colors = zip(*sorted_data) if sorted_data else ([], [], [])
            
            plt.pie(sizes, labels=labels, colors=colors, autopct='%1.1f%%', startangle=140)
            plt.axis('equal')  # Equal aspect ratio ensures that pie is drawn as a circle
            plt.title('Wallet Type Distribution')
            
            # Save to a BytesIO object
            from io import BytesIO
            chart_file = BytesIO()
            plt.savefig(chart_file, format='png', bbox_inches='tight')
            plt.close()
            
            # Convert to base64 for embedding in HTML
            chart_file.seek(0)
            return base64.b64encode(chart_file.read()).decode('utf-8')
        except ImportError:
            console.print("[yellow]Warning: matplotlib not installed - report will be generated without charts.[/yellow]")
            return ""
        except Exception as e:
            console.print(f"[yellow]Warning: Could not generate wallet types chart: {str(e)}[/yellow]")
            return ""
    
    def _generate_risk_scores_chart(self, addresses_data: Dict[str, Dict]) -> str:
        """Generate a chart showing the distribution of risk scores."""
        try:
            # Try to import matplotlib
            import matplotlib.pyplot as plt
            
            # Extract risk scores from heuristics data
            risk_scores = []
            for data in addresses_data.values():
                if 'heuristics' in data and 'risk_score' in data['heuristics']:
                    risk_scores.append(data['heuristics']['risk_score'])
                elif 'anomaly_score' in data:
                    risk_scores.append(data['anomaly_score'])
                else:
                    risk_scores.append(0)
            
            # Create the chart
            plt.figure(figsize=(10, 6))
            
            # Define bins
            bins = [0, 25, 75, 100]
            
            # Create histogram with single color to avoid matplotlib conflicts
            plt.hist(risk_scores, bins=bins, alpha=0.7, edgecolor='black', color='#3498db')
            
            # Add labels and title
            plt.xlabel('Risk Score')
            plt.ylabel('Number of Addresses')
            plt.title('Risk Score Distribution')
            
            # Add vertical lines for risk categories
            plt.axvline(x=25, color='#f1c40f', linestyle='--', alpha=0.5)
            plt.axvline(x=75, color='#e74c3c', linestyle='--', alpha=0.5)
            
            # Add text labels for risk categories
            plt.text(12.5, plt.ylim()[1]*0.9, 'Low Risk', ha='center')
            plt.text(50, plt.ylim()[1]*0.9, 'Medium Risk', ha='center')
            plt.text(87.5, plt.ylim()[1]*0.9, 'High Risk', ha='center')
            
            # Save to a BytesIO object
            from io import BytesIO
            chart_file = BytesIO()
            plt.savefig(chart_file, format='png', bbox_inches='tight')
            plt.close()
            
            # Convert to base64 for embedding in HTML
            chart_file.seek(0)
            return base64.b64encode(chart_file.read()).decode('utf-8')
        except ImportError:
            console.print("[yellow]Warning: matplotlib not installed - report will be generated without charts.[/yellow]")
            return ""
        except Exception as e:
            console.print(f"[yellow]Warning: Could not generate risk scores chart: {str(e)}[/yellow]")
            return ""
    
    def generate_html_report(self) -> str:
        """
        Generate a comprehensive HTML report with all analysis data.
        
        Returns:
            Path to the generated HTML report
        """
        if not hasattr(self.analyzer, 'addresses_data') or not self.analyzer.addresses_data:
            console.print("[yellow]No analysis data available for report generation.[/yellow]")
            return None
        
        console.print("[cyan]Generating comprehensive HTML report...[/cyan]")
        
        # Basic analysis data
        addresses_data = self.analyzer.addresses_data
        connections = self.analyzer.connections
        
        # Create stats for the report
        # Count risk levels
        high_risk_count = len([a for a in addresses_data.values() if a.get("anomaly_score", 0) >= 75])
        medium_risk_count = len([a for a in addresses_data.values() if 25 <= a.get("anomaly_score", 0) < 75])
        low_risk_count = len([a for a in addresses_data.values() if a.get("anomaly_score", 0) < 25])
        
        # Count wallet types
        wallet_type_counts = {}
        for address, data in addresses_data.items():
            wallet_type = data.get("wallet_type", "Unknown")
            wallet_type_counts[wallet_type] = wallet_type_counts.get(wallet_type, 0) + 1
        
        stats = {
            "addresses_analyzed": len(addresses_data),
            "connections_found": len(connections),
            "transactions_processed": self.analyzer.stats.get("transactions_processed", 0),
            "high_risk_count": high_risk_count,
            "medium_risk_count": medium_risk_count,
            "low_risk_count": low_risk_count,
            "wallet_type_counts": wallet_type_counts,
            "runtime": self.analyzer.stats.get("runtime", 0)
        }
        
        # Create charts
        charts = {
            "wallet_types": self._generate_wallet_types_chart(addresses_data),
            "risk_scores": self._generate_risk_scores_chart(addresses_data)
        }
        
        # Identify high risk addresses
        high_risk_addresses = {
            addr: data for addr, data in addresses_data.items() 
            if data.get("anomaly_score", 0) >= 75 or data.get("is_malicious", False)
        }
        
        # Get visualization file
        visualization_file = None
        viz_files = list(VIZ_DIR.glob("*enhanced*.html"))
        if viz_files:
            # Get the most recent visualization file
            visualization_file = str(sorted(viz_files, key=lambda x: x.stat().st_mtime, reverse=True)[0])
        
        # Get narrative data if available
        narrative = None
        if self.story_generator:
            narrative = self.story_generator.generate_narrative_summary()
        
        # Prepare the template data
        template_data = {
            "title": f"TRON Wallet Analysis Report",
            "generation_time": datetime.now().strftime("%Y-%m-%d %H:%M:%S"),
            "stats": stats,
            "charts": charts,
            "addresses": addresses_data,
            "high_risk_addresses": high_risk_addresses,
            "visualization_file": visualization_file,
            "narrative": narrative,
            "runtime": self.analyzer.stats.get("runtime", 0)
        }
        
        # Render the template
        html_content = Template(self.html_template).render(**template_data)
        
        # Write to file
        output_file = f"{REPORT_DIR}/comprehensive_report_{self.timestamp}.html"
        with open(output_file, 'w', encoding='utf-8') as f:
            f.write(html_content)
        
        console.print(f"[green]Comprehensive HTML report saved to {output_file}[/green]")
        return output_file
    
    def generate_pdf_report(self) -> str:
        """
        Generate a comprehensive PDF report with all analysis data.
        
        Returns:
            Path to the generated PDF report or None if generation fails
        """
        if not hasattr(self.analyzer, 'addresses_data') or not self.analyzer.addresses_data:
            console.print("[yellow]No analysis data available for report generation.[/yellow]")
            return None
        
        console.print("[cyan]Generating comprehensive PDF report...[/cyan]")
        
        # First generate the HTML report (we'll convert it to PDF if possible)
        html_report = self.generate_html_report()
        
        if not html_report:
            return None
            
        try:
            # Try to generate a basic PDF using FPDF (no external dependencies)
            return self._generate_basic_pdf_report()
        except Exception as e:
            console.print(f"[yellow]Warning: Could not generate PDF report: {str(e)}[/yellow]")
            console.print("[yellow]HTML report was still generated successfully.[/yellow]")
            return None
    
    def _generate_basic_pdf_report(self) -> str:
        """
        Generate a basic PDF report with essential analysis data.
        
        Returns:
            Path to the generated PDF report
        """
        # Basic analysis data
        addresses_data = self.analyzer.addresses_data
        connections = self.analyzer.connections
        
        # Create a PDF document
        pdf = FPDF()
        pdf.add_page()
        
        # Set up fonts
        pdf.set_font("Arial", "B", 16)
        
        # Title
        pdf.cell(0, 10, "TRON Wallet Analysis Report", ln=True, align="C")
        pdf.set_font("Arial", "", 10)
        pdf.cell(0, 10, f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}", ln=True, align="C")
        
        # Summary section
        pdf.set_font("Arial", "B", 14)
        pdf.ln(10)
        pdf.cell(0, 10, "Summary", ln=True)
        
        pdf.set_font("Arial", "", 10)
        pdf.cell(0, 10, f"Addresses Analyzed: {len(addresses_data)}", ln=True)
        pdf.cell(0, 10, f"Connections Found: {len(connections)}", ln=True)
        pdf.cell(0, 10, f"Transactions Processed: {self.analyzer.stats.get('transactions_processed', 0)}", ln=True)
        pdf.cell(0, 10, f"High Risk Addresses: {len([a for a in addresses_data.values() if a.get('anomaly_score', 0) >= 75])}", ln=True)
        
        # High Risk Addresses
        high_risk = {addr: data for addr, data in addresses_data.items() if data.get("anomaly_score", 0) >= 75}
        if high_risk:
            pdf.set_font("Arial", "B", 14)
            pdf.ln(10)
            pdf.cell(0, 10, "High Risk Addresses", ln=True)
            
            for addr, data in high_risk.items():
                pdf.set_font("Arial", "B", 10)
                pdf.ln(5)
                pdf.cell(0, 10, f"Address: {addr}", ln=True)
                
                pdf.set_font("Arial", "", 10)
                pdf.cell(0, 10, f"Risk Score: {data.get('anomaly_score', 0)}/100", ln=True)
                pdf.cell(0, 10, f"Wallet Type: {data.get('wallet_type', 'Unknown')}", ln=True)
                pdf.cell(0, 10, f"Balance: {data.get('balance', 0)} TRX", ln=True)
                
                # Risk factors
                if data.get("risk_factors"):
                    pdf.set_font("Arial", "B", 10)
                    pdf.cell(0, 10, "Risk Factors:", ln=True)
                    pdf.set_font("Arial", "", 10)
                    for factor in data.get("risk_factors", []):
                        pdf.cell(0, 10, f"- {factor}", ln=True)
        
        # Address Details (brief overview)
        pdf.set_font("Arial", "B", 14)
        pdf.ln(10)
        pdf.cell(0, 10, "Address Overview", ln=True)
        
        # Create a simple table for addresses
        pdf.set_font("Arial", "B", 10)
        pdf.ln(5)
        # Column widths
        col_widths = [70, 30, 30, 30, 30]
        # Header
        pdf.cell(col_widths[0], 10, "Address", 1, 0, "C")
        pdf.cell(col_widths[1], 10, "Type", 1, 0, "C")
        pdf.cell(col_widths[2], 10, "Balance", 1, 0, "C")
        pdf.cell(col_widths[3], 10, "Transactions", 1, 0, "C")
        pdf.cell(col_widths[4], 10, "Risk Score", 1, 1, "C")
        
        # Data
        pdf.set_font("Arial", "", 8)
        for addr, data in addresses_data.items():
            # Truncate address if needed
            display_addr = addr[:30] + "..." if len(addr) > 33 else addr
            pdf.cell(col_widths[0], 10, display_addr, 1, 0)
            pdf.cell(col_widths[1], 10, data.get("wallet_type", "Unknown"), 1, 0, "C")
            pdf.cell(col_widths[2], 10, str(round(data.get("balance", 0), 2)), 1, 0, "R")
            pdf.cell(col_widths[3], 10, str(data.get("transactions_count", 0)), 1, 0, "C")
            pdf.cell(col_widths[4], 10, str(data.get("anomaly_score", 0)), 1, 1, "C")
        
        # Footer
        pdf.ln(10)
        pdf.set_font("Arial", "I", 8)
        pdf.cell(0, 10, "Generated by TRON Wallet Analyzer", ln=True, align="C")
        
        # Save the PDF
        output_file = f"{REPORT_DIR}/comprehensive_report_{self.timestamp}.pdf"
        pdf.output(output_file)
        
        console.print(f"[green]Basic PDF report saved to {output_file}[/green]")
        return output_file
    
    def generate_all_reports(self) -> Dict[str, str]:
        """
        Generate all report formats.
        
        Returns:
            Dictionary with paths to all generated reports
        """
        reports = {}
        
        # Generate HTML report
        html_report = self.generate_html_report()
        if html_report:
            reports["html"] = html_report
        
        # Generate PDF report
        pdf_report = self.generate_pdf_report()
        if pdf_report:
            reports["pdf"] = pdf_report
        
        return reports


def main():
    """
    Example usage of the comprehensive report generator.
    """
    from tron_master_analyzer import TronMasterAnalyzer
    from transaction_story import TransactionStoryGenerator
    import argparse
    
    parser = argparse.ArgumentParser(description="Generate a comprehensive report from TRON Wallet Analysis")
    parser.add_argument("-c", "--checkpoint", type=str, help="Checkpoint file to load analysis from")
    parser.add_argument("-o", "--output", type=str, default="comprehensive", help="Base name for output files")
    args = parser.parse_args()
    
    # Get API keys from environment
    trongrid_api_key = os.environ.get("TRONGRID_API_KEY", "")
    tronscan_api_key = os.environ.get("TRONSCAN_API_KEY", "")
    
    # Initialize the analyzer
    analyzer = TronMasterAnalyzer(
        trongrid_api_key=trongrid_api_key,
        tronscan_api_key=tronscan_api_key
    )
    
    # Load from checkpoint if provided
    if args.checkpoint:
        if analyzer.core_analyzer.load_checkpoint(args.checkpoint):
            console.print(f"[green]Loaded analysis data from checkpoint: {args.checkpoint}[/green]")
        else:
            console.print(f"[red]Failed to load checkpoint: {args.checkpoint}[/red]")
            return
    else:
        console.print("[yellow]No checkpoint provided. Please provide a checkpoint file with analysis data.[/yellow]")
        return
    
    # Create story generator
    story_generator = TransactionStoryGenerator(analyzer.core_analyzer)
    
    # Create report generator
    report_generator = ComprehensiveReportGenerator(analyzer.core_analyzer, story_generator)
    
    # Generate reports
    reports = report_generator.generate_all_reports()
    
    if reports:
        console.print(Panel(
            f"[green]Reports generated successfully![/green]\n\n"
            f"HTML Report: {reports.get('html', 'Not generated')}\n"
            f"PDF Report: {reports.get('pdf', 'Not generated')}",
            title="Report Generation Complete",
            border_style="green"
        ))
    else:
        console.print("[red]Failed to generate reports.[/red]")


if __name__ == "__main__":
    main()