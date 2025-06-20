"""
Transaction Story Generator for TRON Wallet Analyzer

This module generates narrative descriptions of wallet activity based on transaction data.
It creates human-readable stories that explain transaction patterns, wallet behaviors,
and potential insights.
"""

import os
from datetime import datetime
import pandas as pd
import numpy as np
from fpdf import FPDF
from reportlab.lib import colors
from reportlab.lib.pagesizes import letter
from reportlab.platypus import SimpleDocTemplate, Paragraph, Spacer, Table, TableStyle, Image
from reportlab.lib.styles import getSampleStyleSheet, ParagraphStyle
from reportlab.lib.units import inch
# Import weasyprint only when needed (it has complex dependencies)
# import weasyprint
import jinja2
import json
from pathlib import Path

# Token type descriptions for the narrative
TOKEN_TYPE_DESCRIPTIONS = {
    "Stablecoin": "a value-pegged cryptocurrency designed to minimize price volatility",
    "DeFi": "a token used in decentralized finance applications",
    "GameFi": "a token used in blockchain gaming and play-to-earn ecosystems",
    "Exchange": "a token issued by or primarily used on cryptocurrency exchanges",
    "NFT": "a non-fungible token representing unique digital assets",
    "Governance": "a token that grants voting rights in a decentralized protocol",
    "Utility": "a token that provides utility within a specific ecosystem",
    "Security": "a token representing ownership in an asset or enterprise",
    "Wrapped": "a token representing another cryptocurrency on the TRON blockchain",
    "Privacy": "a token with enhanced privacy and anonymization features",
    "Other": "a token with specialized or uncategorized functionality"
}

# Exchange descriptions
EXCHANGE_DESCRIPTIONS = {
    "Binance": "one of the world's largest cryptocurrency exchanges by trading volume",
    "Huobi": "a major global digital asset exchange based in Seychelles",
    "Poloniex": "a US-based cryptocurrency exchange",
    "KuCoin": "a global cryptocurrency exchange based in Seychelles",
    "OKX": "a Seychelles-based cryptocurrency exchange",
    "Kraken": "a US-based cryptocurrency exchange and bank",
    "Bitfinex": "a cryptocurrency exchange owned by iFinex Inc.",
    "Gate.io": "a global cryptocurrency exchange",
    "Bittrex": "a US-based cryptocurrency exchange",
    "Coinbase": "a publicly traded cryptocurrency exchange platform"
}

# Transaction type descriptions
TRANSACTION_TYPE_DESCRIPTIONS = {
    "TRX Transfer": "standard TRX cryptocurrency transfers",
    "Token Transfer": "transfers of TRC-10, TRC-20, or TRC-721 tokens",
    "Smart Contract": "interactions with decentralized applications or protocols",
    "DEX Trade": "trades executed on decentralized exchanges",
    "Staking/Freezing": "locking TRX to gain energy or bandwidth resources",
    "Voting": "participation in TRON's governance through Super Representative voting",
    "NFT Transaction": "transfers or minting of non-fungible tokens",
    "Account Creation": "creation of new TRON accounts",
    "Multi-signature": "transactions requiring multiple signatures for approval"
}

# Wallet type descriptions
WALLET_TYPE_DESCRIPTIONS = {
    "Personal": "an individual user's wallet for day-to-day transactions",
    "Exchange": "a wallet operated by a cryptocurrency exchange for user deposits and withdrawals",
    "Contract": "a smart contract address that hosts decentralized application functionality",
    "Mining Pool": "a wallet that distributes mining or staking rewards to participants",
    "Token Contract": "the main contract address for a specific token",
    "DEX": "a decentralized exchange contract that facilitates peer-to-peer trading",
    "Multisig": "a wallet requiring multiple signatures to approve transactions",
    "Liquidity Pool": "a smart contract that holds pairs of tokens to enable DEX trading",
    "Bridge": "a wallet facilitating cross-chain transactions between TRON and other blockchains"
}

class TransactionStoryGenerator:
    """Generates narrative descriptions of wallet activity based on transaction data."""

    def __init__(self, analyzer):
        """
        Initialize the Transaction Story Generator.

        Args:
            analyzer: TronWalletAnalyzer instance with processed data
        """
        self.analyzer = analyzer
        self.timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        self.templates_dir = Path("templates")
        self.results_dir = Path("results")

        # Create PDF directory if it doesn't exist
        self.pdf_dir = self.results_dir / "pdf"
        self.pdf_dir.mkdir(exist_ok=True)

        # Initialize Jinja2 environment for HTML templates
        self.jinja_env = jinja2.Environment(
            loader=jinja2.FileSystemLoader("templates"),
            autoescape=jinja2.select_autoescape(['html', 'xml'])
        )

    def _get_address_activity_summary(self, address_data):
        """
        Generate a narrative summary of an address's activity.

        Args:
            address_data: Dictionary with address analysis data

        Returns:
            String with narrative description
        """
        address = address_data.get("address", "Unknown")
        balance = float(address_data.get("balance_trx", 0))
        tx_count = int(address_data.get("transactions_count", 0))
        wallet_type = address_data.get("wallet_type", "Unknown")
        risk_score = float(address_data.get("risk_score", 0))
        sent_volume = float(address_data.get("sent_volume", 0))
        received_volume = float(address_data.get("received_volume", 0))

        # Start building the narrative
        narrative = []
        narrative.append(f"Address {address} appears to be {self._get_article_for_type(wallet_type)} {wallet_type.lower()} wallet")

        if wallet_type == "Exchange":
            exchange_name = address_data.get("exchange_name", "unknown exchange")
            if exchange_name in EXCHANGE_DESCRIPTIONS:
                narrative.append(f" associated with {exchange_name}, {EXCHANGE_DESCRIPTIONS[exchange_name]}")
            else:
                narrative.append(f" associated with {exchange_name}")

        narrative.append(f". It currently holds {balance:.2f} TRX")

        # Add transaction volume insights
        if tx_count > 0:
            narrative.append(f" and has been involved in {tx_count} analyzed transactions")

            if sent_volume > 0 or received_volume > 0:
                narrative.append(f", sending {sent_volume:.2f} TRX and receiving {received_volume:.2f} TRX")

                # Describe the balance of sends vs receives
                ratio = sent_volume / received_volume if received_volume > 0 else float('inf')
                if ratio > 2:
                    narrative.append(". This wallet primarily sends funds out")
                elif ratio < 0.5:
                    narrative.append(". This wallet primarily receives funds")
                else:
                    narrative.append(". This wallet has a balanced pattern of sending and receiving funds")
        else:
            narrative.append(" but shows no transaction activity in the analyzed period")

        # Add risk assessment if available
        if risk_score > 0:
            if risk_score > 70:
                narrative.append(f". The wallet has a high risk score of {risk_score}/100, suggesting potentially suspicious activity")
            elif risk_score > 30:
                narrative.append(f". The wallet has a moderate risk score of {risk_score}/100, showing some unusual patterns")
            else:
                narrative.append(f". The wallet has a low risk score of {risk_score}/100, suggesting normal activity")

        # Add additional insights based on patterns
        patterns = address_data.get("patterns", "")
        if patterns:
            if "frequent_amount" in patterns:
                narrative.append(". The wallet shows repeated transactions of the same amount, which may indicate automated payments")
            if "periodic" in patterns:
                narrative.append(". The wallet exhibits periodic transaction patterns, suggesting scheduled activity")

        return "".join(narrative)

    def _get_article_for_type(self, type_name):
        """Return the appropriate article (a/an) for a type name."""
        vowels = ('a', 'e', 'i', 'o', 'u')
        return 'an' if type_name.lower().startswith(vowels) else 'a'

    def _get_connection_narrative(self, connection_data):
        """
        Generate a narrative description of a connection between two addresses.

        Args:
            connection_data: Dictionary with connection details

        Returns:
            String with narrative description
        """
        from_address = connection_data.get("from_address", "Unknown")
        to_address = connection_data.get("to_address", "Unknown")
        trx_sent = float(connection_data.get("trx_sent", 0))
        trx_received = float(connection_data.get("trx_received", 0))
        sent_count = int(connection_data.get("sent_count", 0))
        received_count = int(connection_data.get("received_count", 0))
        strength = float(connection_data.get("strength", 0))
        token_transfers = connection_data.get("token_transfers", False)

        # Start building the narrative
        narrative = []

        if trx_sent > 0 and sent_count > 0:
            narrative.append(f"Address {from_address} sent {trx_sent:.2f} TRX to {to_address} across {sent_count} transactions")

        if trx_received > 0 and received_count > 0:
            if narrative:
                narrative.append(f" and received {trx_received:.2f} TRX in {received_count} transactions")
            else:
                narrative.append(f"Address {from_address} received {trx_received:.2f} TRX from {to_address} in {received_count} transactions")

        # Add token transfer information if available
        if token_transfers:
            token_types = connection_data.get("token_types", [])
            if token_types:
                token_list = ", ".join(token_types)
                narrative.append(f". The connection also involves transfers of {token_list} tokens")
            else:
                narrative.append(". The connection also involves token transfers")

        # Add connection strength assessment
        if strength > 0:
            if strength > 0.7:
                narrative.append(f". This is a strong connection (strength: {strength:.2f})")
            elif strength > 0.3:
                narrative.append(f". This is a moderate connection (strength: {strength:.2f})")
            else:
                narrative.append(f". This is a weak connection (strength: {strength:.2f})")

        # Add exchange information if available
        from_exchange = connection_data.get("from_exchange", False)
        to_exchange = connection_data.get("to_exchange", False)

        if from_exchange and to_exchange:
            narrative.append(". Both addresses are associated with exchanges, suggesting possible cross-exchange transfers")
        elif from_exchange:
            narrative.append(". The source address is associated with an exchange, suggesting a withdrawal")
        elif to_exchange:
            narrative.append(". The destination address is associated with an exchange, suggesting a deposit")

        return "".join(narrative)

    def _get_network_narrative(self):
        """
        Generate a narrative description of the overall network.

        Returns:
            String with narrative description
        """
        addresses = len(self.analyzer.addresses)
        connections = len(self.analyzer.connections)

        if not addresses:
            return "No addresses were analyzed."

        narrative = []
        narrative.append(f"The analysis covers {addresses} TRON addresses")

        if connections > 0:
            narrative.append(f" with {connections} connections between them")

        # Add information about wallet types
        wallet_types = {}
        address_data = getattr(self.analyzer, 'addresses_data', None) or getattr(self.analyzer, 'address_data', {})
        for addr in address_data.values():
            wallet_type = addr.get("heuristics", {}).get("wallet_type", "Unknown")
            if not wallet_type or wallet_type == "Unknown":
                wallet_type = addr.get("wallet_type", "Unknown")
            wallet_types[wallet_type] = wallet_types.get(wallet_type, 0) + 1

        if wallet_types:
            narrative.append(". The network consists of ")
            type_descriptions = []

            for wallet_type, count in wallet_types.items():
                percentage = (count / addresses) * 100
                type_descriptions.append(f"{count} {wallet_type.lower()} wallets ({percentage:.1f}%)")

            narrative.append(", ".join(type_descriptions))

        # Add information about transaction types
        tx_types = {}
        total_tx = 0

        for addr in address_data.values():
            tx_count = addr.get("transactions_count", 0)
            total_tx += tx_count

        if total_tx > 0:
            narrative.append(f". Across all addresses, {total_tx} transactions were analyzed")

        # Add exchange information if available
        exchanges = set()
        for addr in address_data.values():
            if addr.get("is_exchange", False) and addr.get("exchange_name"):
                exchanges.add(addr.get("exchange_name"))

        if exchanges:
            narrative.append(f". The network involves interactions with the following exchanges: {', '.join(exchanges)}")

        # Add token information if available
        tokens = set()
        for addr in address_data.values():
            addr_tokens = addr.get("tokens", [])
            for token in addr_tokens:
                if isinstance(token, dict) and token.get("name"):
                    tokens.add(token.get("name"))

        if tokens:
            narrative.append(f". The analyzed wallets interact with the following tokens: {', '.join(tokens)}")

        return "".join(narrative)

    def _get_wallet_recommendations(self, address_data):
        """
        Generate recommendations based on wallet activity.

        Args:
            address_data: Dictionary with address analysis data

        Returns:
            List of recommendation strings
        """
        recommendations = []
        risk_score = float(address_data.get("risk_score", 0))
        wallet_type = address_data.get("wallet_type", "Unknown")
        patterns = address_data.get("patterns", "")

        # Risk-based recommendations
        if risk_score > 70:
            recommendations.append("Exercise extreme caution when interacting with this wallet due to high-risk indicators")
            recommendations.append("Consider further investigation into the wallet's transaction history")
        elif risk_score > 30:
            recommendations.append("Review the wallet's transaction history before significant interactions")

        # Wallet type recommendations
        if wallet_type == "Exchange":
            recommendations.append("Remember that exchange wallets are custodial - you don't control the private keys")
        elif wallet_type == "Contract":
            recommendations.append("Verify the contract's functionality and reputation before interaction")
        elif wallet_type == "Personal":
            if "frequent_amount" in patterns:
                recommendations.append("Regular transaction patterns may indicate automated payments or subscription services")

        # General recommendations
        if float(address_data.get("balance_trx", 0)) > 10000:
            recommendations.append("Consider security best practices for wallets with significant TRX holdings")

        return recommendations

    def generate_narrative_summary(self):
        """
        Generate a comprehensive narrative summary of all analyzed wallets and connections.

        Returns:
            Dictionary with narrative text sections
        """
        
        # Check if analyzer has the required data (handles both address_data and addresses_data)
        address_data = None
        if hasattr(self.analyzer, 'addresses_data') and self.analyzer.addresses_data:
            address_data = self.analyzer.addresses_data
        elif hasattr(self.analyzer, 'address_data') and self.analyzer.address_data:
            address_data = self.analyzer.address_data
        
        if not address_data:
            return {
                "title": f"TRON Wallet Analysis Report - {datetime.now().strftime('%Y-%m-%d')}",
                "overview": "No addresses were analyzed or data is not available.",
                "addresses": [],
                "connections": [],
                "insights": ["No data available for analysis"],
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

        # Get network overview first
        network_overview = self._get_network_narrative()
        if not network_overview:
            network_overview = "No network data available for analysis"

        summary = {
            "title": f"TRON Wallet Analysis Report - {datetime.now().strftime('%Y-%m-%d')}",
            "overview": network_overview,
            "addresses": [],
            "connections": [],
            "insights": [],
            "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        }

        # Process each address
        for address, data in address_data.items():
            if not data.get("valid", False) or not data.get("exists", False):
                continue

            address_summary = {
                "address": address,
                "narrative": self._get_address_activity_summary(data),
                "recommendations": self._get_wallet_recommendations(data),
                "data": data
            }
            summary["addresses"].append(address_summary)

        # Process connections
        connections = getattr(self.analyzer, 'connections', [])
        for conn in connections:
            conn_summary = {
                "narrative": self._get_connection_narrative(conn),
                "data": conn
            }
            summary["connections"].append(conn_summary)

        # Generate insights
        insights = []

        # Network structure insights
        if len(summary["connections"]) > 0:
            if len(summary["addresses"]) > 2:
                avg_connections_per_address = len(summary["connections"]) / len(summary["addresses"])
                if avg_connections_per_address > 2:
                    insights.append("The network shows a high level of interconnectivity, suggesting a close-knit group of wallets")
                elif avg_connections_per_address < 0.5:
                    insights.append("The network shows limited interconnectivity, suggesting mostly isolated wallet activity")
        else:
            insights.append("No connections were found between the analyzed addresses")

        # Risk insights
        high_risk_count = sum(1 for addr in summary["addresses"] if float(addr["data"].get("risk_score", 0)) > 70)
        if high_risk_count > 0:
            percentage = (high_risk_count / len(summary["addresses"])) * 100
            insights.append(f"{high_risk_count} wallets ({percentage:.1f}%) show high-risk indicators that may warrant further investigation")

        # Exchange insights
        exchange_wallets = [addr for addr in summary["addresses"] if addr["data"].get("wallet_type") == "Exchange"]
        if exchange_wallets:
            insights.append(f"The network includes {len(exchange_wallets)} exchange wallets, suggesting regulated financial activity")

        # Add insights to summary
        summary["insights"] = insights

        return summary

    def generate_pdf_report(self, narrative_summary, output_base="tron_analysis"):
        """
        Generate a comprehensive PDF report with transaction stories.

        Args:
            narrative_summary: Dictionary with narrative data
            output_base: Base name for output file

        Returns:
            Path to the generated PDF file
        """
        # Set up the PDF document
        output_file = self.pdf_dir / f"{output_base}_story_{self.timestamp}.pdf"
        doc = SimpleDocTemplate(str(output_file), pagesize=letter)
        styles = getSampleStyleSheet()

        # Add custom styles
        custom_styles = {
            'ReportTitle': ParagraphStyle(
                'ReportTitle',
                parent=styles['Heading1'],
                fontSize=16,
                textColor=colors.darkblue,
                spaceAfter=12
            ),
            'ReportHeading2': ParagraphStyle(
                'ReportHeading2',
                parent=styles['Heading2'],
                fontSize=14,
                textColor=colors.darkblue,
                spaceAfter=10
            ),
            'ReportHeading3': ParagraphStyle(
                'ReportHeading3',
                parent=styles['Heading3'],
                fontSize=12,
                textColor=colors.darkblue,
                spaceAfter=8
            ),
            'ErrorText': ParagraphStyle(
                'ErrorText',
                parent=styles['Normal'],
                textColor=colors.red,
                fontSize=10
            ),
            'SuccessText': ParagraphStyle(
                'SuccessText',
                parent=styles['Normal'],
                textColor=colors.green,
                fontSize=10
            ),
            'WarningText': ParagraphStyle(
                'WarningText',
                parent=styles['Normal'],
                textColor=colors.orange,
                fontSize=10
            ),
            'InfoText': ParagraphStyle(
                'InfoText',
                parent=styles['Normal'],
                textColor=colors.blue,
                fontSize=10
            )
        }

        # Add styles directly to the stylesheet
        for style_name, style in custom_styles.items():
            styles.add(style)

        # Add more custom styles with try-except to handle already defined styles
        more_custom_styles = {
            'ReportNormal': {
                'parent': 'Normal',
                'fontSize': 10,
                'spaceAfter': 6
            },
            'ReportRecommendation': {
                'parent': 'Normal',
                'fontSize': 10,
                'textColor': colors.darkgreen,
                'leftIndent': 20,
                'spaceAfter': 6
            },
            'ReportAddress': {
                'parent': 'Code',
                'fontSize': 8,
                'textColor': colors.darkslategray
            },
            'ReportInsight': {
                'parent': 'Normal',
                'fontSize': 10,
                'textColor': colors.darkblue,
                'leftIndent': 20,
                'spaceAfter': 6
            },
             'ReportHeading4': {
                'parent': 'Heading4',
                'fontSize': 10,
                'textColor': colors.black,
                'spaceBefore': 6,
                'spaceAfter': 6
            }
        }

        for style_name, style_props in more_custom_styles.items():
            try:
                # Create style with all properties at once to avoid attribute errors
                style_kwargs = {
                    'name': style_name,
                    'parent': styles[style_props['parent']]
                }

                if 'fontSize' in style_props:
                    style_kwargs['fontSize'] = style_props['fontSize']
                if 'spaceAfter' in style_props:
                    style_kwargs['spaceAfter'] = style_props['spaceAfter']
                if 'leftIndent' in style_props:
                    style_kwargs['leftIndent'] = style_props['leftIndent']
                if 'textColor' in style_props:
                    style_kwargs['textColor'] = style_props['textColor']
                if 'bulletIndent' in style_props:
                    style_kwargs['bulletIndent'] = style_props['bulletIndent']

                new_style = ParagraphStyle(**style_kwargs)

                styles.add(new_style)
            except (KeyError, AssertionError):
                # Style already exists, just continue
                pass

        # Format JSON-style output with colors
        json_style = ParagraphStyle(
            'JsonStyle',
            parent=styles['Code'],
            fontSize=9,
            leftIndent=20,
            firstLineIndent=0,
            textColor=colors.black
        )

        # Build the document content
        content = []

        # Title
        content.append(Paragraph(narrative_summary["title"], styles["ReportTitle"]))
        content.append(Spacer(1, 0.25 * inch))

        # Overview
        content.append(Paragraph("Network Overview", styles["ReportHeading2"]))
        content.append(Paragraph(narrative_summary["overview"], styles["ReportNormal"]))
        content.append(Spacer(1, 0.25 * inch))

        # Key Insights
        if narrative_summary["insights"]:
            content.append(Paragraph("Key Insights", styles["ReportHeading2"]))
            for insight in narrative_summary["insights"]:
                content.append(Paragraph(f"• {insight}", styles["ReportInsight"]))
            content.append(Spacer(1, 0.25 * inch))

        # Address Stories
        content.append(Paragraph("Wallet Stories", styles["ReportHeading2"]))

        for addr in narrative_summary["addresses"]:
            content.append(Paragraph(f"Wallet: {addr['address']}", styles["ReportHeading3"]))
            content.append(Paragraph(addr["narrative"], styles["ReportNormal"]))

            # Add recommendations
            if addr["recommendations"]:
                content.append(Paragraph("Recommendations:", styles["ReportHeading3"]))
                for rec in addr["recommendations"]:
                    content.append(Paragraph(f"• {rec}", styles["ReportRecommendation"]))

                # Add color-coded transaction details
                if "data" in addr:
                    metrics = addr["data"].get("analysis", {}).get("metrics", {})

                    # Color code for transaction volumes
                    sent_volume = metrics.get("sent_volume", 0)
                    received_volume = metrics.get("received_volume", 0)

                    volume_data = []
                    volume_data.append(Paragraph("Transaction Volumes:", styles["ReportHeading4"]))
                    volume_data.append(Paragraph(
                        f"Sent: <font color='red'>{sent_volume:.2f}</font> TRX<br/>"
                        f"Received: <font color='green'>{received_volume:.2f}</font> TRX",
                        styles["ReportNormal"]
                    ))

                    # Color code for tokens
                    if "tokens_sent" in metrics:
                        token_data = []
                        token_data.append(Paragraph("Token Activity:", styles["ReportHeading4"]))
                        for token, amount in metrics["tokens_sent"].items():
                            token_data.append(Paragraph(
                                f"<font color='blue'>{token}</font>: {amount:,.2f}",
                                styles["ReportNormal"]
                            ))
                        content.extend(token_data)

                    content.extend(volume_data)

            content.append(Spacer(1, 0.15 * inch))

        # Connection Stories
        if narrative_summary["connections"]:
            content.append(Paragraph("Connection Stories", styles["ReportHeading2"]))

            for conn in narrative_summary["connections"]:
                content.append(Paragraph(conn["narrative"], styles["ReportNormal"]))

            content.append(Spacer(1, 0.25 * inch))

        # Build the PDF
        doc.build(content)

        return output_file

    def generate_html_report(self, narrative_summary, output_base="tron_analysis"):
        """
        Generate an HTML report with transaction stories.

        Args:
            narrative_summary: Dictionary with narrative data
            output_base: Base name for output file

        Returns:
            Path to the generated HTML file
        """
        if not narrative_summary or not isinstance(narrative_summary, dict):
            narrative_summary = {
                "title": f"TRON Wallet Analysis Report - {datetime.now().strftime('%Y-%m-%d')}",
                "overview": "No data available for analysis",
                "addresses": [],
                "connections": [],
                "insights": [],
                "timestamp": datetime.now().strftime("%Y-%m-%d %H:%M:%S")
            }

        # Ensure required keys exist
        required_keys = ["title", "overview", "addresses", "connections", "insights", "timestamp"]
        for key in required_keys:
            if key not in narrative_summary:
                narrative_summary[key] = "" if key in ["title", "overview", "timestamp"] else []

        # Create HTML template if it doesn't exist
        template_file = self.templates_dir / "transaction_story.html"
        if not template_file.exists():
            self._create_html_template()

        # Get the template
        template = self.jinja_env.get_template("transaction_story.html")

        # Render the template with the narrative data
        html_content = template.render(
            title=narrative_summary["title"],
            overview=narrative_summary["overview"],
            addresses=narrative_summary["addresses"],
            connections=narrative_summary["connections"],
            insights=narrative_summary["insights"],
            timestamp=narrative_summary["timestamp"]
        )

        # Write the HTML file
        output_file = self.pdf_dir / f"{output_base}_story_{self.timestamp}.html"
        with open(output_file, "w") as f:
            f.write(html_content)

        # Try to convert HTML to PDF using WeasyPrint
        pdf_output = self.pdf_dir / f"{output_base}_story_{self.timestamp}_weasy.pdf"

        try:
            # Import weasyprint at runtime to avoid loading dependencies on import
            import weasyprint
            weasyprint.HTML(string=html_content).write_pdf(pdf_output)
            return output_file, pdf_output
        except ImportError:
            print("WeasyPrint is not available. PDF generation skipped.")
            print("HTML report is still available at:", output_file)
            return output_file, None
        except Exception as e:
            print(f"Error generating PDF: {e}")
            return output_file, None

    def _create_html_template(self):
        """Create an HTML template for transaction story reports."""
        template_content = """<!DOCTYPE html>
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
        h1 {
            color: #2c3e50;
            border-bottom: 2px solid #3498db;
            padding-bottom: 10px;
        }
        h2 {
            color: #2980b9;
            margin-top: 30px;
        }
        h3 {
            color: #2980b9;
        }
        .section {
            margin-bottom: 30px;
        }
        .overview {
            background-color: #f8f9fa;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #3498db;
        }
        .address-card {
            background-color: #fff;
            border: 1px solid #e0e0e0;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 20px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .address-header {
            font-weight: bold;
            color: #2c3e50;
            margin-bottom: 10px;
        }
        .recommendations {
            background-color: #e8f4f8;
            padding: 10px 15px;
            border-radius: 5px;
            margin-top: 10px;
        }
        .recommendation-item {
            color: #16a085;
            margin: 5px 0;
        }
        .connection-card {
            background-color: #fff;
            border: 1px solid #e0e0e0;
            border-radius: 5px;
            padding: 15px;
            margin-bottom: 15px;
            box-shadow: 0 2px 5px rgba(0,0,0,0.1);
        }
        .insights {
            background-color: #f0f7fb;
            padding: 15px;
            border-radius: 5px;
            border-left: 4px solid #3498db;
            margin-bottom: 20px;
        }
        .insight-item {
            color: #2980b9;
            margin: 8px 0;
        }
        .footer {
            margin-top: 40px;
            text-align: center;
            font-size: 12px;
            color: #7f8c8d;
            border-top: 1px solid #e0e0e0;
            padding-top: 20px;
        }
        .address-code {
            font-family: monospace;
            font-size: 14px;
            background-color: #f5f5f5;
            padding: 2px 5px;
            border-radius: 3px;
        }
    </style>
</head>
<body>
    <div class="section">
        <h1>{{ title }}</h1>
        <div class="overview">
            <p>{{ overview }}</p>
        </div>
    </div>

    {% if insights %}
    <div class="section">
        <h2>Key Insights</h2>
        <div class="insights">
            <ul>
                {% for insight in insights %}
                <li class="insight-item">{{ insight }}</li>
                {% endfor %}
            </ul>
        </div>
    </div>
    {% endif %}

    <div class="section">
        <h2>Wallet Stories</h2>
        {% for address in addresses %}
        <div class="address-card">
            <div class="address-header">Wallet: <span class="address-code">{{ address.address }}</span></div>
            <p>{{ address.narrative }}</p>

            {% if address.recommendations %}
            <div class="recommendations">
                <h3>Recommendations:</h3>
                <ul>
                    {% for rec in address.recommendations %}
                    <li class="recommendation-item">{{ rec }}</li>
                    {% endfor %}
                </ul>
            </div>
            {% endif %}
        </div>
        {% endfor %}
    </div>

    {% if connections %}
    <div class="section">
        <h2>Connection Stories</h2>
        {% for conn in connections %}
        <div class="connection-card">
            <p>{{ conn.narrative }}</p>
        </div>
        {% endfor %}
    </div>
    {% endif %}

    <div class="footer">
        <p>Generated by TRON Wallet Analyzer on {{ timestamp }}</p>
        <p>This report provides a narrative interpretation of blockchain data and should not be considered financial advice.</p>
    </div>
</body>
</html>
"""
        # Ensure the templates directory exists
        self.templates_dir.mkdir(exist_ok=True)

        # Write the template file
        template_path = self.templates_dir / "transaction_story.html"
        with open(template_path, "w") as f:
            f.write(template_content)

def add_terminal_color_coding():
    """
    Add color coding to terminal output by updating the TronWalletAnalyzer display methods.
    """
    from rich.console import Console
    from rich.table import Table
    from rich.panel import Panel
    from rich.text import Text

    # Return the rich console object that can be used throughout the codebase
    return Console()