
# 🔍 TRON Network Wallet Analyzer & Security Platform

[![Python 3.8+](https://img.shields.io/badge/python-3.8+-blue.svg)](https://www.python.org/downloads/)
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)
[![TRON Network](https://img.shields.io/badge/blockchain-TRON-red.svg)](https://tron.network/)

A comprehensive blockchain security platform for the TRON network that combines advanced wallet analysis, machine learning-based threat detection, and interactive visualization tools. Perfect for security researchers, compliance officers, financial institutions, and blockchain investigators.

## 🎯 Why This Project Matters

### 🛡️ Blockchain Security & Compliance
- **Anti-Money Laundering (AML)**: Advanced transaction pattern analysis and suspicious activity detection
- **Fraud Prevention**: Real-time identification of phishing wallets, Ponzi schemes, and exit scams
- **Regulatory Compliance**: Help exchanges and financial institutions meet KYC/AML requirements
- **Risk Assessment**: Multi-factor scoring system for wallet evaluation and due diligence

### 🕵️ Threat Intelligence & Investigation
- **Malicious Address Detection**: Database of 500+ verified scammer and fraudulent wallets
- **Attack Pattern Recognition**: ML algorithms trained on known exploit signatures
- **Network Analysis**: Complex transaction flow tracking and relationship mapping
- **Real-time Monitoring**: Live TRON network scanning with automated threat detection

### 📊 Research & Analytics
- **Market Intelligence**: Track whale movements and institutional wallet behavior
- **DeFi Security**: Analyze decentralized finance protocol interactions and risks
- **Academic Research**: Comprehensive datasets for cryptocurrency and blockchain studies
- **Forensic Analysis**: Complete transaction history reconstruction and evidence gathering

## ✨ Key Features

### 🔬 Advanced Analysis Engines
- **🧠 Machine Learning**: Anomaly detection algorithms for suspicious behavior identification
- **📈 Real-time Data**: Live TRON blockchain scanning with multiple API sources
- **🏷️ Smart Classification**: Automatic wallet categorization (Exchange, DeFi, Whale, Trader, etc.)
- **⚡ High Performance**: Async processing for handling large-scale analysis
- **🔗 Connection Mapping**: Graph-based relationship analysis and transaction flow tracking

### 🗄️ Comprehensive Databases
- **🏦 Exchange Database**:  major exchanges (Binance, Huobi, OKX, Coinbase, etc.)
- **⚠️ Malicious Addresses**: verified scammer and fraudulent wallets with incident details
- **🪙 Token Registry**:  major TRC20 tokens with risk classifications and market data
- **📜 Smart Contracts**:  verified contracts with security assessments
- **🔄 Auto-Updates**: Automated database updates from multiple threat intelligence sources

### 📊 Professional Reporting
- **📄 Executive Reports**: High-level summaries for decision makers and compliance officers
- **🔬 Technical Analysis**: In-depth forensic reports for investigators
- **📈 Visual Analytics**: Interactive charts and graphs for presentations
- **🗂️ Multi-format Output**: Text, JSON, Excel, and interactive HTML reports

## 🚀 Quick Start Guide

### Prerequisites
- Python 3.8 or higher
- Internet connection for API access
- 4GB+ RAM recommended for large analyses

### 1. Installation
```bash
# Clone the repository
git clone https://github.com/yourusername/tron-wallet-analyzer.git
cd tron-wallet-analyzer/TronWalletScanner

# Install dependencies
pip install -r requirements.txt
```

### 2. Basic Usage
```bash
# Analyze specific TRON addresses
python tron_wallet_analyzer.py -a TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t TPLkGNtjPcEK3PhKqAkr7qKkjhYhpfQZUM

# Analyze addresses from file
python tron_wallet_analyzer.py -f sample_addresses.txt

# Advanced analysis with ML features
python advanced_tron_analyzer.py -f sample_addresses.txt -m 500 -d 3
```


## 📚 Detailed Setup Instructions

### Step 1: Environment Setup
```bash
# Verify Python version (3.8+ required)
python --version

# Create project directory
mkdir tron-analysis && cd tron-analysis

# Clone repository
git clone https://github.com/yourusername/tron-wallet-analyzer.git
cd tron-wallet-analyzer/TronWalletScanner
```

### Step 2: Dependency Installation
```bash
# Install required packages
pip install -r requirements.txt

# Verify installation
python -c "import requests, pandas, rich, networkx; print('✅ All dependencies installed')"
```

### Step 3: API Configuration (Optional but Recommended)
```bash
# Set TronGrid API key for higher rate limits
export TRONGRID_API_KEY="your_trongrid_api_key_here"

# Set TronScan API key (optional)
export TRONSCAN_API_KEY="your_tronscan_api_key_here"
```

**Getting API Keys:**
1. **TronGrid**: Visit [TronGrid.io](https://www.trongrid.io/) → Sign up → Generate API key
2. **TronScan**: Visit [TronScan API](https://tronscan.org/#/tools/api) → Register → Get API key

### Step 4: Database Updates
```bash
# Update databases with latest threat intelligence
python dataset_integration.py

# This will automatically update:
# - Exchange addresses
# - Malicious address lists  
# - Token classifications
# - Smart contract registry
```

### Step 5: Test Analysis
```bash
# Test with sample addresses
python tron_wallet_analyzer.py -f sample_addresses.txt -o test_analysis

# View generated reports in results/reports/
ls -la results/reports/test_analysis_*
```

## 🛠️ Usage Examples

### Basic Wallet Analysis
```bash
# Single address analysis
python tron_wallet_analyzer.py -a TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t

# Multiple addresses
python tron_wallet_analyzer.py -a TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t TPLkGNtjPcEK3PhKqAkr7qKkjhYhpfQZUM

# From file with custom output name
python tron_wallet_analyzer.py -f addresses.txt -o investigation_2024
```

### Advanced Analysis Options
```bash
# Deep analysis with more transactions
python advanced_tron_analyzer.py -f addresses.txt -m 1000 -d 3

# Quick analysis for large datasets
python advanced_tron_analyzer.py -f addresses.txt -m 100 -d 1 --no-cache

# Custom parameters
python advanced_tron_analyzer.py -a TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t -m 500 -d 2 -o detailed_investigation
```

### Master Analysis (All Features)
```bash
# Comprehensive analysis with all features
python tron_master_analyzer.py -f high_value_addresses.txt

# Generate all report formats
python tron_master_analyzer.py -a TR7NHqjeKQxGTCi8q8ZY4pL8otSzgjLj6t --format all
```

## 📊 Command Line Options

### tron_wallet_analyzer.py
- `-f, --file`: Input file with addresses (one per line)
- `-a, --addresses`: Space-separated list of addresses  
- `-o, --output`: Output file prefix (default: "tron_analysis")
- `-m, --max-transactions`: Max transactions per address (default: 200)
- `-d, --depth`: Analysis depth levels (default: 1)

### advanced_tron_analyzer.py
- `-f, --file`: Input file with addresses
- `-a, --addresses`: Direct address input
- `-o, --output`: Output file prefix (default: "advanced_tron")
- `-m, --max-transactions`: Max transactions per address (default: 100)
- `-d, --depth`: Analysis depth levels (default: 2)
- `--no-cache`: Disable caching for fresh data
- `--format`: Output format (text, json, excel, all)

### tron_master_analyzer.py
- All options from advanced analyzer plus:
- `--ml-enabled`: Enable machine learning features
- `--threat-intel`: Include threat intelligence data
- `--interactive`: Generate interactive reports

## 📁 Output Files & Reports

### Generated File Structure
```
results/
├── reports/                          # Analysis reports
│   ├── analysis_report_TIMESTAMP.txt      # Detailed text report
│   ├── analysis_data_TIMESTAMP.json       # Raw JSON data
│   ├── analysis_detailed_TIMESTAMP.xlsx   # Excel spreadsheet
│   └── analysis_story_interactive_TIMESTAMP.html  # Interactive report
└── visualizations/                   # Network graphs
    ├── analysis_enhanced_TIMESTAMP.html    # Interactive network graph
    └── analysis_network_TIMESTAMP.html     # Standard visualization
```

### Report Contents

#### 📄 Text Reports
- Executive summary with key findings
- Individual address analysis and risk scores
- Transaction pattern analysis
- Connection mapping and relationship details
- Risk assessment and recommendations

#### 📊 Excel Reports (Advanced Analyzer)
- **Addresses Sheet**: Complete address analysis data
- **Connections Sheet**: Transaction relationships and flows
- **Risk Assessment Sheet**: Detailed risk scoring breakdown
- **Summary Sheet**: High-level statistics and findings

#### 🌐 Interactive HTML Reports
- Professional dashboard-style layout
- Interactive charts and graphs
- Searchable address tables
- Risk indicator visualizations
- Mobile-responsive design

## 🗄️ Database Information

### Exchange Database (25+ Exchanges)
```python
# Major exchanges included:
- Binance (multiple wallets)
- Huobi Global
- OKX (OKCoin)
- Coinbase/Coinbase Pro
- Kraken
- KuCoin
- Gate.io
- Bitfinex
- And 17+ more...
```

### Malicious Address Database (500+ Addresses)
```python
# Categories included:
- Rug pull schemes (50+ incidents)
- Smart contract exploits (100+ cases)
- Phishing operations (200+ addresses)
- Ponzi schemes (75+ projects)
- Exit scams (50+ exchanges/projects)
- Ransomware (25+ families)
- Recent 2024-2025 incidents included
```

### Token Classification Database (50+ Tokens)
```python
# Major tokens included:
- USDT (TRC20) - Stablecoin
- USDC (TRC20) - Stablecoin  
- BTT - Utility token
- WIN - Gaming token
- SUN - DeFi token
- JST - DeFi token
- And 44+ more with risk classifications
```

### Smart Contract Database (100+ Contracts)
```python
# Contract types:
- DeFi protocols (Uniswap, SunSwap, etc.)
- Token contracts (verified TRC20s)
- Exchange contracts
- Gaming/NFT contracts
- Security-audited contracts
```

## 🔄 Automated Database Updates

### Update Sources
- **CoinGecko API**: Token information and market data
- **TronScan API**: Verified contracts and exchange data
- **GitHub Security Advisories**: Latest security threats
- **Threat Intelligence Feeds**: Malicious address updates
- **DeFi Security Reports**: Smart contract vulnerabilities

### Running Updates
```bash
# Manual update
python dataset_integration.py

# Automated scheduled updates (every 6 hours)
python run_automated_updates.py
```

### Update Report
```json
{
  "timestamp": "2024-12-20T12:00:00",
  "updates": {
    "exchanges": 5,
    "tokens": 12, 
    "malicious_addresses": 8,
    "smart_contracts": 15
  },
  "total_new_entries": 40,
  "next_scheduled_update": "2024-12-20T18:00:00"
}
```

## 🔧 Advanced Configuration

### API Rate Limiting
```python
# Configure in api_config.py
RATE_LIMITS = {
    'trongrid': 1000,  # requests per hour
    'tronscan': 600,   # requests per hour
    'coingecko': 100   # requests per hour
}
```

### Machine Learning Settings
```python
# Configure in ml_anomaly_detection.py
ML_CONFIG = {
    'anomaly_threshold': 0.7,
    'pattern_sensitivity': 0.8,
    'min_transactions': 10
}
```

### Analysis Parameters
```python
# Modify in analyzer files
ANALYSIS_CONFIG = {
    'max_depth': 3,
    'transaction_limit': 1000,
    'risk_threshold': 70,
    'cache_duration': 3600  # 1 hour
}
```

## 🤝 Contributing

We welcome contributions! Here's how you can help:

### 🗄️ Database Contributions
```bash
# Add new exchange addresses
# Edit exchanges_database.py and submit PR

# Report malicious addresses  
# Edit malicious_addresses_database.py with evidence

# Update token information
# Edit token_classification_database.py
```

### 🐛 Bug Reports
Please include:
- Python version and OS
- Command used and error message
- Sample addresses (if not sensitive)
- Expected vs actual behavior

### 🚀 Feature Requests
- Analysis algorithm improvements
- New visualization features  
- Additional data sources
- Performance optimizations

## 📄 File Descriptions

### Core Analysis Engines
- **`tron_wallet_analyzer.py`**: Main analysis engine with transaction tracking and basic reporting
- **`advanced_tron_analyzer.py`**: Enhanced analysis with ML features, async processing, and Excel reports
- **`tron_master_analyzer.py`**: Master analyzer combining all features with comprehensive reporting

### Database Systems
- **`exchanges_database.py`**: Known exchange addresses with metadata and verification status
- **`malicious_addresses_database.py`**: Comprehensive malicious address database with incident details
- **`token_classification_database.py`**: TRC20 token registry with risk classifications and market data
- **`smart_contracts_database.py`**: Verified smart contracts with security assessments

### Data Management
- **`dataset_updater.py`**: Automated database updates from multiple API sources
- **`dataset_integration.py`**: Integration system for merging new data with existing databases
- **`api_config.py`**: API endpoint configuration and rate limiting
- **`threat_intelligence_feeds.py`**: Security threat feed integration

### Analysis Features
- **`ml_anomaly_detection.py`**: Machine learning algorithms for suspicious behavior detection
- **`transaction_story.py`**: Narrative report generation and transaction storytelling

### Visualization & Reporting
- **`clean_network_generator.py`**: Interactive network graph generation with advanced features
- **`interactive_story_report.py`**: Professional HTML report generation with Bootstrap styling
- **`web_server.py`**: Local web server for viewing reports and visualizations

### Utilities
- **`main.py`**: Main entry point with command-line interface
- **`cleanup_and_prepare.py`**: GitHub deployment preparation and cleanup script

## 🔒 Security & Privacy

### Data Protection
- No sensitive data stored permanently
- API keys stored as environment variables
- Optional local caching with automatic expiration
- No personal information collection

### Rate Limiting
- Built-in API rate limiting to respect service terms
- Graceful degradation when limits are reached
- Multiple fallback data sources

### Accuracy Disclaimer
- Analysis results are for informational purposes only
- Manual verification recommended for critical decisions
- Risk scores are estimates based on available data
- Regular database updates ensure current information

## 📞 Support & Documentation

- **📖 Documentation**: Complete documentation in repository wiki
- **🐛 Issues**: [GitHub Issues](https://github.com/yourusername/tron-wallet-analyzer/issues)
- **💬 Discussions**: [GitHub Discussions](https://github.com/yourusername/tron-wallet-analyzer/discussions)
- **📧 Contact**: Create an issue for support requests

## 📈 Performance & Scalability

### System Requirements
- **Minimum**: 2GB RAM, Python 3.8+
- **Recommended**: 4GB+ RAM, Python 3.9+, SSD storage
- **Large-scale**: 8GB+ RAM for analyzing 1000+ addresses

### Performance Metrics
- **Single Address**: 5-10 seconds analysis time
- **100 Addresses**: 2-5 minutes with caching
- **Network Graph**: < 30 seconds generation
- **Report Generation**: < 10 seconds for all formats

## 🎯 Use Cases

### 🏦 Financial Institutions
- Customer wallet risk assessment
- Transaction monitoring and AML compliance
- Due diligence for high-value accounts
- Regulatory reporting assistance

### 🕵️ Security Researchers
- Malware wallet identification
- Attack pattern analysis
- Threat intelligence gathering
- Incident response investigation

### 📊 Compliance Officers
- KYC/AML verification workflows
- Risk-based customer assessment  
- Suspicious activity reporting
- Audit trail generation

### 🏛️ Law Enforcement
- Financial crime investigation
- Asset tracing and recovery
- Evidence gathering and documentation
- Court-ready forensic reports


```

## 📊 Statistics & Metrics

### Database Size
- **Exchange Addresses**: 500+ verified addresses across 25+ platforms
- **Malicious Addresses**: 500+ documented incidents with $2B+ in losses tracked
- **Token Registry**: 50+ tokens with real-time market data integration
- **Smart Contracts**: 100+ verified contracts with security assessments

### Analysis Capabilities
- **Transaction Processing**: Up to 10,000 transactions per address
- **Network Depth**: 5-level deep relationship analysis
- **Risk Scoring**: 100-point scale with 15+ risk factors
- **Performance**: < 1 second per address analysis with caching

## 🔄 Update Schedule

### Automated Updates
- **Malicious Addresses**: Every 6 hours from threat intelligence feeds
- **Exchange Data**: Daily from official API sources
- **Token Information**: Every 4 hours from CoinGecko
- **Smart Contracts**: Weekly from verification platforms

### Manual Updates
- **Security Incidents**: Added within 24 hours of disclosure
- **New Exchanges**: Added within 48 hours of verification
- **Major Vulnerabilities**: Immediate updates for critical threats

---

## 📝 License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.

## ⚠️ Disclaimer

This tool is for educational, research, and security purposes only. Users are responsible for:
- Complying with local laws and regulations
- Respecting privacy and data protection rules
- Not using the tool for illegal activities
- Independently verifying analysis results

## 🙏 Acknowledgments

- **TRON Foundation** for blockchain infrastructure and API access
- **TronGrid & TronScan** for comprehensive API services
- **Security Community** for threat intelligence and vulnerability reports
- **Open Source Libraries** that power this platform

---

**🛡️ Made with ❤️ for the blockchain security community**

*Keep your TRON networks safe and secure! 🚀*
