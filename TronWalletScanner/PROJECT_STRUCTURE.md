
# Project Structure

```
TronWalletScanner/
├── Core Analyzers/
│   ├── tron_wallet_analyzer.py          # Main TRON wallet analysis engine
│   ├── advanced_tron_analyzer.py        # Enhanced analysis with ML features
│   └── tron_master_analyzer.py          # Master analyzer with all features
│
├── Database Systems/
│   ├── exchanges_database.py            # Exchange address database
│   ├── malicious_addresses_database.py  # Malicious/scammer addresses
│   ├── token_classification_database.py # TRC20 token information
│   └── smart_contracts_database.py      # Verified smart contracts
│
├── Data Management/
│   ├── dataset_updater.py               # Automatic dataset updates from APIs
│   ├── dataset_integration.py           # Dataset integration system
│   ├── api_config.py                    # API configuration
│   └── threat_intelligence_feeds.py     # Security threat feeds
│
├── Analysis Features/
│   ├── ml_anomaly_detection.py          # Machine learning anomaly detection
│   └── transaction_story.py             # Transaction narrative generation
│
├── Visualization/
│   ├── clean_network_generator.py       # Interactive network graphs
│   ├── interactive_story_report.py      # Professional HTML reports
│   └── web_server.py                    # Local web server for viewing
│
├── Configuration/
│   ├── requirements.txt                 # Python dependencies
│   ├── main.py                          # Main entry point
│   └── sample_addresses.txt             # Sample TRON addresses
│
├── Assets/
│   ├── lib/                            # JavaScript libraries
│   └── templates/                       # HTML templates
│
├── Results/ (Generated at runtime)
│   ├── reports/                         # Text, JSON, Excel reports
│   └── visualizations/                  # Interactive HTML graphs
│
└── Documentation/
    ├── README.md                        # Main documentation
 
```
