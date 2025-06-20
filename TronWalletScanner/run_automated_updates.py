
#!/usr/bin/env python3
"""
Automated Dataset Updates Runner
Simple script to update all datasets with real-time data
"""

import sys
import os
from rich.console import Console
from rich.panel import Panel
from datetime import datetime

# Add the current directory to Python path
sys.path.append(os.path.dirname(os.path.abspath(__file__)))

console = Console()

def main():
    console.print(Panel(
        "[green]TRON Wallet Scanner - Automated Dataset Updater[/green]\n\n"
        "This script will update your datasets with real-time data from free APIs:\n"
        "• Malicious addresses from security feeds\n"
        "• Token information from CoinGecko\n"
        "• Exchange data from multiple sources\n"
        "• Smart contract information from TronScan\n"
        "• Threat intelligence from GitHub advisories",
        title="Dataset Updater",
        border_style="blue"
    ))
    
    try:
        # Test API connections first
        console.print("\n[blue]Testing API connections...[/blue]")
        from dataset_updater import DatasetUpdater
        
        updater = DatasetUpdater()
        
        # Quick API test
        test_results = {}
        for api_name in ['coingecko', 'tronscan']:
            try:
                if api_name == 'coingecko':
                    url = "https://api.coingecko.com/api/v3/ping"
                elif api_name == 'tronscan':
                    url = "https://api.tronscan.org/api/system/status"
                
                result = updater.safe_request(url, api_name)
                test_results[api_name] = "✅ Connected" if result else "❌ Failed"
            except:
                test_results[api_name] = "❌ Failed"
        
        for api, status in test_results.items():
            console.print(f"  {api}: {status}")
        
        # Run the update
        console.print("\n[green]Starting dataset update...[/green]")
        updater.run_full_update()
        
        # Run threat intelligence
        console.print("\n[blue]Fetching threat intelligence...[/blue]")
        from threat_intelligence_feeds import ThreatIntelligenceAggregator
        
        threat_intel = ThreatIntelligenceAggregator()
        analysis = threat_intel.analyze_new_threats()
        
        # Generate report
        report = threat_intel.generate_threat_report(analysis)
        timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
        
        with open(f'threat_report_{timestamp}.md', 'w') as f:
            f.write(report)
        
        console.print(f"[green]Threat intelligence report saved: threat_report_{timestamp}.md[/green]")
        
        console.print(Panel(
            "[green]✅ Dataset update completed successfully![/green]\n\n"
            f"• Updated at: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}\n"
            f"• New threats detected: {analysis['statistics']['tron_threats']}\n"
            f"• High priority alerts: {analysis['statistics']['high_priority']}\n"
            f"• Total entries processed: {analysis['statistics']['total_threats']}",
            title="Update Complete",
            border_style="green"
        ))
        
    except ImportError as e:
        console.print(f"[red]Import error: {e}[/red]")
        console.print("[yellow]Make sure all required packages are installed: pip install requests rich schedule[/yellow]")
    except Exception as e:
        console.print(f"[red]Error during update: {e}[/red]")

if __name__ == "__main__":
    main()
