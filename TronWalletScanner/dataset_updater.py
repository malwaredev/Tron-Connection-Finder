
#!/usr/bin/env python3
"""
Automated Dataset Updater - Real-time updates from free APIs
Updates malicious addresses, tokens, exchanges, and smart contracts databases
"""

import requests
import json
import time
import schedule
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
import logging
from rich.console import Console
from rich.progress import track

console = Console()

# Configure logging
logging.basicConfig(
    level=logging.INFO,
    format='%(asctime)s - %(levelname)s - %(message)s',
    handlers=[
        logging.FileHandler('dataset_updates.log'),
        logging.StreamHandler()
    ]
)

class DatasetUpdater:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'TRON-Wallet-Scanner/1.0'
        })
        
        # API endpoints (all free)
        self.apis = {
            'coingecko': 'https://api.coingecko.com/api/v3',
            'tronscan': 'https://api.tronscan.org/api',
            'trongrid': 'https://api.trongrid.io',
            'cryptocompare': 'https://min-api.cryptocompare.com/data',
            'coinmarketcap': 'https://pro-api.coinmarketcap.com/v1',  # Free tier
            'github_advisories': 'https://api.github.com/advisories',
            'defipulse': 'https://data-api.defipulse.com/api/v1',
            'chainalysis': 'https://public.chainalysis.com/api/v1',  # Public endpoints
            'misttrack': 'https://openapi.misttrack.io/v1'  # Some free endpoints
        }
        
        # Rate limiting (requests per minute)
        self.rate_limits = {
            'coingecko': 10,  # 10-50 depending on tier
            'tronscan': 60,   # Generally generous
            'trongrid': 60,
            'cryptocompare': 100,
            'github_advisories': 60
        }
        
        self.last_requests = {}
        
    def rate_limit_check(self, api_name: str):
        """Ensure we don't exceed rate limits"""
        current_time = time.time()
        if api_name in self.last_requests:
            time_diff = current_time - self.last_requests[api_name]
            min_interval = 60 / self.rate_limits.get(api_name, 10)
            if time_diff < min_interval:
                sleep_time = min_interval - time_diff
                time.sleep(sleep_time)
        
        self.last_requests[api_name] = current_time
    
    def safe_request(self, url: str, api_name: str = 'unknown', params: dict = None) -> Optional[dict]:
        """Make rate-limited API request with error handling"""
        try:
            self.rate_limit_check(api_name)
            response = self.session.get(url, params=params, timeout=30)
            response.raise_for_status()
            return response.json()
        except requests.exceptions.RequestException as e:
            logging.error(f"API request failed for {url}: {e}")
            return None
        except json.JSONDecodeError as e:
            logging.error(f"JSON decode error for {url}: {e}")
            return None
    
    def update_exchange_data(self) -> Dict[str, Any]:
        """Update exchange addresses from multiple sources"""
        console.print("[blue]Updating exchange data...[/blue]")
        
        new_exchanges = {}
        
        # CoinGecko exchanges
        exchanges_url = f"{self.apis['coingecko']}/exchanges"
        exchanges_data = self.safe_request(exchanges_url, 'coingecko')
        
        if exchanges_data:
            for exchange in exchanges_data[:50]:  # Top 50 exchanges
                if 'tron' in exchange.get('name', '').lower() or 'trx' in exchange.get('name', '').lower():
                    new_exchanges[exchange['id']] = {
                        'name': exchange['name'],
                        'trust_score': exchange.get('trust_score', 0),
                        'year_established': exchange.get('year_established'),
                        'country': exchange.get('country'),
                        'url': exchange.get('url'),
                        'has_trading_incentive': exchange.get('has_trading_incentive', False),
                        'source': 'coingecko',
                        'last_updated': datetime.now().isoformat()
                    }
        
        # TronScan known exchanges
        tronscan_url = f"{self.apis['tronscan']}/contracts"
        tronscan_data = self.safe_request(tronscan_url, 'tronscan', {'limit': 100})
        
        if tronscan_data and 'data' in tronscan_data:
            for contract in tronscan_data['data']:
                if contract.get('tag', {}).get('tagType') == 'Exchange':
                    address = contract['address']
                    new_exchanges[address] = {
                        'name': contract.get('tag', {}).get('tagName', 'Unknown Exchange'),
                        'address': address,
                        'type': 'exchange_contract',
                        'verified': True,
                        'source': 'tronscan',
                        'last_updated': datetime.now().isoformat()
                    }
        
        return new_exchanges
    
    def update_token_data(self) -> Dict[str, Any]:
        """Update token classification data"""
        console.print("[blue]Updating token data...[/blue]")
        
        new_tokens = {}
        
        # CoinGecko TRON tokens
        tokens_url = f"{self.apis['coingecko']}/coins/markets"
        params = {
            'vs_currency': 'usd',
            'category': 'tron-ecosystem',
            'order': 'market_cap_desc',
            'per_page': 100,
            'page': 1
        }
        
        tokens_data = self.safe_request(tokens_url, 'coingecko', params)
        
        if tokens_data:
            for token in tokens_data:
                # Extract TRON contract address if available
                contract_address = None
                if 'platforms' in token and 'tron' in token['platforms']:
                    contract_address = token['platforms']['tron']
                
                if contract_address:
                    risk_score = self.calculate_token_risk(token)
                    
                    new_tokens[contract_address] = {
                        'symbol': token['symbol'].upper(),
                        'name': token['name'],
                        'market_cap': token.get('market_cap', 0),
                        'volume_24h': token.get('total_volume', 0),
                        'price_change_24h': token.get('price_change_percentage_24h', 0),
                        'risk_score': risk_score,
                        'classification': self.classify_token_risk(risk_score),
                        'coingecko_id': token['id'],
                        'last_updated': datetime.now().isoformat(),
                        'source': 'coingecko'
                    }
        
        return new_tokens
    
    def calculate_token_risk(self, token_data: dict) -> int:
        """Calculate risk score based on token metrics"""
        risk_score = 0
        
        # Market cap risk
        market_cap = token_data.get('market_cap', 0)
        if market_cap < 100000:  # Less than 100k
            risk_score += 30
        elif market_cap < 1000000:  # Less than 1M
            risk_score += 20
        elif market_cap < 10000000:  # Less than 10M
            risk_score += 10
        
        # Volume risk
        volume = token_data.get('total_volume', 0)
        if volume < 10000:  # Very low volume
            risk_score += 25
        elif volume < 100000:
            risk_score += 15
        
        # Price volatility risk
        price_change = abs(token_data.get('price_change_percentage_24h', 0))
        if price_change > 50:  # High volatility
            risk_score += 20
        elif price_change > 20:
            risk_score += 10
        
        # Age risk (newer tokens are riskier)
        # This would need additional API calls to get token age
        
        return min(risk_score, 100)
    
    def classify_token_risk(self, risk_score: int) -> str:
        """Classify token based on risk score"""
        if risk_score >= 70:
            return 'high_risk'
        elif risk_score >= 40:
            return 'medium_risk'
        elif risk_score >= 20:
            return 'low_risk'
        else:
            return 'minimal_risk'
    
    def update_malicious_addresses(self) -> Dict[str, Any]:
        """Update malicious addresses from security feeds"""
        console.print("[blue]Updating malicious addresses...[/blue]")
        
        new_malicious = {}
        
        # GitHub Security Advisories
        advisories_url = f"{self.apis['github_advisories']}"
        params = {
            'ecosystem': 'cryptocurrency',
            'per_page': 100
        }
        
        advisories_data = self.safe_request(advisories_url, 'github_advisories', params)
        
        if advisories_data:
            for advisory in advisories_data:
                # Extract TRON addresses from advisory descriptions
                description = advisory.get('description', '') + ' ' + advisory.get('summary', '')
                tron_addresses = self.extract_tron_addresses(description)
                
                for address in tron_addresses:
                    new_malicious[address] = {
                        'type': 'security_advisory',
                        'description': advisory.get('summary', 'Security vulnerability'),
                        'severity': advisory.get('severity', 'medium'),
                        'published_at': advisory.get('published_at'),
                        'source': 'github_advisories',
                        'advisory_id': advisory.get('ghsa_id'),
                        'risk_level': self.map_severity_to_risk(advisory.get('severity')),
                        'last_updated': datetime.now().isoformat()
                    }
        
        # TODO: Add more sources like:
        # - Chainalysis public sanctions list
        # - MistTrack free endpoints
        # - DeFiPulse hack reports
        
        return new_malicious
    
    def extract_tron_addresses(self, text: str) -> List[str]:
        """Extract TRON addresses from text using regex"""
        import re
        # TRON address pattern: starts with T, 34 characters, base58
        pattern = r'\bT[1-9A-HJ-NP-Za-km-z]{33}\b'
        return re.findall(pattern, text)
    
    def map_severity_to_risk(self, severity: str) -> str:
        """Map GitHub advisory severity to our risk levels"""
        severity_map = {
            'critical': 'very_high',
            'high': 'high',
            'moderate': 'medium',
            'low': 'low'
        }
        return severity_map.get(severity, 'medium')
    
    def update_smart_contracts(self) -> Dict[str, Any]:
        """Update smart contract database"""
        console.print("[blue]Updating smart contracts...[/blue]")
        
        new_contracts = {}
        
        # TronScan verified contracts
        contracts_url = f"{self.apis['tronscan']}/contracts"
        params = {
            'limit': 200,
            'verified': True
        }
        
        contracts_data = self.safe_request(contracts_url, 'tronscan', params)
        
        if contracts_data and 'data' in contracts_data:
            for contract in contracts_data['data']:
                address = contract['address']
                new_contracts[address] = {
                    'name': contract.get('name', 'Unknown Contract'),
                    'compiler_version': contract.get('compiler_version'),
                    'verification_status': 'verified',
                    'source_code_available': True,
                    'creation_date': contract.get('date_created'),
                    'transaction_count': contract.get('trxCount', 0),
                    'source': 'tronscan_verified',
                    'last_updated': datetime.now().isoformat()
                }
        
        return new_contracts
    
    def merge_with_existing_database(self, new_data: Dict[str, Any], database_file: str):
        """Merge new data with existing database"""
        try:
            # Read existing database
            with open(database_file, 'r') as f:
                content = f.read()
            
            # Find the dictionary variable and update it
            # This is a simplified approach - in production, you'd want more robust parsing
            updated_content = self.update_database_content(content, new_data, database_file)
            
            # Write back to file
            with open(database_file, 'w') as f:
                f.write(updated_content)
                
            logging.info(f"Updated {database_file} with {len(new_data)} new entries")
            
        except Exception as e:
            logging.error(f"Failed to update {database_file}: {e}")
    
    def update_database_content(self, content: str, new_data: Dict[str, Any], database_file: str) -> str:
        """Update database file content with new data"""
        # This is a simplified implementation
        # In production, you'd want to use AST manipulation or similar
        
        if 'malicious_addresses_database.py' in database_file:
            # Add new malicious addresses
            insert_point = content.find('# ================== Recent High-Profile Cases ==================')
            if insert_point != -1:
                new_entries = self.format_malicious_entries(new_data)
                content = content[:insert_point] + new_entries + '\n    ' + content[insert_point:]
        
        # Add timestamp comment
        timestamp_comment = f"# Last auto-update: {datetime.now().isoformat()}\n"
        content = timestamp_comment + content
        
        return content
    
    def format_malicious_entries(self, new_data: Dict[str, Any]) -> str:
        """Format new malicious addresses for database file"""
        entries = []
        for address, data in new_data.items():
            entry = f'''    
    # Auto-detected from {data['source']}
    "{address}": {{
        "type": "{data['type']}",
        "description": "{data['description']}",
        "risk_level": "{data['risk_level']}",
        "first_seen": "{data['last_updated']}",
        "source": "{data['source']}",
        "is_active": True,
        "estimated_losses": 0,
        "victim_count": 0,
        "attack_vector": "automated_detection",
        "year": {datetime.now().year},
        "exploit_name": "Auto-detected Threat"
    }},'''
            entries.append(entry)
        
        return '\n'.join(entries)
    
    def run_full_update(self):
        """Run complete database update"""
        console.print("[green]Starting full database update...[/green]")
        
        try:
            # Update each database
            updates = {}
            
            updates['exchanges'] = self.update_exchange_data()
            updates['tokens'] = self.update_token_data()
            updates['malicious'] = self.update_malicious_addresses()
            updates['contracts'] = self.update_smart_contracts()
            
            # Merge with existing databases
            database_files = {
                'exchanges': 'exchanges_database.py',
                'tokens': 'token_classification_database.py',
                'malicious': 'malicious_addresses_database.py',
                'contracts': 'smart_contracts_database.py'
            }
            
            for update_type, new_data in updates.items():
                if new_data:
                    self.merge_with_existing_database(new_data, database_files[update_type])
            
            # Generate update report
            self.generate_update_report(updates)
            
            console.print("[green]Database update completed successfully![/green]")
            
        except Exception as e:
            logging.error(f"Database update failed: {e}")
            console.print(f"[red]Update failed: {e}[/red]")
    
    def generate_update_report(self, updates: Dict[str, Dict]):
        """Generate update report"""
        report = {
            'timestamp': datetime.now().isoformat(),
            'updates': {
                'exchanges': len(updates.get('exchanges', {})),
                'tokens': len(updates.get('tokens', {})),
                'malicious_addresses': len(updates.get('malicious', {})),
                'smart_contracts': len(updates.get('contracts', {}))
            },
            'total_new_entries': sum(len(data) for data in updates.values()),
            'next_scheduled_update': (datetime.now() + timedelta(hours=6)).isoformat()
        }
        
        with open('dataset_update_report.json', 'w') as f:
            json.dump(report, f, indent=2)
        
        console.print(f"[green]Update report saved. Total new entries: {report['total_new_entries']}[/green]")

def run_scheduled_update():
    """Function to run scheduled updates"""
    updater = DatasetUpdater()
    updater.run_full_update()

def setup_scheduler():
    """Setup automatic updates"""
    # Schedule updates every 6 hours
    schedule.every(6).hours.do(run_scheduled_update)
    
    # Schedule daily full update at 2 AM
    schedule.every().day.at("02:00").do(run_scheduled_update)
    
    console.print("[green]Scheduler configured: Updates every 6 hours + daily at 2 AM[/green]")

if __name__ == "__main__":
    import argparse
    
    parser = argparse.ArgumentParser(description="TRON Dataset Updater")
    parser.add_argument('--update-now', action='store_true', help='Run update immediately')
    parser.add_argument('--schedule', action='store_true', help='Start scheduled updates')
    parser.add_argument('--test-apis', action='store_true', help='Test API connections')
    
    args = parser.parse_args()
    
    updater = DatasetUpdater()
    
    if args.test_apis:
        console.print("[blue]Testing API connections...[/blue]")
        # Test each API
        for api_name, base_url in updater.apis.items():
            test_url = f"{base_url}/"
            result = updater.safe_request(test_url, api_name)
            status = "✅ Working" if result else "❌ Failed"
            console.print(f"{api_name}: {status}")
    
    elif args.update_now:
        updater.run_full_update()
    
    elif args.schedule:
        setup_scheduler()
        console.print("[blue]Starting scheduled updates...[/blue]")
        while True:
            schedule.run_pending()
            time.sleep(60)  # Check every minute
    
    else:
        console.print("Use --update-now, --schedule, or --test-apis")
