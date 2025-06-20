
#!/usr/bin/env python3
"""
Threat Intelligence Feeds - Aggregate security data from multiple free sources
Real-time threat intelligence for TRON ecosystem
"""

import requests
import json
import re
from datetime import datetime, timedelta
from typing import Dict, List, Any, Optional
from rich.console import Console
import logging

console = Console()

class ThreatIntelligenceAggregator:
    def __init__(self):
        self.session = requests.Session()
        self.session.headers.update({
            'User-Agent': 'TRON-Security-Scanner/1.0'
        })
        
        # Free threat intelligence sources
        self.feeds = {
            'github_advisories': 'https://api.github.com/advisories',
            'nvd_cve': 'https://services.nvd.nist.gov/rest/json/cves/2.0',
            'cryptoscamdb': 'https://api.cryptoscamdb.org/v1',
            'phishfort': 'https://api.phishfort.com/v2',  # Some free endpoints
            'certstream': 'https://certstream.calidog.io',  # Certificate transparency
            'urlvoid': 'https://api.urlvoid.com/v1',  # Free tier available
            'abuseipdb': 'https://api.abuseipdb.com/api/v2',  # Free tier
            'otx_alienvault': 'https://otx.alienvault.com/api/v1',  # Free
            'blockchain_info': 'https://blockchain.info/api',  # Free Bitcoin data
            'etherscan_labels': 'https://api.etherscan.io/api',  # Free tier
        }
        
        # Regex patterns for crypto addresses
        self.address_patterns = {
            'tron': r'\bT[1-9A-HJ-NP-Za-km-z]{33}\b',
            'bitcoin': r'\b[13][a-km-zA-HJ-NP-Z1-9]{25,34}\b',
            'ethereum': r'\b0x[a-fA-F0-9]{40}\b',
        }
    
    def fetch_github_crypto_advisories(self) -> List[Dict[str, Any]]:
        """Fetch cryptocurrency-related security advisories from GitHub"""
        console.print("[blue]Fetching GitHub security advisories...[/blue]")
        
        advisories = []
        url = f"{self.feeds['github_advisories']}"
        
        # Search for crypto-related advisories
        crypto_keywords = ['cryptocurrency', 'blockchain', 'defi', 'smart contract', 
                          'wallet', 'exchange', 'tron', 'bitcoin', 'ethereum']
        
        for keyword in crypto_keywords:
            try:
                params = {
                    'per_page': 100,
                    'ecosystem': 'npm'  # Many crypto projects use npm
                }
                
                response = self.session.get(url, params=params, timeout=30)
                response.raise_for_status()
                data = response.json()
                
                for advisory in data:
                    summary = advisory.get('summary', '').lower()
                    description = advisory.get('description', '').lower()
                    
                    if any(kw in summary or kw in description for kw in crypto_keywords):
                        # Extract crypto addresses from the advisory
                        full_text = summary + ' ' + description
                        addresses = self.extract_all_crypto_addresses(full_text)
                        
                        advisories.append({
                            'id': advisory.get('ghsa_id'),
                            'summary': advisory.get('summary'),
                            'severity': advisory.get('severity'),
                            'published_at': advisory.get('published_at'),
                            'updated_at': advisory.get('updated_at'),
                            'addresses_found': addresses,
                            'source': 'github_advisories'
                        })
                
                # Rate limiting
                import time
                time.sleep(1)
                
            except Exception as e:
                logging.error(f"Error fetching GitHub advisories for {keyword}: {e}")
        
        return advisories
    
    def fetch_cryptoscam_database(self) -> List[Dict[str, Any]]:
        """Fetch known scam addresses from CryptoScam DB"""
        console.print("[blue]Fetching CryptoScam database...[/blue]")
        
        scams = []
        try:
            # Get recent scam reports
            url = f"{self.feeds['cryptoscamdb']}/scams"
            response = self.session.get(url, timeout=30)
            response.raise_for_status()
            data = response.json()
            
            for scam in data.get('result', []):
                addresses = []
                
                # Extract addresses from various fields
                for field in ['addresses', 'coin', 'description']:
                    if field in scam:
                        field_text = str(scam[field])
                        addresses.extend(self.extract_all_crypto_addresses(field_text))
                
                if addresses:
                    scams.append({
                        'id': scam.get('id'),
                        'name': scam.get('name'),
                        'category': scam.get('category'),
                        'subcategory': scam.get('subcategory'),
                        'description': scam.get('description'),
                        'addresses': addresses,
                        'reporter': scam.get('reporter'),
                        'status': scam.get('status'),
                        'source': 'cryptoscamdb'
                    })
        
        except Exception as e:
            logging.error(f"Error fetching CryptoScam database: {e}")
        
        return scams
    
    def fetch_otx_threat_indicators(self) -> List[Dict[str, Any]]:
        """Fetch threat indicators from AlienVault OTX"""
        console.print("[blue]Fetching OTX threat indicators...[/blue]")
        
        indicators = []
        try:
            # Search for cryptocurrency-related IOCs
            url = f"{self.feeds['otx_alienvault']}/indicators/domain"
            crypto_domains = ['blockchain', 'crypto', 'bitcoin', 'ethereum', 'tron', 'defi']
            
            for domain_keyword in crypto_domains:
                params = {
                    'q': domain_keyword,
                    'limit': 50
                }
                
                response = self.session.get(url, params=params, timeout=30)
                if response.status_code == 200:
                    data = response.json()
                    
                    for indicator in data.get('results', []):
                        # Look for crypto addresses in indicator description
                        description = indicator.get('description', '')
                        addresses = self.extract_all_crypto_addresses(description)
                        
                        if addresses or any(kw in description.lower() for kw in crypto_domains):
                            indicators.append({
                                'indicator': indicator.get('indicator'),
                                'type': indicator.get('type'),
                                'description': description,
                                'addresses_found': addresses,
                                'created': indicator.get('created'),
                                'source': 'otx_alienvault'
                            })
                
                import time
                time.sleep(1)  # Rate limiting
        
        except Exception as e:
            logging.error(f"Error fetching OTX indicators: {e}")
        
        return indicators
    
    def extract_all_crypto_addresses(self, text: str) -> Dict[str, List[str]]:
        """Extract all cryptocurrency addresses from text"""
        addresses = {}
        
        for crypto, pattern in self.address_patterns.items():
            matches = re.findall(pattern, text, re.IGNORECASE)
            if matches:
                addresses[crypto] = list(set(matches))  # Remove duplicates
        
        return addresses
    
    def fetch_blockchain_labels(self) -> Dict[str, Any]:
        """Fetch known address labels from blockchain explorers"""
        console.print("[blue]Fetching blockchain address labels...[/blue]")
        
        labels = {}
        
        # Etherscan labels (many apply to other chains too)
        try:
            url = f"{self.feeds['etherscan_labels']}"
            params = {
                'module': 'account',
                'action': 'txlist',
                'address': '0x0000000000000000000000000000000000000000',  # Null address
                'apikey': 'YourApiKeyToken'  # Free tier available
            }
            
            # This is a simplified example - in practice you'd iterate through known addresses
            # and fetch their labels/tags
            
        except Exception as e:
            logging.error(f"Error fetching blockchain labels: {e}")
        
        return labels
    
    def analyze_new_threats(self) -> Dict[str, Any]:
        """Analyze and categorize new threats"""
        console.print("[green]Analyzing new threats...[/green]")
        
        all_data = {}
        
        # Fetch from all sources
        try:
            all_data['github_advisories'] = self.fetch_github_crypto_advisories()
            all_data['cryptoscam_db'] = self.fetch_cryptoscam_database()
            all_data['otx_indicators'] = self.fetch_otx_threat_indicators()
        except Exception as e:
            logging.error(f"Error in threat analysis: {e}")
        
        # Analyze and categorize
        threat_analysis = self.categorize_threats(all_data)
        
        return threat_analysis
    
    def categorize_threats(self, threat_data: Dict[str, Any]) -> Dict[str, Any]:
        """Categorize and prioritize threats"""
        categories = {
            'high_priority': [],
            'medium_priority': [],
            'low_priority': [],
            'tron_specific': [],
            'cross_chain': []
        }
        
        # Process GitHub advisories
        for advisory in threat_data.get('github_advisories', []):
            severity = advisory.get('severity', 'low')
            tron_addresses = advisory.get('addresses_found', {}).get('tron', [])
            
            threat_item = {
                'type': 'security_advisory',
                'severity': severity,
                'description': advisory.get('summary'),
                'tron_addresses': tron_addresses,
                'source_data': advisory
            }
            
            if tron_addresses:
                categories['tron_specific'].append(threat_item)
            
            if severity in ['critical', 'high']:
                categories['high_priority'].append(threat_item)
            elif severity == 'moderate':
                categories['medium_priority'].append(threat_item)
            else:
                categories['low_priority'].append(threat_item)
        
        # Process CryptoScam DB
        for scam in threat_data.get('cryptoscam_db', []):
            tron_addresses = scam.get('addresses', {}).get('tron', [])
            
            threat_item = {
                'type': 'known_scam',
                'category': scam.get('category'),
                'description': scam.get('description'),
                'tron_addresses': tron_addresses,
                'source_data': scam
            }
            
            if tron_addresses:
                categories['tron_specific'].append(threat_item)
            
            # Categorize by scam type
            if scam.get('category') in ['exchange', 'wallet']:
                categories['high_priority'].append(threat_item)
            else:
                categories['medium_priority'].append(threat_item)
        
        # Add statistics
        categories['statistics'] = {
            'total_threats': sum(len(cat) for cat in categories.values() if isinstance(cat, list)),
            'tron_threats': len(categories['tron_specific']),
            'high_priority': len(categories['high_priority']),
            'analysis_timestamp': datetime.now().isoformat()
        }
        
        return categories
    
    def generate_threat_report(self, analysis: Dict[str, Any]) -> str:
        """Generate human-readable threat report"""
        report_lines = [
            "# TRON Threat Intelligence Report",
            f"Generated: {datetime.now().strftime('%Y-%m-%d %H:%M:%S')}",
            "",
            "## Summary",
            f"- Total threats analyzed: {analysis['statistics']['total_threats']}",
            f"- TRON-specific threats: {analysis['statistics']['tron_threats']}",
            f"- High priority threats: {analysis['statistics']['high_priority']}",
            "",
        ]
        
        for category, threats in analysis.items():
            if category == 'statistics' or not threats:
                continue
                
            report_lines.extend([
                f"## {category.replace('_', ' ').title()}",
                ""
            ])
            
            for threat in threats[:10]:  # Limit to top 10 per category
                report_lines.extend([
                    f"- **{threat['type']}**: {threat.get('description', 'No description')[:100]}...",
                    f"  TRON addresses: {len(threat.get('tron_addresses', []))}",
                    ""
                ])
        
        return "\n".join(report_lines)

def main():
    """Main function for testing"""
    aggregator = ThreatIntelligenceAggregator()
    
    console.print("[green]Starting threat intelligence analysis...[/green]")
    analysis = aggregator.analyze_new_threats()
    
    # Generate report
    report = aggregator.generate_threat_report(analysis)
    
    # Save report
    timestamp = datetime.now().strftime('%Y%m%d_%H%M%S')
    report_file = f'threat_intelligence_report_{timestamp}.md'
    
    with open(report_file, 'w') as f:
        f.write(report)
    
    console.print(f"[green]Threat intelligence report saved: {report_file}[/green]")
    
    # Save raw data as JSON
    data_file = f'threat_intelligence_data_{timestamp}.json'
    with open(data_file, 'w') as f:
        json.dump(analysis, f, indent=2, default=str)
    
    console.print(f"[green]Raw threat data saved: {data_file}[/green]")

if __name__ == "__main__":
    main()
