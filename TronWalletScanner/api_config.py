
#!/usr/bin/env python3
"""
API Configuration - Manage API keys and rate limits
Store your free API keys here (most services offer free tiers)
"""

import os
from typing import Dict, Optional

class APIConfig:
    def __init__(self):
        # Free API keys (you need to register for these)
        self.api_keys = {
            # CoinGecko - Free tier: 10-50 calls/minute
            'coingecko': os.getenv('COINGECKO_API_KEY', ''),  # Optional for free tier
            
            # CoinMarketCap - Free tier: 10k calls/month
            'coinmarketcap': os.getenv('COINMARKETCAP_API_KEY', ''),
            
            # CryptoCompare - Free tier: 100k calls/month
            'cryptocompare': os.getenv('CRYPTOCOMPARE_API_KEY', ''),
            
            # TronGrid - Free with higher limits when registered
            'trongrid': os.getenv('TRONGRID_API_KEY', ''),
            
            # GitHub - Higher rate limits with token
            'github': os.getenv('GITHUB_TOKEN', ''),
            
            # DeBank - Free for basic data
            'debank': os.getenv('DEBANK_API_KEY', ''),
        }
        
        # Rate limits (requests per minute) for free tiers
        self.rate_limits = {
            'coingecko': 10,      # Free tier
            'coingecko_pro': 50,   # With API key
            'coinmarketcap': 30,   # Free tier
            'cryptocompare': 100,  # Free tier
            'tronscan': 60,        # Generally generous
            'trongrid': 100,       # With API key
            'github': 60,          # Without token
            'github_auth': 5000,   # With token
            'debank': 30,          # Free tier
        }
    
    def get_api_key(self, service: str) -> Optional[str]:
        """Get API key for service"""
        return self.api_keys.get(service)
    
    def get_rate_limit(self, service: str) -> int:
        """Get rate limit for service"""
        # Use higher limit if API key is available
        if self.has_api_key(service):
            return self.rate_limits.get(f"{service}_pro", self.rate_limits.get(service, 10))
        return self.rate_limits.get(service, 10)
    
    def has_api_key(self, service: str) -> bool:
        """Check if API key is available"""
        key = self.api_keys.get(service)
        return key is not None and len(key) > 0
    
    def get_headers(self, service: str) -> Dict[str, str]:
        """Get headers for API requests"""
        headers = {'User-Agent': 'TRON-Wallet-Scanner/1.0'}
        
        api_key = self.get_api_key(service)
        if api_key:
            if service == 'coinmarketcap':
                headers['X-CMC_PRO_API_KEY'] = api_key
            elif service == 'cryptocompare':
                headers['Apikey'] = api_key
            elif service == 'github':
                headers['Authorization'] = f'token {api_key}'
            elif service == 'trongrid':
                headers['TRON-PRO-API-KEY'] = api_key
        
        return headers

# Instructions for getting free API keys
API_SETUP_INSTRUCTIONS = """
Free API Keys Setup Instructions:

1. CoinGecko (Free: 10-50 calls/min):
   - Visit: https://www.coingecko.com/en/api
   - No API key required for free tier
   - Optional: Register for higher limits

2. CoinMarketCap (Free: 10k calls/month):
   - Visit: https://pro.coinmarketcap.com/signup
   - Get free API key
   - Set environment variable: COINMARKETCAP_API_KEY

3. CryptoCompare (Free: 100k calls/month):
   - Visit: https://www.cryptocompare.com/cryptopian/api-keys
   - Get free API key
   - Set environment variable: CRYPTOCOMPARE_API_KEY

4. TronGrid (Free with higher limits):
   - Visit: https://www.trongrid.io/
   - Register for free API key
   - Set environment variable: TRONGRID_API_KEY

5. GitHub (Free: 60 req/hour, 5000 with token):
   - Visit: https://github.com/settings/tokens
   - Create personal access token
   - Set environment variable: GITHUB_TOKEN

6. DeBank (Free for basic data):
   - Visit: https://debank.com/api
   - Get free API key
   - Set environment variable: DEBANK_API_KEY

To set environment variables in Replit:
1. Go to Tools > Secrets
2. Add your API keys as secrets
3. They'll be available as environment variables
"""

def print_setup_instructions():
    """Print API setup instructions"""
    from rich.console import Console
    from rich.panel import Panel
    
    console = Console()
    console.print(Panel(API_SETUP_INSTRUCTIONS, title="API Setup Instructions", border_style="blue"))

if __name__ == "__main__":
    print_setup_instructions()
