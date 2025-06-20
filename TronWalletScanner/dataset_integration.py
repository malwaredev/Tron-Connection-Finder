
import json
import importlib
import sys
from datetime import datetime
from typing import Dict, Any, List
from rich.console import Console
from dataset_updater import DatasetUpdater

console = Console()

class DatasetIntegration:
    def __init__(self):
        self.updater = DatasetUpdater()
        self.database_modules = {
            'exchanges': 'exchanges_database',
            'malicious': 'malicious_addresses_database', 
            'tokens': 'token_classification_database',
            'contracts': 'smart_contracts_database'
        }
    
    def load_database(self, db_type: str) -> Dict[str, Any]:
        """Load database from module"""
        try:
            module_name = self.database_modules[db_type]
            module = importlib.import_module(module_name)
            
            if db_type == 'exchanges':
                return getattr(module, 'EXCHANGES_DATABASE', {})
            elif db_type == 'malicious':
                return getattr(module, 'MALICIOUS_ADDRESSES_DATABASE', {})
            elif db_type == 'tokens':
                return getattr(module, 'TOKEN_CLASSIFICATION_DATABASE', {})
            elif db_type == 'contracts':
                return getattr(module, 'SMART_CONTRACTS_DATABASE', {})
        except Exception as e:
            console.print(f"[red]Error loading {db_type} database: {e}[/red]")
            return {}
    
    def merge_datasets(self, existing: Dict, new_data: Dict) -> Dict:
        """Merge new data with existing database"""
        merged = existing.copy()
        
        for key, value in new_data.items():
            if key not in merged:
                merged[key] = value
                console.print(f"[green]Added new entry: {key}[/green]")
            else:
                # Update existing entry with new information
                if isinstance(merged[key], dict) and isinstance(value, dict):
                    merged[key].update(value)
                    merged[key]['last_updated'] = datetime.now().isoformat()
        
        return merged
    
    def update_all_databases(self):
        """Update all databases with new data"""
        console.print("[blue]Starting database integration and update...[/blue]")
        
        # Get new data from updater
        new_data = {
            'exchanges': self.updater.update_exchange_data(),
            'malicious': self.updater.update_malicious_addresses(),
            'tokens': self.updater.update_token_data(),
            'contracts': self.updater.update_smart_contracts()
        }
        
        # Merge with existing databases
        for db_type, fresh_data in new_data.items():
            if fresh_data:
                existing_data = self.load_database(db_type)
                merged_data = self.merge_datasets(existing_data, fresh_data)
                self.save_updated_database(db_type, merged_data)
        
        console.print("[green]Database integration completed![/green]")
    
    def save_updated_database(self, db_type: str, data: Dict):
        """Save updated database to file"""
        try:
            filename = f"{self.database_modules[db_type]}.py"
            self.write_database_file(filename, db_type, data)
            console.print(f"[green]Updated {filename}[/green]")
        except Exception as e:
            console.print(f"[red]Error saving {db_type}: {e}[/red]")
    
    def write_database_file(self, filename: str, db_type: str, data: Dict):
        """Write database data to Python file"""
        var_names = {
            'exchanges': 'EXCHANGES_DATABASE',
            'malicious': 'MALICIOUS_ADDRESSES_DATABASE',
            'tokens': 'TOKEN_CLASSIFICATION_DATABASE', 
            'contracts': 'SMART_CONTRACTS_DATABASE'
        }
        
        content = f'''"""
{db_type.title()} Database - Auto-updated on {datetime.now().isoformat()}
This file contains verified {db_type} data from multiple sources.
"""

from datetime import datetime

{var_names[db_type]} = {json.dumps(data, indent=4)}

def get_{db_type}_info(identifier: str):
    """Get {db_type} information by identifier"""
    return {var_names[db_type]}.get(identifier, {{}})

def is_{db_type}(identifier: str) -> bool:
    """Check if identifier is in {db_type} database"""
    return identifier in {var_names[db_type]}

def get_all_{db_type}():
    """Get all {db_type} data"""
    return {var_names[db_type]}

# Last updated: {datetime.now().isoformat()}
'''
        
        with open(filename, 'w') as f:
            f.write(content)

if __name__ == "__main__":
    integrator = DatasetIntegration()
    integrator.update_all_databases()
