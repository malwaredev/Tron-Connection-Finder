#!/usr/bin/env python3
"""
Clean TRON Network Graph Generator - Fixed implementation
"""

import json
from datetime import datetime
from pathlib import Path

try:
    from pyvis.network import Network
    PYVIS_AVAILABLE = True
except ImportError:
    PYVIS_AVAILABLE = False

class CleanTronNetworkGenerator:
    """Clean implementation of TRON network graph generator."""
    
    def __init__(self):
        self.colors = {
            "Personal": "#3498db",
            "Exchange": "#2ecc71", 
            "Contract": "#e74c3c",
            "Mining": "#f39c12",
            "Unknown": "#95a5a6"
        }
    
    def create_graph(self, addresses_data, connections, output_name="tron_network"):
        """Create working interactive network graph."""
        
        if not PYVIS_AVAILABLE:
            return self._create_simple_html(addresses_data, connections, output_name)
        
        # Create pyvis network
        net = Network(height="800px", width="100%", directed=True, bgcolor="#1a1a1a", font_color="white")
        
        # Add nodes with enhanced information
        for address, data in addresses_data.items():
            wallet_type = data.get("wallet_type", "Unknown")
            balance = data.get("balance_trx", 0)
            risk_score = data.get("risk_score", data.get("anomaly_score", 0))
            tx_count = data.get("transactions_count", 0)
            
            # Enhanced color coding
            if wallet_type == "Exchange":
                color = "#2ecc71"  # Green for exchanges
            elif wallet_type == "DeFi Protocol" or wallet_type == "DeFi User":
                color = "#1abc9c"  # Teal for DeFi
            elif wallet_type in ["Whale", "High Net Worth"]:
                color = "#f39c12"  # Orange for whales
            elif "Trader" in wallet_type:
                color = "#e74c3c"  # Red for traders
            elif risk_score > 70:
                color = "#8e44ad"  # Purple for high risk
            elif wallet_type == "Contract":
                color = "#34495e"  # Dark gray for contracts
            else:
                color = self.colors.get(wallet_type, "#3498db")  # Default blue
            
            # Dynamic sizing based on balance and activity
            base_size = 15
            balance_factor = min(balance / 5000, 25)  # Up to 25 extra for balance
            activity_factor = min(tx_count / 1000, 15)  # Up to 15 extra for activity
            size = base_size + balance_factor + activity_factor
            
            # Enhanced tooltip with detailed information
            exchange_info = ""
            if data.get("is_exchange"):
                exchange_info = f"\\nExchange: {data.get('exchange_name', 'Unknown')}"
            
            defi_info = ""
            if data.get("is_defi"):
                defi_info = f"\\nDeFi: {data.get('defi_name', 'Unknown Protocol')}"
            
            malicious_info = ""
            if data.get("is_malicious"):
                malicious_info = f"\\n⚠️ MALICIOUS: {data.get('malicious_info', {}).get('type', 'Unknown threat')}"
            
            activity_level = "Low"
            if tx_count > 10000:
                activity_level = "Very High"
            elif tx_count > 1000:
                activity_level = "High"
            elif tx_count > 100:
                activity_level = "Medium"
            
            tooltip = (f"Address: {address}\\n"
                      f"Type: {wallet_type}\\n"
                      f"Balance: {balance:,.2f} TRX\\n"
                      f"Transactions: {tx_count:,}\\n"
                      f"Activity: {activity_level}\\n"
                      f"Risk Score: {risk_score}/100"
                      f"{exchange_info}{defi_info}{malicious_info}")
            
            # Add wallet details if available
            if data.get("wallet_details"):
                tooltip += f"\\nDetails: {data['wallet_details']}"
            
            net.add_node(
                address,
                label=address[:6] + "..." + address[-4:],
                title=tooltip,
                color=color,
                size=size,
                borderWidth=3 if risk_score > 70 else 2,
                borderColor="#ff0000" if data.get("is_malicious") else "#ffffff"
            )
        
        # Add edges with enhanced connection information
        for conn in connections:
            from_addr = conn.get("from_address")
            to_addr = conn.get("to_address")
            
            if from_addr in addresses_data and to_addr in addresses_data:
                amount = conn.get("amount", 0)
                count = conn.get("count", 1)
                trx_sent = conn.get("trx_sent", amount)
                trx_received = conn.get("trx_received", 0)
                strength = conn.get("strength", 0)
                
                # Enhanced edge styling based on amount and frequency
                if amount > 1000000:  # > 1M TRX
                    edge_color = "#e74c3c"  # Red for large amounts
                    width = 6
                elif amount > 100000:  # > 100K TRX
                    edge_color = "#f39c12"  # Orange for medium amounts
                    width = 4
                elif amount > 10000:  # > 10K TRX
                    edge_color = "#f1c40f"  # Yellow for small amounts
                    width = 2
                else:
                    edge_color = "#95a5a6"  # Gray for minimal amounts
                    width = 1
                
                # Adjust width based on transaction frequency
                frequency_factor = min(count / 10, 3)
                width = max(1, width + frequency_factor)
                
                # Enhanced tooltip with comprehensive connection data
                total_volume = trx_sent + trx_received
                avg_tx_size = amount / count if count > 0 else 0
                
                tooltip = (f"Connection Strength: {strength:.2f}\\n"
                          f"Total Volume: {total_volume:,.2f} TRX\\n"
                          f"TRX Sent: {trx_sent:,.2f}\\n"
                          f"TRX Received: {trx_received:,.2f}\\n"
                          f"Transactions: {count:,}\\n"
                          f"Avg Transaction: {avg_tx_size:,.2f} TRX")
                
                # Add transaction types if available
                if conn.get("types"):
                    main_type = max(conn["types"].items(), key=lambda x: x[1])[0]
                    tooltip += f"\\nMain Type: {main_type}"
                
                # Add risk indicators for suspicious connections
                if amount > 1000000 and count < 5:
                    tooltip += "\\n⚠️ Large single transfers"
                elif count > 1000 and avg_tx_size < 10:
                    tooltip += "\\n⚠️ High frequency, small amounts"
                
                net.add_edge(
                    from_addr, 
                    to_addr, 
                    title=tooltip, 
                    width=width, 
                    color=edge_color,
                    arrows={"to": {"enabled": True, "scaleFactor": 1.2}},
                    smooth={"enabled": True, "type": "continuous"}
                )
        
        # Set options
        net.set_options("""
        {
            "physics": {
                "enabled": true,
                "stabilization": {"iterations": 100}
            },
            "interaction": {
                "navigationButtons": true,
                "keyboard": {"enabled": true}
            }
        }
        """)
        
        # Save file
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"results/visualizations/{output_name}_{timestamp}.html"
        
        Path("results/visualizations").mkdir(parents=True, exist_ok=True)
        Path("results/reports").mkdir(parents=True, exist_ok=True)
        
        net.save_graph(filename)
        
        # Add search functionality
        self._add_search_controls(filename, addresses_data, connections)
        
        # Copy to reports
        import shutil
        report_file = f"results/reports/{Path(filename).name}"
        shutil.copy2(filename, report_file)
        
        return filename
    
    def _add_search_controls(self, filename, addresses_data, connections):
        """Add search and filter controls to the HTML."""
        
        with open(filename, 'r') as f:
            content = f.read()
        
        search_html = f'''
        <style>
            .tron-search {{
                position: fixed;
                top: 10px;
                left: 10px;
                background: rgba(0,0,0,0.8);
                color: white;
                padding: 15px;
                border-radius: 8px;
                z-index: 1000;
                font-family: Arial, sans-serif;
                max-width: 300px;
            }}
            .search-input {{
                width: 100%;
                padding: 8px;
                margin: 5px 0;
                border: none;
                border-radius: 4px;
                background: #333;
                color: white;
            }}
            .filter-btn {{
                background: #3498db;
                border: none;
                color: white;
                padding: 5px 10px;
                margin: 2px;
                border-radius: 3px;
                cursor: pointer;
                font-size: 11px;
            }}
            .filter-btn:hover {{ background: #2980b9; }}
            .filter-btn.active {{ background: #e74c3c; }}
            .stats {{
                margin-top: 10px;
                padding-top: 10px;
                border-top: 1px solid #555;
                font-size: 12px;
            }}
        </style>
        
        <div class="tron-search">
            <h4 style="margin-top:0;">TRON Network</h4>
            <input type="text" class="search-input" id="searchAddr" placeholder="Search addresses..." onkeyup="searchNetwork()">
            
            <div style="margin: 10px 0;">
                <button class="filter-btn active" onclick="filterType('all')">All</button>
                <button class="filter-btn" onclick="filterType('Personal')">Personal</button>
                <button class="filter-btn" onclick="filterType('Exchange')">Exchange</button>
                <button class="filter-btn" onclick="filterType('Contract')">Contract</button>
                <button class="filter-btn" onclick="filterType('Mining')">Mining</button>
            </div>
            
            <button class="filter-btn" onclick="resetNetwork()">Reset View</button>
            <button class="filter-btn" onclick="togglePhysics()">Physics On/Off</button>
            
            <div class="stats">
                <strong>Network Stats:</strong><br>
                Addresses: {len(addresses_data)}<br>
                Connections: {len(connections)}<br>
                High Risk: {sum(1 for d in addresses_data.values() if d.get('risk_score', 0) > 50)}
            </div>
        </div>
        
        <script>
            let physicsOn = true;
            
            function searchNetwork() {{
                const query = document.getElementById('searchAddr').value.toLowerCase();
                if (query.length > 2) {{
                    const nodes = network.body.data.nodes.get();
                    const match = nodes.find(n => n.id.toLowerCase().includes(query));
                    if (match) {{
                        network.selectNodes([match.id]);
                        network.focus(match.id, {{scale: 1.5, animation: {{duration: 1000}}}});
                    }}
                }}
            }}
            
            function filterType(type) {{
                document.querySelectorAll('.filter-btn').forEach(b => b.classList.remove('active'));
                event.target.classList.add('active');
                network.fit();
            }}
            
            function resetNetwork() {{
                network.fit({{animation: {{duration: 1000}}}});
            }}
            
            function togglePhysics() {{
                physicsOn = !physicsOn;
                network.setOptions({{physics: {{enabled: physicsOn}}}});
            }}
        </script>
        '''
        
        enhanced_content = content.replace('</body>', search_html + '</body>')
        
        with open(filename, 'w') as f:
            f.write(enhanced_content)
    
    def _create_simple_html(self, addresses_data, connections, output_name):
        """Fallback HTML when pyvis not available."""
        
        timestamp = datetime.now().strftime("%Y%m%d_%H%M%S")
        filename = f"results/visualizations/{output_name}_simple_{timestamp}.html"
        
        nodes_json = json.dumps([{
            "id": addr,
            "label": addr[:8] + "..." + addr[-4:],
            "color": self.colors.get(data.get("wallet_type", "Unknown"), "#95a5a6"),
            "title": f"Address: {addr}\\nType: {data.get('wallet_type', 'Unknown')}\\nBalance: {data.get('balance_trx', 0):.2f} TRX"
        } for addr, data in addresses_data.items()])
        
        edges_json = json.dumps([{
            "from": conn.get("from_address"),
            "to": conn.get("to_address"), 
            "arrows": "to",
            "title": f"Amount: {conn.get('amount', 0):.2f} TRX"
        } for conn in connections if conn.get("from_address") in addresses_data and conn.get("to_address") in addresses_data])
        
        html = f'''<!DOCTYPE html>
<html><head><title>TRON Network</title>
<script src="https://unpkg.com/vis-network/standalone/umd/vis-network.min.js"></script>
<style>body{{margin:0;padding:20px;font-family:Arial;}} #net{{width:100%;height:600px;border:1px solid #ccc;}}</style>
</head><body>
<h2>TRON Network Analysis</h2>
<div id="net"></div>
<script>
const nodes = new vis.DataSet({nodes_json});
const edges = new vis.DataSet({edges_json});
const network = new vis.Network(document.getElementById('net'), {{nodes, edges}}, {{
    physics: {{enabled: true}},
    interaction: {{navigationButtons: true}}
}});
</script></body></html>'''
        
        Path("results/visualizations").mkdir(parents=True, exist_ok=True)
        with open(filename, 'w') as f:
            f.write(html)
        
        return filename