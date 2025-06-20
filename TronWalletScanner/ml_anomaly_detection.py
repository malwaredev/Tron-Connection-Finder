"""
ML-based Anomaly Detection for TRON Wallet Analysis

This module provides machine learning based anomaly detection capabilities 
for identifying suspicious transactions and wallet behaviors.
"""

import numpy as np
import pandas as pd
from datetime import datetime, timedelta
import math
from typing import Dict, List, Tuple, Any, Optional

# Common patterns in fraudulent or suspicious transactions (enhanced)
SUSPICIOUS_PATTERNS = {
    "round_number_transfers": {
        "description": "Exactly round number amounts (like 1000.00 TRX) are often used in automated scripts",
        "risk_weight": 0.3,
        "threshold": 0.8,  # If 80% of transactions have round numbers
        "severity": "medium"
    },
    "short_holding_period": {
        "description": "Funds received and sent out within a very short timeframe",
        "risk_weight": 0.7,
        "threshold": 300,  # Seconds
        "severity": "high"
    },
    "splitting_pattern": {
        "description": "Large amounts split into many smaller transactions of similar size",
        "risk_weight": 0.6,
        "threshold": 0.9,  # Similarity threshold
        "severity": "high"
    },
    "layering_pattern": {
        "description": "Funds moved through multiple addresses in quick succession",
        "risk_weight": 0.8,
        "threshold": 3,  # Number of hops
        "severity": "very_high"
    },
    "unusual_hours": {
        "description": "Transactions occurring at unusual hours based on historical patterns",
        "risk_weight": 0.4,
        "threshold": 0.05,  # Statistical p-value threshold
        "severity": "medium"
    },
    "unusual_transaction_size": {
        "description": "Transaction sizes that deviate significantly from the address's normal pattern",
        "risk_weight": 0.5,
        "threshold": 2.5,  # Standard deviations from mean
        "severity": "medium"
    },
    "high_frequency_trading": {
        "description": "Extremely high frequency of transactions suggesting bot activity",
        "risk_weight": 0.6,
        "threshold": 100,  # Transactions per hour
        "severity": "high"
    },
    "dust_attack_pattern": {
        "description": "Many tiny transactions from unknown sources (dust attack)",
        "risk_weight": 0.5,
        "threshold": 0.001,  # TRX amount threshold
        "severity": "medium"
    },
    "exchange_hopping": {
        "description": "Rapid movement between multiple exchanges",
        "risk_weight": 0.7,
        "threshold": 5,  # Number of different exchanges
        "severity": "high"
    },
    "mirror_trading": {
        "description": "Transactions that mirror amounts and timing of another address",
        "risk_weight": 0.8,
        "threshold": 0.95,  # Correlation threshold
        "severity": "very_high"
    },
    "token_creation_spam": {
        "description": "Creation of multiple tokens with similar properties",
        "risk_weight": 0.9,
        "threshold": 5,  # Number of tokens created
        "severity": "very_high"
    },
    "wash_trading": {
        "description": "Self-trading to artificially inflate volume",
        "risk_weight": 0.8,
        "threshold": 0.3,  # Percentage of self-transactions
        "severity": "high"
    }
}

class AnomalyDetector:
    """ML-based anomaly detector for TRON transactions."""
    
    def __init__(self, sensitivity=1.0):
        """
        Initialize the anomaly detector.
        
        Args:
            sensitivity: Sensitivity multiplier for detection thresholds (higher means more sensitive)
        """
        self.sensitivity = sensitivity
        self.transaction_history = {}
        self.address_profiles = {}
    
    def build_address_profile(self, address: str, transactions: List[Dict[str, Any]]) -> Dict[str, Any]:
        """
        Build a behavioral profile for an address based on its transaction history.
        
        Args:
            address: The TRON address
            transactions: List of transaction dictionaries
            
        Returns:
            Profile dictionary with behavioral metrics
        """
        if not transactions:
            return {
                "address": address,
                "profile_complete": False,
                "transaction_count": 0
            }
        
        # Extract timestamps and amounts
        timestamps = []
        amounts = []
        tx_types = []
        counterparties = []
        
        for tx in transactions:
            # Extract data based on transaction source (TronGrid or TronScan)
            if tx.get("source") == "trongrid":
                if tx.get("type") == "trx":
                    # Extract data from TronGrid TRX transaction
                    if "raw_data" in tx and "contract" in tx["raw_data"]:
                        contract = tx["raw_data"]["contract"][0]
                        if "parameter" in contract and "value" in contract["parameter"]:
                            value = contract["parameter"]["value"]
                            
                            amount = value.get("amount", 0) / 1_000_000
                            timestamp = tx["raw_data"].get("timestamp", 0) / 1000
                            tx_type = contract.get("type", "")
                            
                            # Determine if this address is sender or receiver
                            is_sender = False
                            counterparty = None
                            
                            if "owner_address" in value and value["owner_address"] == address:
                                is_sender = True
                                if "to_address" in value:
                                    counterparty = value["to_address"]
                            elif "to_address" in value and value["to_address"] == address:
                                if "owner_address" in value:
                                    counterparty = value["owner_address"]
                            
                            if timestamp and amount:
                                timestamps.append(timestamp)
                                amounts.append(amount)
                                tx_types.append(tx_type)
                                if counterparty:
                                    counterparties.append(counterparty)
                
                elif tx.get("type") == "trc20":
                    # Extract data from TronGrid TRC20 transaction
                    from_addr = tx.get("from", "")
                    to_addr = tx.get("to", "")
                    token_addr = tx.get("token_info", {}).get("address", "")
                    value = float(tx.get("value", "0"))
                    decimals = int(tx.get("token_info", {}).get("decimals", 6))
                    amount = value / (10 ** decimals)
                    timestamp = tx.get("block_timestamp", 0) / 1000
                    
                    if from_addr and to_addr and timestamp:
                        timestamps.append(timestamp)
                        amounts.append(amount)
                        tx_types.append("TRC20Transfer")
                        
                        if from_addr == address:
                            counterparties.append(to_addr)
                        else:
                            counterparties.append(from_addr)
            
            elif tx.get("source") == "tronscan":
                # Extract data from TronScan transaction
                if tx.get("type") == "trx":
                    timestamp = tx.get("timestamp", 0) / 1000
                    contract_type = tx.get("contractType", "")
                    
                    if contract_type == "TransferContract":
                        contract_data = tx.get("contractData", {})
                        from_addr = tx.get("ownerAddress", "")
                        to_addr = contract_data.get("to_address", "")
                        amount = contract_data.get("amount", 0) / 1_000_000
                        
                        if timestamp and amount:
                            timestamps.append(timestamp)
                            amounts.append(amount)
                            tx_types.append(contract_type)
                            
                            if from_addr == address:
                                if to_addr:
                                    counterparties.append(to_addr)
                            else:
                                if from_addr:
                                    counterparties.append(from_addr)
                
                elif tx.get("type") == "trc20":
                    # Process TRC20 transfers from TronScan
                    from_addr = tx.get("from_address", "")
                    to_addr = tx.get("to_address", "")
                    token_addr = tx.get("contract_address", "")
                    amount = float(tx.get("quant", "0")) / (10 ** int(tx.get("decimals", 6)))
                    timestamp = tx.get("timestamp", 0) / 1000
                    
                    if timestamp and amount:
                        timestamps.append(timestamp)
                        amounts.append(amount)
                        tx_types.append("TRC20Transfer")
                        
                        if from_addr == address:
                            if to_addr:
                                counterparties.append(to_addr)
                        else:
                            if from_addr:
                                counterparties.append(from_addr)
        
        # Build the profile
        if not timestamps or not amounts:
            return {
                "address": address,
                "profile_complete": False,
                "transaction_count": 0
            }
        
        # Convert to numpy arrays for analysis
        timestamps = np.array(timestamps)
        amounts = np.array(amounts)
        
        # Calculate basic statistics
        avg_amount = np.mean(amounts)
        median_amount = np.median(amounts)
        std_amount = np.std(amounts)
        max_amount = np.max(amounts)
        min_amount = np.min(amounts)
        
        # Calculate temporal patterns
        if len(timestamps) > 1:
            sorted_timestamps = np.sort(timestamps)
            time_diffs = np.diff(sorted_timestamps)
            avg_time_diff = np.mean(time_diffs)
            std_time_diff = np.std(time_diffs)
        else:
            avg_time_diff = 0
            std_time_diff = 0
        
        # Count transaction types
        tx_type_counts = {}
        for tx_type in tx_types:
            tx_type_counts[tx_type] = tx_type_counts.get(tx_type, 0) + 1
        
        # Analyze counterparties
        counterparty_counts = {}
        unique_counterparties = set()
        for cp in counterparties:
            counterparty_counts[cp] = counterparty_counts.get(cp, 0) + 1
            unique_counterparties.add(cp)
        
        # Check for round number transactions
        round_number_count = sum(1 for amount in amounts if amount.is_integer() or (amount * 10).is_integer() or (amount * 100).is_integer())
        round_number_ratio = round_number_count / len(amounts) if amounts else 0
        
        # Advanced pattern analysis
        patterns = self._detect_transaction_patterns(timestamps, amounts, address, counterparties)
        
        # Build the complete profile
        profile = {
            "address": address,
            "profile_complete": True,
            "transaction_count": len(timestamps),
            "unique_counterparties": len(unique_counterparties),
            "most_frequent_counterparty": max(counterparty_counts.items(), key=lambda x: x[1])[0] if counterparty_counts else None,
            "most_frequent_tx_type": max(tx_type_counts.items(), key=lambda x: x[1])[0] if tx_type_counts else None,
            "amount_stats": {
                "mean": avg_amount,
                "median": median_amount,
                "std_dev": std_amount,
                "max": max_amount,
                "min": min_amount
            },
            "time_stats": {
                "avg_time_between_tx": avg_time_diff,
                "std_time_between_tx": std_time_diff,
                "first_tx_timestamp": min(timestamps) if timestamps else 0,
                "last_tx_timestamp": max(timestamps) if timestamps else 0
            },
            "transaction_types": tx_type_counts,
            "round_number_ratio": round_number_ratio,
            "patterns": patterns
        }
        
        # Store in instance
        self.address_profiles[address] = profile
        self.transaction_history[address] = list(zip(timestamps, amounts))
        
        return profile
    
    def _detect_transaction_patterns(self, timestamps, amounts, address, counterparties):
        """Detect specific transaction patterns that may indicate suspicious activity."""
        patterns = {}
        
        # Detect round number pattern
        round_numbers = sum(1 for amount in amounts if amount.is_integer() or (amount * 10).is_integer() or (amount * 100).is_integer())
        round_number_ratio = round_numbers / len(amounts) if amounts else 0
        
        patterns["round_number_transfers"] = {
            "detected": round_number_ratio >= SUSPICIOUS_PATTERNS["round_number_transfers"]["threshold"],
            "confidence": round_number_ratio,
            "description": SUSPICIOUS_PATTERNS["round_number_transfers"]["description"]
        }
        
        # Detect short holding periods
        if len(timestamps) > 5:
            # Sort transactions by timestamp
            tx_data = list(zip(timestamps, amounts))
            tx_data.sort(key=lambda x: x[0])
            
            # Find rapid in-out patterns
            rapid_transfers = 0
            for i in range(1, len(tx_data)):
                if tx_data[i][0] - tx_data[i-1][0] < SUSPICIOUS_PATTERNS["short_holding_period"]["threshold"]:
                    if amounts[i-1] > 0 and amounts[i] < 0:  # in then out
                        rapid_transfers += 1
            
            rapid_transfer_ratio = rapid_transfers / (len(tx_data) - 1) if len(tx_data) > 1 else 0
            
            patterns["short_holding_period"] = {
                "detected": rapid_transfer_ratio > 0.5,
                "confidence": rapid_transfer_ratio,
                "description": SUSPICIOUS_PATTERNS["short_holding_period"]["description"]
            }
        else:
            patterns["short_holding_period"] = {
                "detected": False,
                "confidence": 0,
                "description": SUSPICIOUS_PATTERNS["short_holding_period"]["description"]
            }
        
        # Detect splitting pattern (similar sized transactions in a short period)
        if len(amounts) > 5:
            # Group transactions by day
            day_groups = {}
            for i, ts in enumerate(timestamps):
                day = datetime.fromtimestamp(ts).date()
                if day not in day_groups:
                    day_groups[day] = []
                day_groups[day].append((ts, amounts[i]))
            
            # Look for days with multiple similar transactions
            days_with_splitting = 0
            for day, txs in day_groups.items():
                if len(txs) >= 3:  # At least 3 transactions in a day
                    # Calculate coefficient of variation (std/mean)
                    day_amounts = [tx[1] for tx in txs]
                    if np.mean(day_amounts) > 0:
                        cv = np.std(day_amounts) / np.mean(day_amounts)
                        if cv < 0.2:  # Low variation means similar amounts
                            days_with_splitting += 1
            
            splitting_ratio = days_with_splitting / len(day_groups) if day_groups else 0
            
            patterns["splitting_pattern"] = {
                "detected": splitting_ratio > 0.3,
                "confidence": splitting_ratio,
                "description": SUSPICIOUS_PATTERNS["splitting_pattern"]["description"]
            }
        else:
            patterns["splitting_pattern"] = {
                "detected": False,
                "confidence": 0,
                "description": SUSPICIOUS_PATTERNS["splitting_pattern"]["description"]
            }
        
        # Unusual transaction size detection
        if len(amounts) > 10 and np.std(amounts) > 0:
            # Calculate z-scores for each transaction
            z_scores = np.abs((amounts - np.mean(amounts)) / np.std(amounts))
            outliers = np.where(z_scores > SUSPICIOUS_PATTERNS["unusual_transaction_size"]["threshold"])[0]
            outlier_ratio = len(outliers) / len(amounts)
            
            patterns["unusual_transaction_size"] = {
                "detected": outlier_ratio > 0.1,  # More than 10% of transactions are outliers
                "confidence": outlier_ratio,
                "description": SUSPICIOUS_PATTERNS["unusual_transaction_size"]["description"]
            }
        else:
            patterns["unusual_transaction_size"] = {
                "detected": False,
                "confidence": 0,
                "description": SUSPICIOUS_PATTERNS["unusual_transaction_size"]["description"]
            }
        
        return patterns
    
    def calculate_anomaly_score(self, address: str, profile: Optional[Dict] = None) -> Tuple[float, List[str]]:
        """
        Calculate an ML-based anomaly score for the address.
        
        Args:
            address: TRON address to analyze
            profile: Optional pre-computed profile (if None, uses stored profile)
            
        Returns:
            Tuple of (anomaly_score, risk_factors) where anomaly_score is 0-100
            and risk_factors is a list of descriptions
        """
        if profile is None:
            profile = self.address_profiles.get(address)
        
        if not profile or not profile.get("profile_complete", False):
            return 0, []
        
        score = 0
        risk_factors = []
        
        # Check for suspicious patterns
        patterns = profile.get("patterns", {})
        for pattern_name, pattern_info in patterns.items():
            if pattern_info.get("detected", False):
                pattern_weight = SUSPICIOUS_PATTERNS.get(pattern_name, {}).get("risk_weight", 0.5)
                pattern_confidence = pattern_info.get("confidence", 0.5)
                
                # Apply sensitivity multiplier
                weighted_score = pattern_weight * pattern_confidence * 100 * self.sensitivity
                score += weighted_score
                
                risk_factors.append(pattern_info.get("description", pattern_name))
        
        # Check transaction frequency and volume
        tx_count = profile.get("transaction_count", 0)
        amount_stats = profile.get("amount_stats", {})
        time_stats = profile.get("time_stats", {})
        
        # High frequency trading with low balance is suspicious
        if tx_count > 50 and amount_stats.get("mean", 0) < 10:
            score += 15 * self.sensitivity
            risk_factors.append("High transaction count with low average value")
        
        # Very high transaction values
        if amount_stats.get("max", 0) > 100000:
            score += 10 * self.sensitivity
            risk_factors.append("Extremely high transaction values detected")
        
        # Unusual time pattern - very regular intervals
        if time_stats.get("std_time_between_tx", 0) < 60 and tx_count > 10:
            score += 20 * self.sensitivity
            risk_factors.append("Unusually regular transaction timing (potential bot/automated activity)")
        
        # Round number ratio
        round_ratio = profile.get("round_number_ratio", 0)
        if round_ratio > 0.8:
            score += 15 * self.sensitivity
            risk_factors.append("High proportion of round-number transactions")
        
        # High unique counterparty ratio may indicate distribution
        unique_ratio = profile.get("unique_counterparties", 0) / max(tx_count, 1)
        if unique_ratio > 0.8 and tx_count > 10:
            score += 25 * self.sensitivity
            risk_factors.append("High number of unique counterparties (potential distribution pattern)")
        
        # Cap the score at 100
        score = min(score, 100)
        
        return score, risk_factors
    
    def analyze_transaction_flow(self, transactions: List[Dict], depth: int = 2) -> Dict[str, Any]:
        """
        Analyze transaction flow patterns across multiple addresses.
        
        Args:
            transactions: List of transactions to analyze
            depth: How deep to analyze transaction patterns
            
        Returns:
            Dictionary with flow analysis results
        """
        # Extract transaction graph
        graph = {}
        node_values = {}
        
        for tx in transactions:
            source = tx.get("source", "unknown")
            
            # Process based on source and type
            if source == "trongrid":
                if tx.get("type") == "trx" and "raw_data" in tx:
                    raw_data = tx["raw_data"]
                    
                    if "contract" in raw_data and raw_data["contract"]:
                        contract = raw_data["contract"][0]
                        if "parameter" in contract and "value" in contract["parameter"]:
                            value = contract["parameter"]["value"]
                            
                            from_address = None
                            to_address = None
                            amount = 0
                            
                            if "owner_address" in value:
                                from_hex = value["owner_address"]
                                from_address = from_hex  # Would convert if needed
                            
                            if "to_address" in value:
                                to_hex = value["to_address"]
                                to_address = to_hex  # Would convert if needed
                            
                            if "amount" in value:
                                amount = value["amount"] / 1_000_000
                            
                            if from_address and to_address and amount > 0:
                                # Add to graph
                                if from_address not in graph:
                                    graph[from_address] = []
                                graph[from_address].append((to_address, amount))
                                
                                # Update node values
                                node_values[from_address] = node_values.get(from_address, 0) - amount
                                node_values[to_address] = node_values.get(to_address, 0) + amount
            
            elif source == "tronscan":
                if tx.get("type") == "trx":
                    contract_type = tx.get("contractType", "")
                    
                    if contract_type == "TransferContract":
                        from_address = tx.get("ownerAddress", "")
                        contract_data = tx.get("contractData", {})
                        to_address = contract_data.get("to_address", "")
                        amount = contract_data.get("amount", 0) / 1_000_000
                        
                        if from_address and to_address and amount > 0:
                            # Add to graph
                            if from_address not in graph:
                                graph[from_address] = []
                            graph[from_address].append((to_address, amount))
                            
                            # Update node values
                            node_values[from_address] = node_values.get(from_address, 0) - amount
                            node_values[to_address] = node_values.get(to_address, 0) + amount
        
        # Find potential layering patterns
        layering_paths = []
        
        # Start with outflow nodes (nodes with negative value)
        start_nodes = [addr for addr, value in node_values.items() if value < 0]
        
        for start_node in start_nodes:
            # Do a BFS to find paths
            for path in self._find_paths(graph, start_node, depth):
                # Calculate how much value flowed through this path
                if len(path) >= 3:  # At least 3 nodes in the path
                    layering_paths.append(path)
        
        # Calculate flow metrics
        flow_centrality = {}
        for addr in graph:
            # Out-degree
            out_degree = len(graph.get(addr, []))
            
            # In-degree
            in_degree = sum(1 for src in graph if any(dst == addr for dst, _ in graph[src]))
            
            # Centrality score
            if out_degree + in_degree > 0:
                flow_centrality[addr] = (out_degree + in_degree) / 2
        
        # Return results
        return {
            "transaction_count": len(transactions),
            "unique_addresses": len(graph),
            "layering_patterns": layering_paths,
            "flow_centrality": flow_centrality,
            "node_values": node_values
        }
    
    def _find_paths(self, graph, start_node, max_depth, current_path=None, visited=None):
        """Find all paths up to max_depth from start_node in the transaction graph."""
        if current_path is None:
            current_path = [start_node]
        if visited is None:
            visited = set([start_node])
        
        if len(current_path) > max_depth:
            yield current_path
            return
        
        # Get neighbors
        for neighbor, amount in graph.get(start_node, []):
            if neighbor not in visited:
                visited.add(neighbor)
                yield from self._find_paths(graph, neighbor, max_depth, current_path + [neighbor], visited)
                visited.remove(neighbor)
        
        # Return the current path at the end
        if len(current_path) > 1:
            yield current_path
    
    def detect_anomalies(self, transactions: List[Dict], addresses: List[str]) -> Dict[str, Any]:
        """
        Detect anomalies across multiple transactions and addresses.
        
        Args:
            transactions: List of transactions to analyze
            addresses: List of addresses to focus on
            
        Returns:
            Dictionary with anomaly detection results
        """
        # Build profiles for all addresses
        profiles = {}
        for address in addresses:
            # Filter transactions for this address
            addr_txs = []
            for tx in transactions:
                # Check if transaction is from TronGrid
                if tx.get("source") == "trongrid":
                    # Check TRX transfers
                    if tx.get("type") == "trx" and "raw_data" in tx and "contract" in tx["raw_data"]:
                        if tx["raw_data"]["contract"] and "parameter" in tx["raw_data"]["contract"][0]:
                            if "value" in tx["raw_data"]["contract"][0]["parameter"]:
                                value = tx["raw_data"]["contract"][0]["parameter"]["value"]
                                
                                # Check if address is sender
                                if "owner_address" in value and value["owner_address"] == address:
                                    addr_txs.append(tx)
                                    continue
                                
                                # Check if address is receiver
                                if "to_address" in value and value["to_address"] == address:
                                    addr_txs.append(tx)
                                    continue
                    
                    # Check TRC20 transfers
                    elif tx.get("type") == "trc20":
                        if tx.get("from") == address or tx.get("to") == address:
                            addr_txs.append(tx)
                            continue
                
                # Check if transaction is from Tronscan
                elif tx.get("source") == "tronscan":
                    # Check TRX transfers
                    if tx.get("type") == "trx":
                        if tx.get("ownerAddress") == address:
                            addr_txs.append(tx)
                            continue
                        
                        if tx.get("contractData", {}).get("to_address") == address:
                            addr_txs.append(tx)
                            continue
                    
                    # Check TRC20 transfers
                    elif tx.get("type") == "trc20":
                        if tx.get("from_address") == address or tx.get("to_address") == address:
                            addr_txs.append(tx)
                            continue
            
            # Build profile
            profiles[address] = self.build_address_profile(address, addr_txs)
        
        # Analyze transaction flow
        flow_analysis = self.analyze_transaction_flow(transactions)
        
        # Calculate anomaly scores
        anomaly_scores = {}
        for address, profile in profiles.items():
            score, factors = self.calculate_anomaly_score(address, profile)
            anomaly_scores[address] = {
                "score": score,
                "risk_factors": factors
            }
        
        # Overall analysis
        addresses_by_risk = sorted(anomaly_scores.items(), key=lambda x: x[1]["score"], reverse=True)
        high_risk = [addr for addr, data in addresses_by_risk if data["score"] >= 75]
        medium_risk = [addr for addr, data in addresses_by_risk if 25 <= data["score"] < 75]
        low_risk = [addr for addr, data in addresses_by_risk if data["score"] < 25]
        
        central_addresses = []
        if flow_analysis["flow_centrality"]:
            central_addresses = sorted(
                flow_analysis["flow_centrality"].items(),
                key=lambda x: x[1],
                reverse=True
            )[:5]
            
        return {
            "profiles": profiles,
            "flow_analysis": flow_analysis,
            "anomaly_scores": anomaly_scores,
            "risk_categories": {
                "high_risk": high_risk,
                "medium_risk": medium_risk,
                "low_risk": low_risk
            },
            "suspected_layering": flow_analysis["layering_patterns"],
            "central_addresses": central_addresses
        }