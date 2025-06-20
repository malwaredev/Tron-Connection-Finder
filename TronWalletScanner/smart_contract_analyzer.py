"""
TRON Smart Contract and Multi-Signature Transaction Analyzer

This module enhances the TRON Wallet Analyzer with capabilities to analyze
smart contract interactions and multi-signature transactions.
"""

import json
import time
import asyncio
import aiohttp
from typing import Dict, List, Any, Tuple, Optional

# TRON smart contract function signatures (commonly used functions)
FUNCTION_SIGNATURES = {
    # TRC20 Token Interface
    "a9059cbb": "transfer(address,uint256)",
    "095ea7b3": "approve(address,uint256)",
    "23b872dd": "transferFrom(address,address,uint256)",
    "70a08231": "balanceOf(address)",
    "18160ddd": "totalSupply()",
    "dd62ed3e": "allowance(address,address)",
    
    # TRC721 (NFT) Interface
    "6352211e": "ownerOf(uint256)",
    "42842e0e": "safeTransferFrom(address,address,uint256)",
    "b88d4fde": "safeTransferFrom(address,address,uint256,bytes)",
    "e985e9c5": "isApprovedForAll(address,address)",
    "a22cb465": "setApprovalForAll(address,bool)",
    
    # Multi-signature
    "c6427474": "submitTransaction(address,uint256,bytes)",
    "ee22610b": "confirmTransaction(uint256)",
    "20ea8d86": "revokeConfirmation(uint256)",
    "784547a7": "isConfirmed(uint256)",
    "8b51d13f": "getConfirmationCount(uint256)",
    "3411c81c": "getTransactionCount(bool,bool)",
    
    # DeFi Functions
    "e8e33700": "addLiquidity(address,address,uint256,uint256)",
    "38ed1739": "swapExactTokensForTokens(uint256,uint256,address[],address,uint256)",
    "7ff36ab5": "swapExactETHForTokens(uint256,address[],address,uint256)",
    "4a25d94a": "swapTokensForExactETH(uint256,uint256,address[],address,uint256)",
    "5c11d795": "swapExactTokensForETH(uint256,uint256,address[],address,uint256)",
    
    # TRON Specific
    "faa5d46c": "freezeBalance(uint256,uint64,uint8)",
    "d126d72c": "unfreezeBalance(uint256,uint8)",
    "ba72e001": "voteWitness(address[],uint256[])",
    "e75f9d67": "withdrawBalance()",
    
    # Governance
    "c9d27afe": "vote(uint256)",
    "b384abef": "propose(address[],uint256[],string[],bytes[])",
    "c01f9e37": "queue(uint256)",
    "3a66f901": "execute(uint256)",
    
    # Staking
    "a694fc3a": "stake(uint256)",
    "2e17de78": "unstake(uint256)",
    "3d18b912": "getReward()",
    
    # Proxy Patterns
    "3659cfe6": "upgradeTo(address)",
    "4f1ef286": "upgradeToAndCall(address,bytes)",
    "8f283970": "changeAdmin(address)"
}

# Known smart contract types and their characteristics
CONTRACT_TYPES = {
    "TRC20_Token": {
        "required_functions": ["transfer", "approve", "balanceOf", "totalSupply"],
        "description": "Standard fungible token contract"
    },
    "TRC721_NFT": {
        "required_functions": ["ownerOf", "safeTransferFrom", "balanceOf"],
        "description": "Non-fungible token contract"
    },
    "MultiSig_Wallet": {
        "required_functions": ["submitTransaction", "confirmTransaction", "revokeConfirmation"],
        "description": "Multi-signature wallet requiring multiple approvals"
    },
    "DEX_Pool": {
        "required_functions": ["addLiquidity", "swapExactTokensForTokens"],
        "description": "Decentralized exchange liquidity pool"
    },
    "Staking_Contract": {
        "required_functions": ["stake", "unstake", "getReward"],
        "description": "Token staking contract"
    },
    "Governance": {
        "required_functions": ["propose", "vote", "queue", "execute"],
        "description": "On-chain governance contract"
    },
    "Proxy": {
        "required_functions": ["upgradeTo"],
        "description": "Upgradeable proxy contract"
    }
}

# Risk patterns in smart contract interactions
CONTRACT_RISK_PATTERNS = {
    "Unlimited_Approval": {
        "description": "Approving a very large amount of tokens (unlimited approval)",
        "risk_level": "Medium",
        "function": "approve",
        "detection": "amount >= 2^254"
    },
    "Admin_Change": {
        "description": "Changing the admin/owner of a contract",
        "risk_level": "High",
        "functions": ["changeAdmin", "transferOwnership"],
        "detection": "function_call_present"
    },
    "Self_Destruct": {
        "description": "Self-destructing a contract or removing essential features",
        "risk_level": "Critical",
        "functions": ["selfdestruct", "suicide"],
        "detection": "function_call_present"
    },
    "Multiple_Transfers": {
        "description": "Multiple transfers to the same address in short time",
        "risk_level": "Medium",
        "function": "transfer",
        "detection": "frequency_threshold"
    },
    "Proxy_Upgrade": {
        "description": "Upgrading a proxy contract implementation",
        "risk_level": "High",
        "functions": ["upgradeTo", "upgradeToAndCall"],
        "detection": "function_call_present"
    }
}

class SmartContractAnalyzer:
    """Analyzer for TRON smart contract interactions and multi-signature transactions."""
    
    def __init__(self, trongrid_api_key=None, tronscan_api_key=None):
        """
        Initialize the smart contract analyzer.
        
        Args:
            trongrid_api_key: API key for TronGrid
            tronscan_api_key: API key for Tronscan
        """
        self.trongrid_api_key = trongrid_api_key
        self.tronscan_api_key = tronscan_api_key
        self.contract_cache = {}
        self.function_cache = {}
        
        # Setup headers
        self.headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        
        if self.trongrid_api_key:
            self.headers["TRON-PRO-API-KEY"] = self.trongrid_api_key
            
        self.tronscan_headers = {
            "Accept": "application/json",
            "Content-Type": "application/json"
        }
        
        if self.tronscan_api_key:
            self.tronscan_headers["TRON-PRO-API-KEY"] = self.tronscan_api_key
    
    async def get_contract_details(self, contract_address: str) -> Dict[str, Any]:
        """
        Get detailed information about a smart contract.
        
        Args:
            contract_address: The contract address
            
        Returns:
            Dictionary with contract details
        """
        # Check cache first
        if contract_address in self.contract_cache:
            return self.contract_cache[contract_address]
        
        # Try to get from TronGrid first
        contract_info = None
        
        if self.trongrid_api_key:
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(
                        f"https://api.trongrid.io/v1/contracts/{contract_address}",
                        headers=self.headers,
                        timeout=10
                    ) as response:
                        if response.status == 200:
                            data = await response.json()
                            if "data" in data and len(data["data"]) > 0:
                                contract_info = data["data"][0]
                except Exception as e:
                    print(f"Error fetching contract from TronGrid: {str(e)}")
        
        # Fall back to Tronscan if needed
        if not contract_info and self.tronscan_api_key:
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(
                        f"https://apilist.tronscan.org/api/contract?contract={contract_address}",
                        headers=self.tronscan_headers,
                        timeout=10
                    ) as response:
                        if response.status == 200:
                            data = await response.json()
                            if "data" in data and len(data["data"]) > 0:
                                contract_info = data["data"][0]
                except Exception as e:
                    print(f"Error fetching contract from Tronscan: {str(e)}")
        
        # Process and return the contract details
        result = {
            "address": contract_address,
            "found": contract_info is not None,
            "name": contract_info.get("name", "Unknown") if contract_info else "Unknown",
            "abi": contract_info.get("abi", []) if contract_info else [],
            "bytecode": contract_info.get("bytecode", "") if contract_info else "",
            "verified": bool(contract_info.get("verified", False)) if contract_info else False,
            "creation_timestamp": contract_info.get("creation_timestamp", 0) if contract_info else 0
        }
        
        # Determine contract type
        if result["abi"]:
            result["contract_type"] = self._determine_contract_type(result["abi"])
        else:
            result["contract_type"] = "Unknown"
        
        # Cache the result
        self.contract_cache[contract_address] = result
        
        return result
    
    def _determine_contract_type(self, abi: List[Dict]) -> str:
        """
        Determine the type of contract based on its ABI.
        
        Args:
            abi: The contract ABI
            
        Returns:
            Contract type string
        """
        if not abi:
            return "Unknown"
        
        # Extract function names
        function_names = set()
        for item in abi:
            if item.get("type") == "function":
                function_names.add(item.get("name", ""))
        
        # Check for each contract type
        for contract_type, type_info in CONTRACT_TYPES.items():
            required_functions = set(type_info["required_functions"])
            if required_functions.issubset(function_names):
                return contract_type
        
        return "Custom"
    
    async def analyze_transaction(self, tx_hash: str) -> Dict[str, Any]:
        """
        Analyze a smart contract transaction.
        
        Args:
            tx_hash: Transaction hash
            
        Returns:
            Dictionary with transaction analysis
        """
        # Try to get transaction info from TronGrid first
        tx_info = None
        
        if self.trongrid_api_key:
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(
                        f"https://api.trongrid.io/v1/transactions/{tx_hash}",
                        headers=self.headers,
                        timeout=10
                    ) as response:
                        if response.status == 200:
                            data = await response.json()
                            if "data" in data and len(data["data"]) > 0:
                                tx_info = data["data"][0]
                except Exception as e:
                    print(f"Error fetching transaction from TronGrid: {str(e)}")
        
        # Fall back to Tronscan if needed
        if not tx_info and self.tronscan_api_key:
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(
                        f"https://apilist.tronscan.org/api/transaction-info?hash={tx_hash}",
                        headers=self.tronscan_headers,
                        timeout=10
                    ) as response:
                        if response.status == 200:
                            tx_info = await response.json()
                except Exception as e:
                    print(f"Error fetching transaction from Tronscan: {str(e)}")
        
        if not tx_info:
            return {
                "hash": tx_hash,
                "found": False,
                "error": "Transaction not found"
            }
        
        # Process transaction data
        is_contract_call = False
        contract_address = None
        function_signature = None
        function_name = "Unknown"
        params = []
        
        # Process based on source
        if "contract_address" in tx_info:  # Tronscan format
            is_contract_call = True
            contract_address = tx_info.get("contract_address", "")
            data = tx_info.get("data", "")
            
            if data and len(data) >= 10:
                function_signature = data[:8]
                function_name = FUNCTION_SIGNATURES.get(function_signature, "Unknown")
                
                # TODO: Parse parameters from data
                # This requires ABI knowledge and complex decoding
                
        elif "raw_data" in tx_info:  # TronGrid format
            raw_data = tx_info["raw_data"]
            if "contract" in raw_data and raw_data["contract"]:
                contract = raw_data["contract"][0]
                
                if contract.get("type") == "TriggerSmartContract":
                    is_contract_call = True
                    if "parameter" in contract and "value" in contract["parameter"]:
                        value = contract["parameter"]["value"]
                        contract_address = value.get("contract_address", "")
                        data = value.get("data", "")
                        
                        if data and len(data) >= 10:
                            function_signature = data[:8]
                            function_name = FUNCTION_SIGNATURES.get(function_signature, "Unknown")
                            
                            # TODO: Parse parameters from data
                
                # Check for multi-signature
                elif contract.get("type") == "AccountPermissionUpdateContract":
                    if "parameter" in contract and "value" in contract["parameter"]:
                        value = contract["parameter"]["value"]
                        # Check for adding multiple keys (multi-sig setup)
                        if "active_permission" in value:
                            for perm in value["active_permission"]:
                                if "keys" in perm and len(perm["keys"]) > 1:
                                    return {
                                        "hash": tx_hash,
                                        "found": True,
                                        "is_contract_call": False,
                                        "is_multisig_setup": True,
                                        "multisig_threshold": perm.get("threshold", 0),
                                        "multisig_keys": len(perm.get("keys", [])),
                                        "timestamp": tx_info.get("block_timestamp", 0),
                                        "status": tx_info.get("ret", [{}])[0].get("contractRet", "UNKNOWN")
                                    }
        
        # Get contract details if this is a contract call
        contract_details = None
        if is_contract_call and contract_address:
            try:
                contract_details = await self.get_contract_details(contract_address)
            except Exception as e:
                print(f"Error getting contract details: {str(e)}")
        
        # Check for risk patterns
        risk_assessment = self._assess_contract_risks(function_name, params)
        
        # Build the result
        result = {
            "hash": tx_hash,
            "found": True,
            "is_contract_call": is_contract_call,
            "timestamp": tx_info.get("block_timestamp", 0) if "block_timestamp" in tx_info else tx_info.get("timestamp", 0),
            "status": tx_info.get("ret", [{}])[0].get("contractRet", "UNKNOWN") if "ret" in tx_info else tx_info.get("contractRet", "UNKNOWN"),
            "energy_usage": tx_info.get("energy_usage", 0) if "energy_usage" in tx_info else tx_info.get("cost", {}).get("energy", 0),
            "result": tx_info.get("ret", [{}])[0].get("contractRet", "") if "ret" in tx_info else tx_info.get("contractRet", "")
        }
        
        if is_contract_call:
            result.update({
                "contract_address": contract_address,
                "function_signature": function_signature,
                "function_name": function_name,
                "contract_type": contract_details.get("contract_type", "Unknown") if contract_details else "Unknown",
                "risk_assessment": risk_assessment
            })
        
        return result
    
    def _assess_contract_risks(self, function_name: str, params: List) -> Dict[str, Any]:
        """
        Assess risks in a contract interaction.
        
        Args:
            function_name: Name of the called function
            params: Function parameters
            
        Returns:
            Dictionary with risk assessment
        """
        risks = []
        
        # Check function name against known risk patterns
        for risk_id, risk_info in CONTRACT_RISK_PATTERNS.items():
            if risk_info.get("function") == function_name or function_name in risk_info.get("functions", []):
                if risk_info["detection"] == "function_call_present":
                    risks.append({
                        "id": risk_id,
                        "description": risk_info["description"],
                        "level": risk_info["risk_level"],
                        "confidence": 0.9
                    })
                
                # TODO: Add more complex detection logic for other risk patterns
                # This would require parameter decoding
        
        return {
            "has_risks": len(risks) > 0,
            "risks": risks
        }
    
    async def analyze_multisig_wallet(self, address: str) -> Dict[str, Any]:
        """
        Analyze a multi-signature wallet.
        
        Args:
            address: The wallet address
            
        Returns:
            Dictionary with wallet analysis
        """
        # Try to determine if this is a multi-sig wallet
        contract_details = await self.get_contract_details(address)
        
        if not contract_details["found"]:
            return {
                "address": address,
                "is_multisig": False,
                "error": "Address not found or not a contract"
            }
        
        is_multisig = contract_details["contract_type"] == "MultiSig_Wallet"
        
        if not is_multisig:
            # Check if there are multi-sig functions in the ABI
            if contract_details["abi"]:
                multisig_functions = ["confirmTransaction", "submitTransaction", "executeTransaction"]
                for item in contract_details["abi"]:
                    if item.get("type") == "function" and item.get("name", "") in multisig_functions:
                        is_multisig = True
                        break
        
        # Get transactions for this address
        transactions = []
        
        if self.trongrid_api_key:
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(
                        f"https://api.trongrid.io/v1/accounts/{address}/transactions",
                        headers=self.headers,
                        params={"limit": 50},
                        timeout=15
                    ) as response:
                        if response.status == 200:
                            data = await response.json()
                            if "data" in data:
                                transactions = data["data"]
                except Exception as e:
                    print(f"Error fetching transactions from TronGrid: {str(e)}")
        
        # If no transactions from TronGrid, try Tronscan
        if not transactions and self.tronscan_api_key:
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(
                        f"https://apilist.tronscan.org/api/transaction",
                        headers=self.tronscan_headers,
                        params={"address": address, "limit": 50},
                        timeout=15
                    ) as response:
                        if response.status == 200:
                            data = await response.json()
                            if "data" in data:
                                transactions = data["data"]
                except Exception as e:
                    print(f"Error fetching transactions from Tronscan: {str(e)}")
        
        # Analyze multi-sig behavior
        owners = set()
        confirmations = {}
        proposals = {}
        
        if is_multisig:
            for tx in transactions:
                # Process based on source format
                if "raw_data" in tx:  # TronGrid format
                    raw_data = tx["raw_data"]
                    if "contract" in raw_data and raw_data["contract"]:
                        contract = raw_data["contract"][0]
                        if contract.get("type") == "TriggerSmartContract":
                            if "parameter" in contract and "value" in contract["parameter"]:
                                value = contract["parameter"]["value"]
                                data = value.get("data", "")
                                
                                if data and len(data) >= 10:
                                    func_sig = data[:8]
                                    
                                    if func_sig == "c6427474":  # submitTransaction
                                        proposals[tx.get("txID", "")] = {
                                            "proposer": value.get("owner_address", ""),
                                            "timestamp": raw_data.get("timestamp", 0)
                                        }
                                        owners.add(value.get("owner_address", ""))
                                    
                                    elif func_sig == "ee22610b":  # confirmTransaction
                                        tx_id = tx.get("txID", "")
                                        if tx_id not in confirmations:
                                            confirmations[tx_id] = []
                                        confirmations[tx_id].append({
                                            "confirmer": value.get("owner_address", ""),
                                            "timestamp": raw_data.get("timestamp", 0)
                                        })
                                        owners.add(value.get("owner_address", ""))
                elif "data" in tx:  # Tronscan format
                    data = tx.get("data", "")
                    if data and len(data) >= 10:
                        func_sig = data[:8]
                        
                        if func_sig == "c6427474":  # submitTransaction
                            proposals[tx.get("hash", "")] = {
                                "proposer": tx.get("ownerAddress", ""),
                                "timestamp": tx.get("timestamp", 0)
                            }
                            owners.add(tx.get("ownerAddress", ""))
                        
                        elif func_sig == "ee22610b":  # confirmTransaction
                            tx_id = tx.get("hash", "")
                            if tx_id not in confirmations:
                                confirmations[tx_id] = []
                            confirmations[tx_id].append({
                                "confirmer": tx.get("ownerAddress", ""),
                                "timestamp": tx.get("timestamp", 0)
                            })
                            owners.add(tx.get("ownerAddress", ""))
        
        return {
            "address": address,
            "is_multisig": is_multisig,
            "contract_type": contract_details["contract_type"],
            "owners": list(owners),
            "owner_count": len(owners),
            "proposals": len(proposals),
            "latest_transactions": [{
                "hash": tx.get("txID", tx.get("hash", "")),
                "timestamp": tx.get("block_timestamp", tx.get("timestamp", 0)),
                "type": tx.get("raw_data", {}).get("contract", [{}])[0].get("type", "Unknown") if "raw_data" in tx else tx.get("contractType", "Unknown")
            } for tx in transactions[:5]]
        }
    
    async def decode_function_call(self, data: str, contract_address: str = None) -> Dict[str, Any]:
        """
        Decode a smart contract function call.
        
        Args:
            data: The function call data (hex string)
            contract_address: Optional contract address for ABI lookup
            
        Returns:
            Dictionary with decoded function information
        """
        if not data or len(data) < 10:
            return {
                "success": False,
                "error": "Invalid function data"
            }
        
        # Extract function signature
        function_signature = data[:8]
        function_name = FUNCTION_SIGNATURES.get(function_signature, "Unknown")
        
        result = {
            "success": True,
            "function_signature": function_signature,
            "function_name": function_name
        }
        
        # If we have a contract address, try to get its ABI for better decoding
        if contract_address:
            try:
                contract_details = await self.get_contract_details(contract_address)
                if contract_details["found"] and contract_details["abi"]:
                    # TODO: Use ABI to decode parameters
                    # This requires complex parameter decoding logic
                    pass
            except Exception as e:
                print(f"Error getting contract details for parameter decoding: {str(e)}")
        
        return result
    
    async def analyze_contract_transactions(self, contract_address: str, limit: int = 20) -> Dict[str, Any]:
        """
        Analyze transactions involving a smart contract.
        
        Args:
            contract_address: The contract address
            limit: Maximum number of transactions to analyze
            
        Returns:
            Dictionary with contract transaction analysis
        """
        # First get contract details
        contract_details = await self.get_contract_details(contract_address)
        
        if not contract_details["found"]:
            return {
                "address": contract_address,
                "found": False,
                "error": "Contract not found"
            }
        
        # Get transactions for this contract
        transactions = []
        
        if self.trongrid_api_key:
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(
                        f"https://api.trongrid.io/v1/contracts/{contract_address}/transactions",
                        headers=self.headers,
                        params={"limit": limit},
                        timeout=15
                    ) as response:
                        if response.status == 200:
                            data = await response.json()
                            if "data" in data:
                                transactions = data["data"]
                except Exception as e:
                    print(f"Error fetching contract transactions from TronGrid: {str(e)}")
        
        # If no transactions from TronGrid, try Tronscan
        if not transactions and self.tronscan_api_key:
            async with aiohttp.ClientSession() as session:
                try:
                    async with session.get(
                        f"https://apilist.tronscan.org/api/contract/transactions",
                        headers=self.tronscan_headers,
                        params={"contract": contract_address, "limit": limit},
                        timeout=15
                    ) as response:
                        if response.status == 200:
                            data = await response.json()
                            if "data" in data:
                                transactions = data["data"]
                except Exception as e:
                    print(f"Error fetching contract transactions from Tronscan: {str(e)}")
        
        # Analyze function calls
        function_calls = {}
        callers = set()
        
        for tx in transactions:
            # Process based on source format
            function_signature = None
            caller = None
            
            if "raw_data" in tx:  # TronGrid format
                raw_data = tx["raw_data"]
                if "contract" in raw_data and raw_data["contract"]:
                    contract = raw_data["contract"][0]
                    if contract.get("type") == "TriggerSmartContract":
                        if "parameter" in contract and "value" in contract["parameter"]:
                            value = contract["parameter"]["value"]
                            data = value.get("data", "")
                            caller = value.get("owner_address", "")
                            
                            if data and len(data) >= 10:
                                function_signature = data[:8]
            
            elif "data" in tx:  # Tronscan format
                data = tx.get("data", "")
                caller = tx.get("ownerAddress", "")
                
                if data and len(data) >= 10:
                    function_signature = data[:8]
            
            # Record function call
            if function_signature:
                function_name = FUNCTION_SIGNATURES.get(function_signature, "Unknown")
                if function_name not in function_calls:
                    function_calls[function_name] = 0
                function_calls[function_name] += 1
            
            # Record caller
            if caller:
                callers.add(caller)
        
        # Sort function calls by frequency
        sorted_functions = sorted(function_calls.items(), key=lambda x: x[1], reverse=True)
        
        return {
            "address": contract_address,
            "found": True,
            "contract_type": contract_details["contract_type"],
            "transaction_count": len(transactions),
            "unique_callers": len(callers),
            "most_used_functions": sorted_functions[:5],
            "latest_transactions": [{
                "hash": tx.get("txID", tx.get("hash", "")),
                "timestamp": tx.get("block_timestamp", tx.get("timestamp", 0)),
                "caller": tx.get("raw_data", {}).get("contract", [{}])[0].get("parameter", {}).get("value", {}).get("owner_address", "Unknown") if "raw_data" in tx else tx.get("ownerAddress", "Unknown")
            } for tx in transactions[:5]]
        }