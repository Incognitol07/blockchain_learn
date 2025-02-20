#node.py

import binascii
import hashlib
import json
import threading
from fastapi import Request
from fastapi.responses import JSONResponse
import time
from collections import OrderedDict
from concurrent.futures import ThreadPoolExecutor, as_completed
from logging import getLogger
from threading import Lock
from typing import List
from urllib.parse import urlparse
from Cryptodome.Hash import SHA
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5
from fastapi import FastAPI, HTTPException
from pydantic import BaseModel
import requests

logger = getLogger()
MINING_SENDER = "0"

# --- Core Blockchain Classes ---
class Transaction:
    def __init__(self, sender_pubkey: str, signature: str, recipient_pubkey: str, amount: float):
        self.sender = sender_pubkey
        self.recipient = recipient_pubkey
        self.amount = amount
        self.signature = signature
        self.timestamp = time.time()
        self.tx_hash = self.calculate_hash()

    def calculate_hash(self) -> str:
        payload = f"{self.sender}{self.recipient}{self.amount}{self.timestamp}".encode()
        return hashlib.sha256(payload).hexdigest()

    def serialize(self) -> dict:
        return OrderedDict({
            'sender': self.sender,
            'recipient': self.recipient,
            'amount': self.amount,
            'signature': self.signature,
            'hash': self.tx_hash,
            'timestamp': self.timestamp
        })

class Wallet:
    def __init__(self):
        self.private_key, self.public_key = self.generate_keys()
        
    @staticmethod
    def generate_keys() -> tuple:
        key = RSA.generate(2048)
        private_key = binascii.hexlify(key.export_key(format='DER')).decode()
        public_key = binascii.hexlify(key.publickey().export_key(format='DER')).decode()
        return private_key, public_key

    def sign_transaction(self, recipient: str, amount: float) -> Transaction:
        payload = f"{self.public_key}{recipient}{amount}{time.time()}".encode()
        h = SHA.new(payload)
        signer = PKCS1_v1_5.new(RSA.import_key(binascii.unhexlify(self.private_key)))
        signature = binascii.hexlify(signer.sign(h)).decode()
        return Transaction(self.public_key, signature, recipient, amount)

class Blockchain:
    """Distributed ledger system with consensus mechanism"""
    def __init__(self):
        self.chain = []
        self.pending_txs = []
        self.nodes = set()
        self.wallets = {}
        self.lock = Lock()
        self.difficulty = 4
        self.miner_wallet = Wallet()  # Add this line
        self.node_id = self.miner_wallet.public_key
        
        # Create genesis block
        self._create_block(nonce=100, previous_hash='0')

    @staticmethod
    def hash(block: dict) -> str:
        block_string = json.dumps(block, sort_keys=True).encode()
        return hashlib.sha256(block_string).hexdigest()

    # --- Core Blockchain Operations ---
    
    def _create_block(self, nonce: int, previous_hash: str) -> dict:
        """Internal block creation method"""
        block = {
            'index': len(self.chain) + 1,
            'timestamp': time.time(),
            'transactions': [tx.serialize() for tx in self.pending_txs],
            'nonce': nonce,
            'previous_hash': previous_hash,
            'merkle_root': self._calculate_merkle_root(),
        }
        
        self.pending_txs = []
        self.chain.append(block)
        return block
    
    def _validate_transaction(self, tx: Transaction) -> bool:
        """Full transaction validation including cryptographic verification"""
        try:
            # Validate signature
            sender_key = RSA.import_key(binascii.unhexlify(tx.sender))
            verifier = PKCS1_v1_5.new(sender_key)
            payload = f"{tx.sender}{tx.recipient}{tx.amount}{tx.timestamp}".encode()
            h = SHA.new(payload)
            if not verifier.verify(h, binascii.unhexlify(tx.signature)):
                return False

            # Validate balance
            balance = self.get_balance(tx.sender)
            return balance >= tx.amount
            
        except (ValueError, TypeError):
            return False
        
    def get_balance(self, pubkey: str) -> float:
        """Proper balance calculation considering both inflows and outflows"""
        balance = 0.0
        for block in self.chain:
            for tx in block['transactions']:
                if tx['recipient'] == pubkey:
                    balance += tx['amount']
                if tx['sender'] == pubkey:
                    balance -= tx['amount']
        return balance

    def _calculate_merkle_root(self) -> str:
        """Compute Merkle root for current transactions"""
        tx_hashes = [tx.tx_hash for tx in self.pending_txs]
        if not tx_hashes: return ''
        
        while len(tx_hashes) > 1:
            if len(tx_hashes) % 2 != 0:
                tx_hashes.append(tx_hashes[-1])
            tx_hashes = [hashlib.sha256(l + r).hexdigest() 
                        for l, r in zip(tx_hashes[::2], tx_hashes[1::2])]
        return tx_hashes[0]

    def _valid_proof(self, last_nonce: int, nonce: int) -> bool:
        """Proof-of-work validation"""
        guess = f"{last_nonce}{nonce}".encode()
        return hashlib.sha256(guess).hexdigest()[:self.difficulty] == '0' * self.difficulty

    # --- Network Operations ---
    
    def register_node(self, address: str, propagate=True):
        parsed = urlparse(address)
        node = parsed.netloc or parsed.path
        if node not in self.nodes:
            self.nodes.add(node)
            if propagate:
                self._propagate_node(node)
    
    def _propagate_node(self, new_node: str):
        """Inform other nodes about new network participants"""
        for node in self.nodes:
            if node != new_node:
                try:
                    requests.post(
                        f'http://{node}/nodes',
                        json={'nodes': [new_node]},
                        timeout=1
                    )
                except requests.exceptions.RequestException:
                    logger.warning(f"Failed to propagate node {new_node} to {node}")

    def resolve_conflicts(self) -> bool:
        """Consensus algorithm (longest valid chain)"""
        with ThreadPoolExecutor() as executor:
            neighbors = list(self.nodes)
            futures = {executor.submit(self._fetch_chain, node): node for node in neighbors}
            
            max_length = len(self.chain)
            new_chain = None
            
            for future in as_completed(futures):
                try:
                    chain = future.result()
                    if chain and len(chain) > max_length and self._valid_chain(chain):
                        max_length = len(chain)
                        new_chain = chain

                    if new_chain:
                        old_chain = self.chain.copy()
                        self.chain = new_chain

                        # Find split point between chains
                        split_index = 0
                        for i in range(min(len(old_chain), len(new_chain))):
                            if self.hash(old_chain[i]) != self.hash(new_chain[i]):
                                split_index = i
                                break
                        else:
                            split_index = min(len(old_chain), len(new_chain))

                        # Re-add orphaned transactions
                        for block in old_chain[split_index:]:
                            for tx in block['transactions']:
                                # Skip coinbase transactions and duplicates
                                if tx['sender'] != "0" and tx not in self.current_transactions:
                                    self.current_transactions.append(tx)
                        self.current_transactions = [tx for tx in self.current_transactions if not any(tx['tx_hash'] in (b_tx.get('tx_hash') for b in new_chain for b_tx in b['transactions'])) ]

                        return True
                    return False
                except Exception as e:
                    logger.error(f"Chain validation failed: {e}")

            if new_chain:
                self._handle_chain_replacement(new_chain)
                return True
            return False

    # --- Helper Methods ---
    
    def _fetch_chain(self, node: str) -> list:
        """Retrieve chain from network node"""
        resp = requests.get(f'http://{node}/chain', timeout=5)
        return resp.json()['chain'] if resp.ok else None

    def _valid_chain(self, chain: list) -> bool:
        """Full chain validation including transaction verification"""
        if not chain: return False
        
        last_block = chain[0]
        for idx in range(1, len(chain)):
            block = chain[idx]
            
            # Validate block structure
            if block['previous_hash'] != self.hash(last_block):
                return False
            if not self._valid_proof(last_block['nonce'], block['nonce']):
                return False
                
            # Validate all transactions in block
            for tx_data in block['transactions']:
                tx = Transaction(**tx_data)
                if tx.sender != MINING_SENDER and not self._validate_transaction(tx):
                    return False
                    
            last_block = block
        return True
    
    def _handle_chain_replacement(self, new_chain: list):
        """Handle chain replacement and transaction re-broadcasting"""
        old_chain = self.chain.copy()
        self.chain = new_chain
        
        # Find divergence point
        split_idx = next((i for i, (a, b) in enumerate(zip(old_chain, new_chain)) 
                        if a['previous_hash'] != b['previous_hash']), len(old_chain))
        
        # Re-add valid orphaned transactions
        for block in old_chain[split_idx:]:
            for tx in block['transactions']:
                if tx['sender'] != MINING_SENDER:
                    self.pending_txs.append(Transaction(**tx))
    
    async def propagate_block(self, block: dict):
        """Broadcast new block to all registered nodes"""
        for node in self.nodes:
            try:
                requests.post(
                    f'http://{node}/blocks', 
                    json=block,
                    timeout=2)
            except requests.exceptions.RequestException:
                logger.error(f"Failed to propagate to {node}")

# --- API Setup ---

app = FastAPI(title="Decentralized Blockchain Network")
blockchain = Blockchain()

class TransactionRequest(BaseModel):
    sender_pubkey: str
    signature: str
    recipient: str
    amount: float

class NodeRegistration(BaseModel):
    nodes: List[str]

@app.post('/transactions', status_code=201)
def create_transaction(tx: TransactionRequest):
    new_tx = Transaction(
        tx.sender_pubkey,
        tx.signature,
        tx.recipient,
        tx.amount
    )
    
    if not blockchain._validate_transaction(new_tx):
        raise HTTPException(400, "Invalid transaction")
        
    blockchain.pending_txs.append(new_tx)
    return {"tx_hash": new_tx.tx_hash}

@app.post('/nodes', status_code=201)
def register_nodes(nodes: NodeRegistration):
    for node in nodes.nodes:
        blockchain.register_node(node, propagate=True)
    return {"message": f"{len(nodes.nodes)} nodes added"}


@app.get('/chain')
def get_chain():
    """Return full blockchain"""
    return {'chain': blockchain.chain, 'length': len(blockchain.chain)}


@app.get('/balance/{pubkey}')
def get_balance(pubkey: str):
    return {'balance': blockchain.get_balance(pubkey)}



@app.post('/mine')
def mine_block():
    """Mine new block with pending transactions"""
    with blockchain.lock:
        valid_txs = [tx for tx in blockchain.pending_txs if blockchain._validate_transaction(tx)]
        blockchain.pending_txs = valid_txs

        last_block = blockchain.chain[-1]
        nonce = 0
        
        # Proof-of-work computation
        while not blockchain._valid_proof(last_block['nonce'], nonce):
            nonce += 1
            
        # Create coinbase transaction
        coinbase = Transaction(
            sender_pubkey=MINING_SENDER,
            signature="0",  # Special value for coinbase
            recipient_pubkey=blockchain.miner_wallet.public_key,
            amount=1.0
        )
        
        # Add to pending transactions
        blockchain.pending_txs.insert(0, coinbase)
        
        # Create new block
        new_block = blockchain._create_block(nonce, blockchain.hash(last_block))
        
        # Propagate block
        threading.Thread(target=blockchain.propagate_block, args=(new_block,)).start()
        
        return {
            'message': 'New block forged',
            'block': new_block,
            'reward': 1.0
        }


@app.post('/blocks')
async def receive_block(request: Request):
    """Webhook endpoint for receiving new blocks"""
    block = await request.json()
    
    with blockchain.lock:
        # Validate block structure
        if not all(key in block for key in ['index', 'transactions', 'nonce', 'previous_hash']):
            return JSONResponse({"error": "Invalid block structure"}, status_code=400)
        
        # Validate proof-of-work
        last_block = blockchain.chain[-1]
        if not blockchain._valid_proof(last_block['nonce'], block['nonce']):
            return JSONResponse({"error": "Invalid proof"}, status_code=400)
        
        # Validate previous hash
        if block['previous_hash'] != blockchain.hash(last_block):
            logger.info("Chain divergence detected, triggering consensus")
            blockchain.resolve_conflicts()
            return JSONResponse({"message": "Divergence handled"}, status_code=200)
        
        # Add to chain if valid
        blockchain.chain.append(block)
        logger.info(f"New block added: {block['index']}")
        return JSONResponse({"message": "Block accepted"}, status_code=200)