# blockchain_client.py
from fastapi import FastAPI, HTTPException, Depends
from pydantic import BaseModel
from contextlib import asynccontextmanager
import requests
import os

@asynccontextmanager
async def lifespan(app: FastAPI):
    """Manage application lifespan events."""
    print("Starting up the application...")
    os.makedirs(WALLET_DIR, exist_ok=True)
    try:
        yield
    finally:
        print("Shutting down the application...")

app = FastAPI(title="Blockchain Client Interface", lifespan=lifespan)

# Import your existing ClientWallet class
from client_wallet import ClientWallet  # Use your existing implementation

# Configuration
DEFAULT_NODE = "http://localhost:8000"
WALLET_DIR = "./wallets"

class TransactionRequest(BaseModel):
    recipient: str
    amount: float
    node_url: str = DEFAULT_NODE

class WalletCreateRequest(BaseModel):
    password: str
    filename: str = "default_wallet.enc"

class WalletLoadRequest(BaseModel):
    password: str
    filename: str = "default_wallet.enc"

class NodeInteraction:
    def __init__(self, node_url: str = DEFAULT_NODE):
        self.node_url = node_url
        
    def get_balance(self, pubkey: str) -> float:
        try:
            response = requests.get(f"{self.node_url}/balance/{pubkey}")
            return response.json()['balance']
        except requests.exceptions.RequestException as e:
            raise HTTPException(500, f"Node connection failed: {str(e)}")

    def submit_transaction(self, transaction_data: dict):
        try:
            response = requests.post(
                f"{self.node_url}/transactions",
                json=transaction_data
            )
            return response.json()
        except requests.exceptions.RequestException as e:
            raise HTTPException(500, f"Transaction submission failed: {str(e)}")

def validate_wallet_path(filename: str):
    full_path = os.path.join(WALLET_DIR, filename)
    if not os.path.abspath(full_path).startswith(os.path.abspath(WALLET_DIR)):
        raise HTTPException(400, "Invalid wallet path")
    return full_path



@app.post("/wallet/create")
async def create_wallet(request: WalletCreateRequest):
    """Create new encrypted wallet"""
    try:
        wallet = ClientWallet()
        full_path = validate_wallet_path(request.filename)
        wallet.save_to_file(request.password, full_path)
        return {"public_key": wallet.public_key}
    except Exception as e:
        raise HTTPException(500, f"Wallet creation failed: {str(e)}")

@app.post("/wallet/load")
async def load_wallet(request: WalletLoadRequest):
    """Load existing wallet"""
    try:
        full_path = validate_wallet_path(request.filename)
        wallet = ClientWallet.load_from_file(request.password, full_path)
        return {"public_key": wallet.public_key}
    except Exception as e:
        raise HTTPException(400, f"Wallet loading failed: {str(e)}")

@app.post("/transaction/create")
async def create_transaction(request: TransactionRequest, pubkey: str = "test_pubkey"):
    """Create and submit transaction"""
    try:
        # In real usage, get pubkey from loaded wallet
        wallet = ClientWallet()  # Replace with loaded wallet in actual implementation
        
        # Create signed transaction
        tx_data = wallet.sign_transaction(
            recipient=request.recipient,
            amount=request.amount
        )
        
        # Submit to blockchain node
        node = NodeInteraction(request.node_url)
        return node.submit_transaction(tx_data)
    except Exception as e:
        raise HTTPException(500, f"Transaction failed: {str(e)}")

@app.get("/balance/{pubkey}")
async def get_balance(pubkey: str, node_url: str = DEFAULT_NODE):
    """Get balance from blockchain network"""
    try:
        node = NodeInteraction(node_url)
        return {"balance": node.get_balance(pubkey)}
    except Exception as e:
        raise HTTPException(500, f"Balance check failed: {str(e)}")

@app.get("/network/chain")
async def get_chain(node_url: str = DEFAULT_NODE):
    """Retrieve full blockchain from node"""
    try:
        response = requests.get(f"{node_url}/chain")
        return response.json()
    except requests.exceptions.RequestException as e:
        raise HTTPException(500, f"Failed to retrieve chain: {str(e)}")

if __name__ == "__main__":
    import uvicorn
    uvicorn.run(app, host="0.0.0.0", port=8002)