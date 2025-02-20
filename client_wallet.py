# client_wallet.py

import binascii
import hashlib
import time
from Cryptodome.Hash import SHA
from Cryptodome.PublicKey import RSA
from Cryptodome.Signature import PKCS1_v1_5
from Cryptodome.Cipher import AES
from Cryptodome.Random import get_random_bytes

class ClientWallet:
    def __init__(self):
        self.private_key, self.public_key = self._generate_keypair()

    def sign_transaction(self, recipient: str, amount: float) -> dict:
        """Create and sign transaction locally"""
        payload = f"{self.public_key}{recipient}{amount}{time.time()}".encode()
        h = SHA.new(payload)
        signer = PKCS1_v1_5.new(RSA.import_key(binascii.unhexlify(self.private_key)))
        signature = binascii.hexlify(signer.sign(h)).decode()
        
        return {
            'sender_pubkey': self.public_key,
            'recipient': recipient,
            'amount': amount,
            'signature': signature
        }

    def save_to_file(self, password: str, filename="wallet.enc"):
        salt = get_random_bytes(16)
        key = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
        cipher = AES.new(key, AES.MODE_GCM)
        ciphertext, tag = cipher.encrypt_and_digest(self.private_key.encode())
        
        with open(filename, 'wb') as f:
            [f.write(x) for x in (
                salt,
                cipher.nonce,
                tag,
                ciphertext
            )]
        
    @staticmethod
    def _generate_keypair() -> tuple:
        """Generate and properly encode RSA-2048 keys"""
        key = RSA.generate(2048)
        
        # Export private key
        private_key = binascii.hexlify(
            key.export_key(
                format='DER',
                pkcs=8,
                protection='scryptAndAES128-CBC'
            )
        ).decode()
        
        # Export public key
        public_key = binascii.hexlify(
            key.publickey().export_key(
                format='DER'
            )
        ).decode()
        
        return private_key, public_key

    @classmethod
    def load_from_file(cls, password: str, filename="wallet.enc"):
        with open(filename, 'rb') as f:
            salt, nonce, tag, ciphertext = [f.read(x) for x in (16, 16, 16, -1)]
            
        key = hashlib.scrypt(password.encode(), salt=salt, n=2**14, r=8, p=1, dklen=32)
        cipher = AES.new(key, AES.MODE_GCM, nonce=nonce)
        private_key = cipher.decrypt_and_verify(ciphertext, tag).decode()
        
        # Get public key from private key properly
        private_key_obj = RSA.import_key(binascii.unhexlify(private_key))
        public_key = binascii.hexlify(
            private_key_obj.publickey().export_key(format='DER')
        ).decode()
        
        wallet = cls()
        wallet.private_key = private_key
        wallet.public_key = public_key  # Store as string
        return wallet
