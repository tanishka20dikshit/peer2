from __future__ import annotations
import base64
import json
import hashlib
from typing import Dict, Any, Optional
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding, rsa
from cryptography.hazmat.primitives.asymmetric.utils import Prehashed
from cryptography.hazmat.primitives import serialization
from cryptography.exceptions import InvalidSignature

B64URL_NOPAD = lambda b: base64.urlsafe_b64encode(b).rstrip(b"=")
B64URL_DECODE = lambda s: base64.urlsafe_b64decode(s + b"=" * ((4 - len(s) % 4) % 4))

def generate_rsa4096() -> rsa.RSAPrivateKey:
	# For tooling/offline key generation; avoid runtime generation in browser.
	return rsa.generate_private_key(public_exponent=65537, key_size=4096)

def export_pubkey_b64url(pub) -> str:
	der = pub.public_bytes(
		encoding=serialization.Encoding.DER,
		format=serialization.PublicFormat.SubjectPublicKeyInfo,
	)
	return B64URL_NOPAD(der).decode()

def export_privkey_b64url(priv) -> str:
	der = priv.private_bytes(
		encoding=serialization.Encoding.DER,
		format=serialization.PrivateFormat.PKCS8,
		encryption_algorithm=serialization.NoEncryption()
	)
	return B64URL_NOPAD(der).decode()

def import_pubkey_b64url(s: str):
	der = B64URL_DECODE(s.encode())
	return serialization.load_der_public_key(der)

def import_privkey_b64url(s: str):
	der = B64URL_DECODE(s.encode())
	return serialization.load_der_private_key(der, password=None)

def sign_transport(priv, payload_bytes: bytes) -> str:
	# RSASSA-PSS(SHA-256), §4, §12
	sig = priv.sign(
		payload_bytes,
		padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
		hashes.SHA256(),
	)
	return B64URL_NOPAD(sig).decode()

def verify_transport(pub, payload_bytes: bytes, sig_b64url: str) -> bool:
	try:
		pub.verify(
			B64URL_DECODE(sig_b64url.encode()),
			payload_bytes,
			padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
			hashes.SHA256(),
		)
		return True
	except InvalidSignature:
		return False
	except Exception:
		return False

def rsa_oaep_encrypt(pub, plaintext: bytes) -> str:
	ct = pub.encrypt(
		plaintext,
		padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
	)
	return B64URL_NOPAD(ct).decode()

def rsa_oaep_decrypt(priv, ciphertext_b64url: str) -> bytes:
	return priv.decrypt(
		B64URL_DECODE(ciphertext_b64url.encode()),
		padding.OAEP(mgf=padding.MGF1(algorithm=hashes.SHA256()), algorithm=hashes.SHA256(), label=None),
	)

# Content signature functions for end-to-end encryption (§12)
def sign_content_dm(priv, ciphertext: str, from_id: str, to_id: str, ts: int) -> str:
	"""Sign content for direct messages: SHA256(ciphertext || from || to || ts)"""
	data = f"{ciphertext}{from_id}{to_id}{ts}".encode('utf-8')
	sig = priv.sign(
		data,
		padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
		hashes.SHA256(),
	)
	return B64URL_NOPAD(sig).decode()

def verify_content_dm(pub, ciphertext: str, from_id: str, to_id: str, ts: int, sig_b64url: str) -> bool:
	"""Verify content signature for direct messages"""
	try:
		data = f"{ciphertext}{from_id}{to_id}{ts}".encode('utf-8')
		pub.verify(
			B64URL_DECODE(sig_b64url.encode()),
			data,
			padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
			hashes.SHA256(),
		)
		return True
	except InvalidSignature:
		return False
	except Exception:
		return False

def sign_content_public(priv, ciphertext: str, from_id: str, ts: int) -> str:
	"""Sign content for public channel: SHA256(ciphertext || from || ts)"""
	data = f"{ciphertext}{from_id}{ts}".encode('utf-8')
	sig = priv.sign(
		data,
		padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
		hashes.SHA256(),
	)
	return B64URL_NOPAD(sig).decode()

def verify_content_public(pub, ciphertext: str, from_id: str, ts: int, sig_b64url: str) -> bool:
	"""Verify content signature for public channel"""
	try:
		data = f"{ciphertext}{from_id}{ts}".encode('utf-8')
		pub.verify(
			B64URL_DECODE(sig_b64url.encode()),
			data,
			padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
			hashes.SHA256(),
		)
		return True
	except InvalidSignature:
		return False
	except Exception:
		return False

# Canonical JSON serialization for transport signatures (§12)
def canonical_json(obj: Dict[str, Any]) -> bytes:
	"""Serialize JSON object with canonical key ordering and no whitespace"""
	return json.dumps(obj, separators=(',', ':'), sort_keys=True).encode('utf-8')

# Key validation functions
def validate_rsa_key_size(pub_key) -> bool:
	"""Validate that RSA key is 4096 bits as required by protocol"""
	return pub_key.key_size == 4096

def validate_rsa_public_exponent(pub_key) -> bool:
    """
    Validate RSA public exponent is secure (Protocol §16).
    
    Rejects weak/small exponents (e.g., 3, 17, 257) which are
    vulnerable to attacks. Accepts 65537 (F4, standard) or larger.
    
    Returns:
        True if exponent is secure (≥ 65537)
    """
    e = pub_key.public_numbers().e
    return e >= 65537  # F4 or larger

def validate_key_pair(priv_key, pub_key) -> bool:
	"""Validate that private and public keys form a valid pair"""
	try:
		# Test encryption/decryption
		test_data = b"test_data_for_key_validation"
		ciphertext = rsa_oaep_encrypt(pub_key, test_data)
		decrypted = rsa_oaep_decrypt(priv_key, ciphertext)
		return decrypted == test_data
	except Exception:
		return False

# Key generation utilities
def generate_key_pair() -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
	"""Generate a new RSA-4096 key pair"""
	priv_key = generate_rsa4096()
	pub_key = priv_key.public_key()
	return priv_key, pub_key

def save_key_pair(priv_key: rsa.RSAPrivateKey, pub_key: rsa.RSAPublicKey, 
                 priv_path: str, pub_path: str) -> None:
	"""Save key pair to files"""
	with open(priv_path, 'w') as f:
		f.write(export_privkey_b64url(priv_key))
	with open(pub_path, 'w') as f:
		f.write(export_pubkey_b64url(pub_key))

def load_key_pair(priv_path: str, pub_path: str) -> tuple[rsa.RSAPrivateKey, rsa.RSAPublicKey]:
	"""Load key pair from files"""
	with open(priv_path, 'r') as f:
		priv_b64 = f.read().strip()
	with open(pub_path, 'r') as f:
		pub_b64 = f.read().strip()
	
	priv_key = import_privkey_b64url(priv_b64)
	pub_key = import_pubkey_b64url(pub_b64)
	return priv_key, pub_key

def export_privkey_pem(priv) -> bytes:
	"""Export private key in PEM format"""
	return priv.private_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PrivateFormat.PKCS8,
		encryption_algorithm=serialization.NoEncryption()
	)

def export_pubkey_pem(pub) -> bytes:
	"""Export public key in PEM format"""
	return pub.public_bytes(
		encoding=serialization.Encoding.PEM,
		format=serialization.PublicFormat.SubjectPublicKeyInfo
	)

def import_privkey_pem(pem_bytes: bytes):
	"""Import private key from PEM format"""
	return serialization.load_pem_private_key(pem_bytes, password=None)

def import_pubkey_pem(pem_bytes: bytes):
	"""Import public key from PEM format"""
	return serialization.load_pem_public_key(pem_bytes)

def sign_content_key_share(priv, shares: list, creator_pub: str) -> str:
	"""
	Sign PUBLIC_CHANNEL_KEY_SHARE content per Protocol §12
	
	For Public Channel Key Share: SHA256(shares || creator_pub)
	
	Args:
		priv: Private key for signing
		shares: List of share dictionaries
		creator_pub: Creator's public key (base64url)
	
	Returns:
		Signature in base64url format
	"""
	import json
	# Canonical representation: shares as JSON + creator_pub
	shares_bytes = json.dumps(shares, separators=(',', ':'), sort_keys=True).encode('utf-8')
	creator_bytes = creator_pub.encode('utf-8')
	
	# SHA256(shares || creator_pub)
	digest = hashlib.sha256(shares_bytes + creator_bytes).digest()
	
	# Sign with RSASSA-PSS
	sig = priv.sign(
		digest,
		padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
		Prehashed(hashes.SHA256())
	)
	return B64URL_NOPAD(sig).decode()


def verify_content_key_share(pub, shares: list, creator_pub: str, sig_b64url: str) -> bool:
	"""
	Verify PUBLIC_CHANNEL_KEY_SHARE content signature per Protocol §12
	
	Args:
		pub: Public key for verification
		shares: List of share dictionaries
		creator_pub: Creator's public key (base64url)
		sig_b64url: Signature in base64url format
	
	Returns:
		True if signature is valid, False otherwise
	"""
	try:
		import json
		# Canonical representation: shares as JSON + creator_pub
		shares_bytes = json.dumps(shares, separators=(',', ':'), sort_keys=True).encode('utf-8')
		creator_bytes = creator_pub.encode('utf-8')
		
		# SHA256(shares || creator_pub)
		digest = hashlib.sha256(shares_bytes + creator_bytes).digest()
		
		# Verify signature
		sig = B64URL_DECODE(sig_b64url.encode())
		pub.verify(
			sig,
			digest,
			padding.PSS(mgf=padding.MGF1(hashes.SHA256()), salt_length=padding.PSS.MAX_LENGTH),
			Prehashed(hashes.SHA256())
		)
		return True
	except InvalidSignature:
		return False
	except Exception:
		return False