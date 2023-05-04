from Crypto.PublicKey import DSA
from Crypto.Hash import SHA256
from Crypto.Signature import DSS

def generate_keys():
    """
    This function is used to generate keys
    """
    key = DSA.generate(2048)
    public_key = key.publickey().export_key()
    private_key = key.export_key()
    return public_key, private_key

def sign_message(message, private_key):
    """
    This function is used to sign message with private key
    """
    key = DSA.import_key(private_key)
    h = SHA256.new(message)
    signer = DSS.new(key, 'fips-186-3')
    signature = signer.sign(h)
    return signature

def verify_signature(message, signature, public_key):
    """
    This function is used to verift signature using public key
    """
    key = DSA.import_key(public_key)
    h = SHA256.new(message)
    verifier = DSS.new(key, 'fips-186-3')
    try:
        verifier.verify(h, signature)
        return True
    except ValueError:
        return False