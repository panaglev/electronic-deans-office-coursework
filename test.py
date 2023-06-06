import unittest
from dsa import generate_keys, sign_message, verify_signature
from Crypto.PublicKey import DSA
from Crypto.Hash import SHA256
from Crypto.Signature import DSS

class TestDSAFunctions(unittest.TestCase):

    def test_generate_keys(self):
        public_key, private_key = generate_keys()
        self.assertIsNotNone(public_key)
        self.assertIsNotNone(private_key)

    def test_sign_and_verify(self):
        message = b"Hello, world!"
        public_key, private_key = generate_keys()

        signature = sign_message(message, private_key)
        self.assertIsNotNone(signature)

        verified = verify_signature(message, signature, public_key)
        self.assertTrue(verified)

    def test_verify_tampered_signature(self):
        message = b"Hello, world!"
        public_key, private_key = generate_keys()

        signature = sign_message(message, private_key)
        self.assertIsNotNone(signature)

        tampered_message = b"Hello, tampered!"
        verified = verify_signature(tampered_message, signature, public_key)
        self.assertFalse(verified)

if __name__ == '__main__':
    unittest.main()