from cryptography.hazmat.backends import default_backend
from cryptography.fernet import Fernet
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives.serialization import PublicFormat, Encoding, load_der_public_key
import base64

class CygCrypt:
    #setting param numbers (p, g) as defined in RFC-3526 (DH group 14)
    _p = 0xFFFFFFFFFFFFFFFFC90FDAA22168C234C4C6628B80DC1CD129024E088A67CC74020BBEA63B139B22514A08798E3404DDEF9519B3CD3A431B302B0A6DF25F14374FE1356D6D51C245E485B576625E7EC6F44C42E9A637ED6B0BFF5CB6F406B7EDEE386BFB5A899FA5AE9F24117C4B1FE649286651ECE45B3DC2007CB8A163BF0598DA48361C55D39A69163FA8FD24CF5F83655D23DCA3AD961C62F356208552BB9ED529077096966D670C354E4ABC9804F1746C08CA18217C32905E462E36CE3BE39E772C180E86039B2783A2EC07A28FB5C55DF06F4C52C9DE2BCBF6955817183995497CEA956AE515D2261898FA051015728E5A8AACAA68FFFFFFFFFFFFFFFF
    _g = 2
    _param_numbers = dh.DHParameterNumbers(_p, _g)
    _parameters = _param_numbers.parameters(default_backend())

    def __init__(self, public_key=None, private_key=None):
        self.public_key = public_key
        self._private_key = private_key
        self._encryption_key = None

    def generate_keys(self):
        #generating new keys (public+private) for one side of DH exchange
        private_key = CygCrypt._parameters.generate_private_key()
        self.public_key = private_key.public_key()
        self._private_key = private_key
        return self.public_key

    def shared_secret(self, peer_public_key: bytes):
        """gets peer's public key and derives the encryption key to be used"""

        #deriving shared secret
        shared_key = self._private_key.exchange(CygCrypt.deserialise_public_key(peer_public_key))
        #deriving final encryption key using HKDF (deterministic)
        self._encryption_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data'
        ).derive(shared_key)
    
    def serialised_public_key(self):
        return self.public_key.public_bytes(Encoding.DER, PublicFormat.SubjectPublicKeyInfo)
    
    @staticmethod
    def deserialise_public_key(pkey: bytes):
        return load_der_public_key(pkey, backend=default_backend())

    def encrypt_msg(self, msg):
        f = Fernet(base64.urlsafe_b64encode(self._encryption_key))
        return f.encrypt(msg.encode())

    def decrypt_msg(self, encrypted):
        f = Fernet(base64.urlsafe_b64encode(self._encryption_key))
        return f.decrypt(encrypted).decode()