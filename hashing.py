import hashlib
import hmac

class HashingModule:
    
    @staticmethod
    def generate_hash(data: str) -> str:
        
        sha256_hash = hashlib.sha256(data.encode('utf-8')).hexdigest()
        return sha256_hash

    @staticmethod
    def verify_hash(data: str, provided_hash: str) -> bool:
    
        computed_hash = HashingModule.generate_hash(data)
        return computed_hash == provided_hash
