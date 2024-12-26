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

    @staticmethod
    def generate_hmac(key: str, data: str) -> str:
        
        hmac_result = hmac.new(key.encode('utf-8'), data.encode('utf-8'), hashlib.sha256).hexdigest()
        return hmac_result

    @staticmethod
    def verify_hmac(key: str, data: str, provided_hmac: str) -> bool:
        
        computed_hmac = HashingModule.generate_hmac(key, data)
        return computed_hmac == provided_hmac

# Example Usage
if __name__ == "__main__":
    # Example data
    data = "This is a secure message."
    secret_key = "supersecretkey"

    # Generate SHA-256 hash
    hash_result = HashingModule.generate_hash(data)
    print(f"SHA-256 Hash: {hash_result}")

    # Verify hash
    is_hash_valid = HashingModule.verify_hash(data, hash_result)
    print(f"Is hash valid? {is_hash_valid}")

    # Generate HMAC
    hmac_result = HashingModule.generate_hmac(secret_key, data)
    print(f"HMAC: {hmac_result}")

    # Verify HMAC
    is_hmac_valid = HashingModule.verify_hmac(secret_key, data, hmac_result)
    print(f"Is HMAC valid? {is_hmac_valid}")
