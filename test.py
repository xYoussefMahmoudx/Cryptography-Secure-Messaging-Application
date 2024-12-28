import key_management as KMM
import RSA as RS
import block_cypher as BC


if __name__ == "__main__":
    Message="here is my kingdom come here is my kingdome come"
    userid1='user123'
    userpassword1="12345"
    km=KMM.KeyManagement()
    privatekey,publickey=km.generate_rsa_key_pair()
    km.save_private_key(private_key=privatekey,user_id=userid1,password=userpassword1)
    km.save_public_key(public_key=publickey,user_id=userid1)
    sym_key=km.generate_symmetric_key()
    
    print(f'symetric key :{sym_key}')
    
    bc=BC.AESEncryption(sym_key)
    cp=bc.encrypt(Message)
    public_key=km.load_public_key(userid1)
    encrypted_sym_key=RS.encrypt(public_key=public_key,plaintext=sym_key)
    
    
    print(f'cyphered text : {cp["ciphertext"]}')
    print("______________________________________________________________________")
    print(f'encrypted symetric key :{encrypted_sym_key}')
    
    userid2='user123'
    userpassword2="123456"
    
    km2=KMM.KeyManagement()
    km2.save_symmetric_key(encrypted_sym_key,userid2,userpassword2)
    re_encrypted_sym_key=km2.load_symmetric_key(userid2,userpassword2)
    
    privatekey2=km2.load_private_key(userid1,userpassword1)
    rsm=decrypted_sym_key=RS.decrypt(privatekey2,re_encrypted_sym_key)
    pt=bc.decrypt(cp['ciphertext'],cp["tag"],cp["nonce"])
    
    
    print(f'plain text :{pt}')
    print("______________________________________________________________________")
    print(f'decrypted symetric key :{rsm}')