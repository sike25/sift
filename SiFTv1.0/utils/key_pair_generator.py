import os
from Crypto.PublicKey import RSA

this_dir = os.path.dirname(os.path.abspath(__file__))

public_key_file = os.path.join(this_dir, '..', 'server', 'pubkey.pem')
key_pair_file = os.path.join(this_dir, '..', 'client', 'keypair.pem')

print("Generating a new 2048-bit RSA key pair...")
keypair = RSA.generate(2048)

print("Saving the public key to the server...")
with open(public_key_file, 'wb') as file:
    file.write(keypair.public_key().export_key(format = 'PEM'))
    public_key_success = True

print("Saving the public-private key pair to the client...")
with open(key_pair_file, 'wb') as file:
    file.write(keypair.export_key(format = 'PEM'))
    key_pair_success = True
    
print("All Done!")