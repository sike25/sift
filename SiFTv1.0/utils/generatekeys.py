import os
from Crypto.PublicKey import RSA

this_dir = os.path.dirname(os.path.abspath(__file__))

client_pub_file  = os.path.join(this_dir, '..', 'client', 'pubkey.pem')
server_pub_file  = os.path.join(this_dir, '..', 'server', 'pubkey.pem')
server_priv_file = os.path.join(this_dir, '..', 'server', 'privkey.pem')

print("Generating a new 2048-bit RSA key pair...")
keypair = RSA.generate(2048)

print("Saving the public and private keys to the server...")
with open(server_pub_file, 'wb') as file:
    file.write(keypair.public_key().export_key(format = 'PEM'))

with open(server_priv_file, 'wb') as file:
    file.write(keypair.export_key(format = 'PEM'))

print("Saving the public key to the client...")
with open(client_pub_file, 'wb') as file:
    file.write(keypair.public_key().export_key(format = 'PEM'))
    
print("All Done!")