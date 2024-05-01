# Simple File Transfer Protocol (SiFT)

## Authors
- Zehra Gundogdu
- Sike Ogieva

## Introduction
This document outlines the implementation details of the Simple File Transfer Protocol (SiFT), a secure protocol designed for transferring files between a client and a server. We implement SiFT v1.0 by extending SiFT v0.5 to provide protection from eavesdropping, modification, deletion, injection and replay of messages sent by the parties, by cryptographically securing the message transfer sub-protocol.

## Implementation
- **RSA Key Pair Generation:**
  At the outset of the project, we implemented a RSA key pair generation and distribution utility between the client and server.

- **Login Protocol and Key Establishment:**
The login messages (requests and responses) are protected by a temporary key, encrypted with the generated RSA key using the PBKDF2 (Password-Based Key Derivation Function 2) and sent from the client to the server. The server, being in possession of the private key, can retrieve this temporary key and decrypt the client's login request (implicitly authenticating itself to the client). The login messages pass key material from the client to the server and from the server to the client. At the end of a successful login protocol, a final key is derived from these nonces, using a salted HMAC key derivation function with SHA-256 as the internal hash function. All subsequent MTP messages are protected with this final key.
  
- **Securing the Message Transfer Protocol:**
Finally, for securing the Message Transfer Protocol (MTP), we implemented AES in GCM (Galois/Counter Mode) mode, as well as replay protectuon. This choice provides both encryption and integrity protection for the messages exchanged between the client and server. By using AES-GCM, we ensure that the data integrity and confidentiality are maintained, protecting against common threats like tampering and eavesdropping.

This comprehensive implementation of cryptographic techniques ensures a high level of security throughout the file transfer process, making SiFT a robust solution for secure file transfer needs.

## Usage
### Prerequisites
- Python 3.x
- PyCryptoDome library

### Installation Steps
1. Clone the repository:
   ```bash
   git clone https://github.com/sike25/sift/  
   cd SiFT/SiFTv1.0/
   ```
2. Generate RSA key pair for server and client:
   ```bash
   cd utils
   python generatekeys.py
   ```
3. In different terminals, start the server and client:
   ```bash
   cd server
   python server.py
   cd client
   python client.py
   ``` 
4. Once the client and server are running, follow the on-screen prompts to log in, send commands, and transfer files.
 
5. Supported commands are:
   - **pwd**: print working directory
   - **lst**: list contents of working directory
   - **chd**: change working directory
   - **mkd**: make directory
   - **del**: delete file
   - **upl**: upload file
   - **dnl**: download file
   - **help**: for information
   - **bye**: to close connection.  

### License
[![License: MIT](https://img.shields.io/badge/License-MIT-yellow.svg)](https://opensource.org/licenses/MIT)

### Contact Information
- zgundo25@colby.edu  
- oogieva25@amherst.edu  


   
