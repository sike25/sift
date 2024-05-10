#python3

import time
import secrets

from Crypto.Hash import SHA256
from Crypto.Protocol.KDF import HKDF
from Crypto.Protocol.KDF import PBKDF2
from siftprotocols.siftmtp import SiFT_MTP, SiFT_MTP_Error


class SiFT_LOGIN_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_LOGIN:
    def __init__(self, mtp):

        self.DEBUG = True
        # constants
        self.delimiter = '\n'
        self.coding = 'utf-8'
        self.acceptance_window = 20000000000 # nanoseconds

        # state
        self.mtp = mtp
        self.server_users = None 
        self.recent_requests = [] # list of (timestamp, login_request) tuples

        # key derivation pieces
        self.client_random = None
        self.server_random = None
        self.request_hash = None


    # sets user passwords dictionary (to be used by the server)
    def set_server_users(self, users):
        self.server_users = users
 

    # builds a login request from a dictionary
    def build_login_req(self, login_req_struct):
        timestamp = str(int(time.time_ns()))
        client_random = secrets.token_hex(16)
        
        login_req_str = f"{timestamp}{self.delimiter}"
        login_req_str += f"{login_req_struct['username']}{self.delimiter}"
        login_req_str += f"{login_req_struct['password']}{self.delimiter}"
        login_req_str += client_random

        self.client_random = bytes.fromhex(client_random)
        return login_req_str.encode(self.coding)


    # parses a login request into a dictionary
    def parse_login_req(self, login_req):
        login_req_fields = login_req.decode(self.coding).split(self.delimiter)
        
        login_req_struct = {}
        login_req_struct['timestamp'] = int(login_req_fields[0])
        login_req_struct['username'] = login_req_fields[1]
        login_req_struct['password'] = login_req_fields[2]
        login_req_struct['client_random'] = login_req_fields[3]

        self.client_random = bytes.fromhex(login_req_struct['client_random'])
        return login_req_struct


    # builds a login response from a dictionary
    def build_login_res(self, login_res_struct):
        server_random = secrets.token_hex(16)
        login_res_str = f"{login_res_struct['request_hash'].hex()}{self.delimiter}{server_random}"

        self.server_random = bytes.fromhex(server_random)
        self.request_hash = login_res_struct['request_hash']
        return login_res_str.encode(self.coding)


    # parses a login response into a dictionary
    def parse_login_res(self, login_res):
        login_res_fields = login_res.decode(self.coding).split(self.delimiter)
        login_res_struct = {}
        login_res_struct['request_hash'] = bytes.fromhex(login_res_fields[0])
        login_res_struct['server_random'] = login_res_fields[1]

        self.server_random = bytes.fromhex(login_res_struct['server_random'])
        self.request_hash = login_res_struct['request_hash']
        return login_res_struct


    # check correctness of a provided password
    def check_password(self, pwd, usr_struct):

        pwdhash = PBKDF2(pwd, usr_struct['salt'], len(usr_struct['pwdhash']), count=usr_struct['icount'], hmac_hash_module=SHA256)
        if pwdhash == usr_struct['pwdhash']: return True
        return False
    

    # checks if the same request was received in another connection (with another client) within the acceptance window
    def is_duplicate_request(self, login_req_timestamp, login_request):
        current_time = time.time()

        # removes requests that are outside the acceptance window, for efficiency and freshness
        self.recent_requests = [(timestamp, message) for timestamp, message in self.recent_requests if abs(current_time - timestamp) < self.acceptance_window]
        
        for request in self.recent_requests:
            if request[1] == login_request: # request[1] = message payload for login request
                return True
            
        self.recent_requests.append((login_req_timestamp, login_request))
        return False



    # handles login process (to be used by the server)
    def handle_login_server(self, private_key_data):

        if not self.server_users:
            raise SiFT_LOGIN_Error('User database is required for handling login at server')

        # trying to receive a login request
        try:
            msg_type, msg_payload = self.mtp.receive_login_request(private_key_data)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to receive login request --> ' + e.err_msg)

        # DEBUG 
        if self.DEBUG:
            print('Incoming payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        if msg_type != self.mtp.type_login_req:
            raise SiFT_LOGIN_Error('Login request expected, but received something else')

        # processing login request
        hash_fn = SHA256.new()
        hash_fn.update(msg_payload)
        request_hash = hash_fn.digest()

        login_req_struct = self.parse_login_req(msg_payload)

        # check if timestamp is within the acceptance window
        current_time = time.time() 
        login_req_timestamp = login_req_struct['timestamp'] / 1_000_000_000  # Convert nanoseconds to seconds
        if abs(current_time - login_req_timestamp) > self.acceptance_window:
            raise SiFT_LOGIN_Error('Login request not fresh')

        # check if the same request was not received within the acceptance window
        if self.is_duplicate_request(login_req_timestamp, msg_payload):
            raise SiFT_LOGIN_Error('Duplicate login request')
        
        # checking username and password
        if login_req_struct['username'] in self.server_users:
            if not self.check_password(login_req_struct['password'], self.server_users[login_req_struct['username']]):
                raise SiFT_LOGIN_Error('Password verification failed')
        else:
            raise SiFT_LOGIN_Error('Unkown user attempted to log in')

        # building login response
        login_res_struct = {}
        login_res_struct['request_hash'] = request_hash
        msg_payload = self.build_login_res(login_res_struct)

        # DEBUG 
        if self.DEBUG:
            print('Outgoing payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        # sending login response
        try:
            self.mtp.send_msg(self.mtp.type_login_res, msg_payload)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to send login response --> ' + e.err_msg)

        # DEBUG 
        if self.DEBUG:
            print('User ' + login_req_struct['username'] + ' logged in')
        # DEBUG 

        # after all successful verification...
        if self.client_random and self.server_random and self.request_hash:
            self.final_key_derivation()
        else:
            raise SiFT_LOGIN_Error('Insufficient material for final key derivation')

        return login_req_struct['username']


    # handles login process (to be used by the client)
    def handle_login_client(self, username, password, public_key_data):

        if not public_key_data:
            raise SiFT_LOGIN_Error('Client did not send public key')

        # building a login request
        login_req_struct = {}
        login_req_struct['username'] = username
        login_req_struct['password'] = password
        msg_payload = self.build_login_req(login_req_struct)

        # DEBUG 
        if self.DEBUG:
            print('Outgoing payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        # trying to send login request
        try:
            self.mtp.send_login_request(self.mtp.type_login_req, msg_payload, public_key_data)
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to send login request --> ' + e.err_msg)

        # computing hash of sent request payload
        hash_fn = SHA256.new()
        hash_fn.update(msg_payload)
        request_hash = hash_fn.digest()

        # trying to receive a login response
        try:
            msg_type, msg_payload = self.mtp.receive_msg()
        except SiFT_MTP_Error as e:
            raise SiFT_LOGIN_Error('Unable to receive login response --> ' + e.err_msg)

        # DEBUG 
        if self.DEBUG:
            print('Incoming payload (' + str(len(msg_payload)) + '):')
            print(msg_payload[:max(512, len(msg_payload))].decode('utf-8'))
            print('------------------------------------------')
        # DEBUG 

        if msg_type != self.mtp.type_login_res:
            raise SiFT_LOGIN_Error('Login response expected, but received something else')

        # processing login response
        login_res_struct = self.parse_login_res(msg_payload)

        # checking request_hash receiveid in the login response
        if login_res_struct['request_hash'] != request_hash:
            raise SiFT_LOGIN_Error('Verification of login response failed')
        
        # after all successful verification...
        if self.client_random and self.server_random and self.request_hash:
            self.final_key_derivation()
        else:
            raise SiFT_LOGIN_Error('Insufficient material for final key derivation')


    # compute a 32-byte final transfer key for the MTP protocol
    def final_key_derivation(self):
        session_key = HKDF(
            master = self.client_random + self.server_random,
            key_len = 32,
            salt = self.request_hash,
            hashmod = SHA256,
        )

        self.mtp.update_key(session_key)