#python3

import base64
import secrets
import socket
from Crypto.Cipher import AES
from Crypto.Cipher import PKCS1_OAEP
from Crypto.Random import get_random_bytes
from Crypto.PublicKey import RSA


class SiFT_MTP_Error(Exception):

    def __init__(self, err_msg):
        self.err_msg = err_msg

class SiFT_MTP:
	def __init__(self, peer_socket):

		self.DEBUG = True
		# constants
		self.version_major = 1
		self.version_minor = 0
		self.msg_hdr_ver = b'\x01\x00'
		self.size_msg_hdr = 16
		self.size_msg_hdr_ver = 2
		self.size_msg_hdr_typ = 2
		self.size_msg_hdr_len = 2
		self.size_msg_hdr_sqn = 2
		self.size_msg_hdr_rnd = 6
		self.size_msg_hdr_rsv = 2
		self.size_mac = 12 
		self.size_etk = 256

		self.type_login_req =    b'\x00\x00'
		self.type_login_res =    b'\x00\x10'
		self.type_command_req =  b'\x01\x00'
		self.type_command_res =  b'\x01\x10'
		self.type_upload_req_0 = b'\x02\x00'
		self.type_upload_req_1 = b'\x02\x01'
		self.type_upload_res =   b'\x02\x10'
		self.type_dnload_req =   b'\x03\x00'
		self.type_dnload_res_0 = b'\x03\x10'
		self.type_dnload_res_1 = b'\x03\x11'
		self.msg_types = ( self.type_login_req,    self.type_login_res, 
						   self.type_command_req,  self.type_command_res,
						   self.type_upload_req_0, self.type_upload_req_1, 
						   self.type_upload_res,   self.type_dnload_req, 
						   self.type_dnload_res_0, self.type_dnload_res_1 )
		
		# state
		self.peer_socket = peer_socket
		self.received_sequence_number = 1
		self.sent_sequence_number = 1

		self.key = None


	# updates session key
	def update_key(self, new_key):
		self.key = new_key

	# parses a message header and returns a dictionary containing the header fields
	def parse_msg_header(self, msg_hdr):

		parsed_msg_hdr, i = {}, 0
		parsed_msg_hdr['ver'], i = msg_hdr[i : i + self.size_msg_hdr_ver], i + self.size_msg_hdr_ver 
		parsed_msg_hdr['typ'], i = msg_hdr[i : i + self.size_msg_hdr_typ], i + self.size_msg_hdr_typ
		parsed_msg_hdr['len'], i = msg_hdr[i : i + self.size_msg_hdr_len], i + self.size_msg_hdr_len
		parsed_msg_hdr['sqn'], i = msg_hdr[i : i + self.size_msg_hdr_sqn], i + self.size_msg_hdr_sqn
		parsed_msg_hdr['rnd'], i = msg_hdr[i : i + self.size_msg_hdr_rnd], i + self.size_msg_hdr_rnd
		parsed_msg_hdr['rsv'], i = msg_hdr[i : i + self.size_msg_hdr_rsv]

		return parsed_msg_hdr
	

	##############################################################################################################
	### SEND AND RECEIVE BYTES - DO NOT MODIFY
	##############################################################################################################

	# sends all bytes provided via the peer socket - do not modify
	def send_bytes(self, bytes_to_send):
		try:
			self.peer_socket.sendall(bytes_to_send)
		except:
			raise SiFT_MTP_Error('Unable to send via peer socket')


	# receives n bytes from the peer socket - do not modify
	def receive_bytes(self, n):
		bytes_received = b''
		bytes_count = 0
		while bytes_count < n:
			try:
				chunk = self.peer_socket.recv(n-bytes_count)
			except:
				raise SiFT_MTP_Error('Unable to receive via peer socket')
			if not chunk: 
				raise SiFT_MTP_Error('Connection with peer is broken')
			bytes_received += chunk
			bytes_count += len(chunk)
		return bytes_received
	


	##############################################################################################################
	### SEND AND RECEIVE LOGIN REQUESTS
	##############################################################################################################

	# builds and sends login requests
	def send_login_request(self, msg_type, msg_payload, public_key_data):

		if msg_type != self.type_login_req:
			raise SiFT_MTP_Error('Only login requests take a public key argument!')
		
		# build message header and collect nonce
		msg_size = self.size_msg_hdr + len(msg_payload) + self.size_mac + self.size_etk
		msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')
		msg_hdr_sqn = self.sent_sequence_number.to_bytes(self.size_msg_hdr_sqn, byteorder='big')
		msg_hdr_rnd = get_random_bytes(6)
		msg_hdr_rsv = b'\x00\x00'

		msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len + msg_hdr_sqn + msg_hdr_rnd + msg_hdr_rsv
		nonce = msg_hdr_sqn + msg_hdr_rnd

		# create a temporary 32-byte AES key solely for the login session
		temporary_key = secrets.token_bytes(32)
		self.key = temporary_key

		# encrypt the temporary key using the server's public RSA key.
		public_key = RSA.import_key(public_key_data) # load the public RSA key
		cipher = PKCS1_OAEP.new(public_key)
		encrypted_temporary_key = cipher.encrypt(temporary_key)

		# encrypt and compute the mac
		cipher = AES.new(temporary_key, AES.MODE_GCM, nonce = nonce, mac_len = self.size_mac) 
		cipher.update(msg_hdr)
		ciphertext, mac = cipher.encrypt_and_digest(msg_payload)

		# build login request
		message = msg_hdr + ciphertext + mac + encrypted_temporary_key

		# DEBUG 
		if self.DEBUG:
			print('MTP login request to send (' + str(msg_size) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('cipher (' + str(len(ciphertext)) + '): ' + ciphertext.hex())
			print('mac (' + str(len(mac)) + '): ' + mac.hex())
			print('etk (' + str(len(encrypted_temporary_key)) + '): ' + encrypted_temporary_key.hex())
			
			print('------------------------------------------')

		# DEBUG 

		# try to send
		try:
			self.send_bytes(message)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to send login request to peer --> ' + e.err_msg)

		self.sent_sequence_number += 1



	# receives and parses login requests, returns message type and payload
	def receive_login_request(self, private_key_data):
		try:
			msg_hdr = self.receive_bytes(self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

		if len(msg_hdr) != self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message header received')
		parsed_msg_hdr = self.parse_msg_header(msg_hdr)

		# verify version, type and replay protection 
		if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
			raise SiFT_MTP_Error('Unsupported version found in message header' + parsed_msg_hdr['ver'])
		if parsed_msg_hdr['typ'] != self.type_login_req:
			raise SiFT_MTP_Error('This is not a login request.')
		if int.from_bytes(parsed_msg_hdr['sqn'], 'big') < self.received_sequence_number:
			raise SiFT_MTP_Error('This message is a replay')
		
		# collect nonce from header
		nonce = parsed_msg_hdr['sqn'] + parsed_msg_hdr['rnd']

		# collect message body
		total_message_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')
		epd_len = total_message_len - (self.size_msg_hdr + self.size_mac + self.size_etk)
		try:	
			encrypted_payload = self.receive_bytes(epd_len)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive encrypted payload --> ' + e.err_msg)

		# collect mac
		try:
			received_mac = self.receive_bytes(self.size_mac)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive MAC --> ' + e.err_msg)

		# collect etk
		try:
			etk = self.receive_bytes(self.size_etk)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive ETK --> ' + e.err_msg)
		
		# decrypt encrypted temporary key (etk) 
		private_key = RSA.import_key(private_key_data) # load the private RSA key
		cipher = PKCS1_OAEP.new(private_key)
		temporary_key = cipher.decrypt(etk)

		# set session key to the temporary login key for now
		self.key = temporary_key 
		
		# decrypt and authenticate the message with the etk
		try:
			cipher = AES.new(key = self.key, mode = AES.MODE_GCM, nonce = nonce, mac_len = self.size_mac)
			cipher.update(msg_hdr)
			decrypted_payload = cipher.decrypt_and_verify(encrypted_payload, received_mac)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Decryption or authentication has failed --> ' + e.err_msg)

		# DEBUG 
		if self.DEBUG:
			print('MTP login request received (' + str(total_message_len) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(decrypted_payload)) + '): ')
			print(decrypted_payload.hex())
			print('------------------------------------------')
		# DEBUG 

		if len(decrypted_payload) != epd_len: 
			raise SiFT_MTP_Error('Incomplete message body received')
		
		self.received_sequence_number += 1

		return parsed_msg_hdr['typ'], decrypted_payload



	##############################################################################################################
	### SEND AND RECEIVE ALL OTHER MESSAGES
	##############################################################################################################
 

	# builds and sends message of a given type using the provided payload
	def send_msg(self, msg_type, msg_payload):
		
		# build message header
		msg_size = self.size_msg_hdr + len(msg_payload) + self.size_mac
		msg_hdr_len = msg_size.to_bytes(self.size_msg_hdr_len, byteorder='big')
		msg_hdr_sqn = self.sent_sequence_number.to_bytes(self.size_msg_hdr_sqn, byteorder='big')
		msg_hdr_rnd = get_random_bytes(6)
		msg_hdr_rsv = b'\x00\x00'

		msg_hdr = self.msg_hdr_ver + msg_type + msg_hdr_len + msg_hdr_sqn + msg_hdr_rnd + msg_hdr_rsv
		nonce =  msg_hdr_sqn + msg_hdr_rnd

		# encrypt and compute the mac
		cipher = AES.new(key = self.key, mode = AES.MODE_GCM, nonce = nonce, mac_len = self.size_mac)
		cipher.update(msg_hdr)
		ciphertext, mac = cipher.encrypt_and_digest(msg_payload)

		message = msg_hdr + ciphertext + mac

		# DEBUG 
		if self.DEBUG:
			print('MTP message to send (' + str(msg_size) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(msg_payload)) + '): ')
			print(msg_payload.hex())
			print('------------------------------------------')
		# DEBUG 

		# try to send
		try:
			self.send_bytes(message)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to send message to peer --> ' + e.err_msg)

		self.sent_sequence_number += 1

	# receives and parses message, returns msg_type and msg_payload
	def receive_msg(self):

		try:
			msg_hdr = self.receive_bytes(self.size_msg_hdr)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message header --> ' + e.err_msg)

		if len(msg_hdr) != self.size_msg_hdr: 
			raise SiFT_MTP_Error('Incomplete message header received')
		parsed_msg_hdr = self.parse_msg_header(msg_hdr)

		# verify version, type and replay protection 
		if parsed_msg_hdr['ver'] != self.msg_hdr_ver:
			raise SiFT_MTP_Error('Unsupported version found in message header' + parsed_msg_hdr['ver'])
		if parsed_msg_hdr['typ'] not in self.msg_types:
			raise SiFT_MTP_Error('Unknown message type found in message header')
		if int.from_bytes(parsed_msg_hdr['sqn'], 'big') < self.received_sequence_number:
			raise SiFT_MTP_Error('This message is a replay')
		
		# collect nonce from header
		nonce = parsed_msg_hdr['sqn'] + parsed_msg_hdr['rnd']

		# collect message body
		msg_len = int.from_bytes(parsed_msg_hdr['len'], byteorder='big')
		try:
			msg_body = self.receive_bytes(msg_len - (self.size_msg_hdr + self.size_mac))
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive message body --> ' + e.err_msg)
		
		# collect mac
		try:
			received_mac = self.receive_bytes(self.size_mac)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Unable to receive MAC --> ' + e.err_msg)
	
		# decrypt and authenticate the message
		try:
			cipher = AES.new(key = self.key, mode = AES.MODE_GCM, nonce = nonce, mac_len = self.size_mac)
			cipher.update(msg_hdr)
			msg_body = cipher.decrypt_and_verify(msg_body, received_mac)
		except SiFT_MTP_Error as e:
			raise SiFT_MTP_Error('Decryption or authentication has failed --> ' + e.err_msg)

		# DEBUG 
		if self.DEBUG:
			print('MTP message received (' + str(msg_len) + '):')
			print('HDR (' + str(len(msg_hdr)) + '): ' + msg_hdr.hex())
			print('BDY (' + str(len(msg_body)) + '): ')
			print(msg_body.hex())
			print('------------------------------------------')
		# DEBUG 

		if len(msg_body) != (msg_len - (self.size_msg_hdr + self.size_mac)): 
			print("len of message body", len(msg_body))
			print("the other length?", (msg_len - (self.size_msg_hdr + self.size_mac)))
			raise SiFT_MTP_Error('Incomplete message body received')
		
		self.received_sequence_number += 1

		return parsed_msg_hdr['typ'], msg_body
