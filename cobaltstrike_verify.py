#!/usr/bin/env python3
import time
import socket
import ssl
import argparse
import sys
import random
from concurrent.futures import ThreadPoolExecutor,wait, ALL_COMPLETED

MIN_PYTHON = (3, 3)
if sys.version_info < MIN_PYTHON:
	sys.exit("Python %s.%s or later is required.\n" % MIN_PYTHON)

class NotConnectedException(Exception):
	def __init__(self, message=None, node=None):
		self.message = message
		self.node = node


class DisconnectedException(Exception):
	def __init__(self, message=None, node=None):
		self.message = message
		self.node = node


class Connector:
	def __init__(self):
		self.sock = None
		self.ssl_sock = None
		self.ctx = ssl.SSLContext()
		self.ctx.verify_mode = ssl.CERT_NONE
		pass

	def is_connected(self):
		return self.sock and self.ssl_sock

	def open(self, hostname, port):
		self.sock = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
		self.sock.settimeout(5)
		self.ssl_sock = self.ctx.wrap_socket(self.sock)

		if hostname == socket.gethostname():
			ipaddress = socket.gethostbyname_ex(hostname)[2][0]
			self.ssl_sock.connect((ipaddress, port))
		else:
			self.ssl_sock.connect((hostname, port))

	def close(self):
		if self.sock:
			self.sock.close()
		self.sock = None
		self.ssl_sock = None

	def send(self, buffer):
		if not self.ssl_sock: raise NotConnectedException("Not connected (SSL Socket is null)")
		self.ssl_sock.sendall(buffer)

	def receive(self):
		if not self.ssl_sock: raise NotConnectedException("Not connected (SSL Socket is null)")
		received_size = 0
		data_buffer = b""

		while received_size < 4:
			data_in = self.ssl_sock.recv()
			data_buffer = data_buffer + data_in
			received_size += len(data_in)

		return data_buffer



def passwordcheck(hostq):
	if hostq == "":
		return
	if ":" not in hostq:
		hostq = hostq+":50050"
	password = random.choice('abcdefghijklmnopqrstuvwxyz1234567890')
	result = None
	conn = Connector()
	host = hostq.split(":")[0]
	port = hostq.split(":")[1]
	conn.open(host, int(port))
	payload = bytearray(b"\x00\x00\xbe\xef") + len(password).to_bytes(1, "big", signed=True) + bytes(
		bytes(password, "ascii").ljust(256, b"A"))
	conn.send(payload)
	if conn.is_connected(): result = conn.receive()
	if conn.is_connected(): conn.close()
	
	if result == bytearray(b"\x00\x00\xca\xfe") or result == bytearray(b"\x00\x00\x00\x00"):
		print("teamserver, "+host+":"+port)
		f = open("write.csv", "a") 
		f.write(host+", "+port+", \n")
		f.close


if __name__ == '__main__':
	parser = argparse.ArgumentParser()
	parser.add_argument("-l",dest="targets",help="IP:PORT file")
	parser.add_argument("-t", dest="threads", default=50, type=int, help="threads")
	if len(sys.argv) < 3:
		parser.print_help()
		exit()
	else:
		args = parser.parse_args()
	
	
	urls = []
	passwords = []
	if args.targets == "":
		parser.print_help()
		exit()

	start = time.time()
	try:
		f = open(args.targets)
		for text in f.readlines():
			data = text.strip('\n')
			urls.append(data)
	finally:
		f.close()
	with ThreadPoolExecutor(max_workers=args.threads) as pool:
		all_task = [pool.submit(passwordcheck, host) for host in urls]
		wait(all_task, return_when=ALL_COMPLETED)

	finish = time.time()
	print("Seconds: {:.1f}".format(finish - start))