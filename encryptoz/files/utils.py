
import os
import sys
import funcy
import base64

import Crypto.Protocol
from Crypto import Random

from Crypto.Cipher import AES
import secrets
from PIL import Image
from flask import url_for, current_app
from flask_mail import Message
from encryptoz import mail
from werkzeug import secure_filename



def encrypt_file(filename, file_path, enc_key):
#	try:
	usr_key = enc_key
	salt = b'\x9aX\x10\xa6^\x1fUVu\xc0\xa2\xc8\xff\xceOV'
	key = Crypto.Protocol.KDF.PBKDF2(password=usr_key, salt=salt, dkLen=32, count=10000)
	iv = Random.new().read(AES.block_size)
	bs = AES.block_size


	def pad(s):
		return s + (bs - len(s) % bs) * chr(bs - len(s) % bs).encode('utf-8')

	def encrypt(raw):
		raw = pad(raw.encode("utf-8"))
		cipher = AES.new(key, AES.MODE_CBC, iv)
		return base64.b64encode(key + iv + cipher.encrypt(raw))


	def encryptFile(fileIn, chunksize=64*1024):
		fileOut = fileIn + ".cursed"
		cipher = AES.new(key, AES.MODE_CBC, iv)
		with open(fileIn, "rb") as plain:
			with open(fileOut, "wb") as outFile:
				outFile.write(base64.b64encode(key + iv))

				while True:
					chunk = plain.read(chunksize)
					if len(chunk) == 0:
						break
					chunk = pad(chunk)
					outFile.write(base64.b64encode(cipher.encrypt(chunk)))
		os.remove(fileIn)
	enc_stat = 1
	encryptFile(file_path)
	return enc_stat
#	except:
#		encrypt =0
#		return encrypt

def decrypt_file(filename, file_path, enc_key):
	def unpad(s):
		return s[:-ord(s[len(s) - 1:])]

	def decrypt(l):
		l = base64.b64decode(l)
		alpha = l[:32]
		key == alpha
		iv = l[32:32 + 16]
		cipher = AES.new(key, AES.MODE_CBC, iv)
		return unpad(cipher.decrypt(l[48:]))

	def decryptFile(fileIn, chunksize=24*1024):
		with open(fileIn, "rb") as encryptedFile:
			encrypted = base64.b64decode(encryptedFile.read(64))
			setup = encrypted[:48]
			key_confirm = enc_key
			salt = b'\x9aX\x10\xa6^\x1fUVu\xc0\xa2\xc8\xff\xceOV'
			key_check = Crypto.Protocol.KDF.PBKDF2(password=key_confirm, salt=salt, dkLen=32, count=10000)
			if key_check == setup[:32]:
				print("Password Correct!")
			else:
				print("Wrong Password!")
				sys.exit(0)

			iv = setup[32:]
			cipher = AES.new(key_check, AES.MODE_CBC, iv)
			with open(fileIn[:-7], "wb") as decryptedFile:
				encrypted = base64.b64decode(encryptedFile.read())
				chunks = list(funcy.chunks(chunksize, encrypted))
				for chunk in chunks:
					decrypted_chunk = unpad(cipher.decrypt(chunk))
					decryptedFile.write(decrypted_chunk)
	fileIn = file_path        
	decryptFile(fileIn)
	os.remove(fileIn)
	enc_stat = 0
	return enc_stat
