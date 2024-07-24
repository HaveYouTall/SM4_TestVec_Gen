##########################
# By HaveYouTall         #
# Date: 2024-07-24		 #
##########################

import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
# import sys
import codecs

import CFB as CFB

def hex_to_bytes(hex_str):
	if "0x" in hex_str:
		return codecs.decode(hex_str[2:], 'hex')
	else:
		return codecs.decode(hex_str, 'hex')

def bytes_to_hex(byte_str):
    return codecs.encode(byte_str, 'hex').decode('utf-8')

def byte_list_to_bytes(byte_list):
	return b''.join(byte_list)

def bit_list_to_bytes(bit_list):
	# 确保比特数组的长度是8的倍数
	if len(bit_list) % 8 != 0:
		raise ValueError("比特数组的长度必须是8的倍数")

	# 将比特数组转换为字节
	bytes_array = bytearray()
	for i in range(0, len(bit_list), 8):
		byte = 0
		for j in range(8):
			byte = ((byte << 1) & 0xff) | bit_list[i + j]
		bytes_array.append(byte)

	# print(bytes_array)
	return bytes(bytes_array)

def ByteJ(IV, j):
    """
    返回 IV 的第 j 个字节
    
    参数:
    IV (bytes): 字节串列表
    j (int): 字节串中的字节索引
    
    返回:
    int.to_bytes(): 第 j 个字节的值
    """
    if j < 0 or j >= len(IV):
        raise IndexError("字节索引超出范围")
    
    return IV[j].to_bytes()

def BitJ(IV, j):
    """
    返回 IV 的第 j bit
    
    参数:
    IV (bytes): 包含多个字节串的列表
    j (int): bit索引
    
    返回:
    int: 第 j bit位的值（0 或 1）
    """
    if j < 0 or j >= len(IV) * 8:
        raise IndexError("bit索引超出范围")
    
    byte_index = j // 8
    bit_index = j % 8
    
    byte_value = IV[byte_index]
    bit_value = (byte_value >> (7 - bit_index)) & 1
    
    return bit_value

def mode_to_number(mode):
    modes = {
        'CBC': 0,
        'OFB': 1,
        'CFB': 2,
        'CFB1': 6,
        'CFB8': 5,
        'CTR': 3,
        'ECB': 4
    }
    return modes.get(mode, None)

def read_config(file_path):
	config_list = []
	with open(file_path, 'r') as file:
		lines = file.readlines()

	current_config = {}
	for line in lines:
		line = line.replace(" ", "")
		# line = line.strip()
		line = line.split('#')[0].strip()
		if not line:
			if current_config:
				config_list.append(current_config)
				current_config = {}
			continue
		if '=' in line:
			key, value = line.split('=', 1)
			current_config[key] = value

	if current_config:
		config_list.append(current_config)

	return config_list


def cipher_core_once(cipher, message, padder, unpadder):

	pad_flag = False

	encryptor = cipher.encryptor()

	# str=padder.update(message.encode())+padder.finalize()
	
	# Do not pad if message already fit in several blocks. 
	if len(message) % 16 != 0:
		pad_flag = True
	
	if pad_flag:
		pad_msg=padder.update(message)+padder.finalize()
	else:
		pad_msg = message

	# pad_msg=padder.update(message)+padder.finalize()

	ciphertext = encryptor.update(pad_msg) + encryptor.finalize()

	# Now decrypt

	decryptor = cipher.decryptor()

	if pad_flag:
		rtn = unpadder.update(decryptor.update(ciphertext) + decryptor.finalize())+unpadder.finalize()
	else:
		rtn = decryptor.update(ciphertext) + decryptor.finalize()
	
	# rtn = unpadder.update(decryptor.update(ciphertext) + decryptor.finalize())+unpadder.finalize()


	return ciphertext, rtn, pad_msg


# def cipher_core_update(cipher, message, padder):
# Encryptor should keep the same when perform one stream encrypt.
# def cipher_core_update(encryptor, message, padder):

# 	pad_flag = False
	
# 	# Do not pad if message already fit in several blocks. 
# 	if len(message) % 16 != 0:
# 		pad_flag = True
	
# 	if pad_flag:
# 		pad_msg=padder.update(message)+padder.finalize()
# 	else:
# 		pad_msg = message

# 	ciphertext = encryptor.update(pad_msg)

# 	return ciphertext
# def cipher_core_update(encryptor, message, padder):
def cipher_core_update(encryptor, message):
	pad_msg = message
	ciphertext = encryptor.update(pad_msg)
	return ciphertext

def cipher_core_finalize(encryptor):
	return encryptor.finalize()

def do_aes(message, key=None, iv=None, mode=0):

	if iv is None:
		iv = os.urandom(16)
	
	if key is None:
		key = os.urandom(16)

	padder = padding.PKCS7(128).padder()
	unpadder = padding.PKCS7(128).unpadder()
	
	cipher=None

	if (mode==0): 
		cipher = Cipher(algorithms.AES128(key), modes.CBC(iv))
	if (mode==1): 
		cipher = Cipher(algorithms.AES128(key), modes.OFB(iv))
	if (mode==2): 
		cipher = Cipher(algorithms.AES128(key), modes.CFB(iv))
	if (mode==5): 
		cipher = Cipher(algorithms.AES128(key), modes.CFB8(iv))
	if (mode==3): 
		cipher = Cipher(algorithms.AES128(key), modes.CTR(iv))
	if (mode==4): 
		cipher = Cipher(algorithms.AES128(key), modes.ECB())
	
	if cipher is not None:
		ciphertext, rtn, pad_msg = cipher_core_once(cipher, message, padder, unpadder)
			
		print("Type:\t\t\t",cipher.algorithm.name)
		print("Mode:\t\t\t",cipher.mode.name)
		print("Message:\t\t",message.hex())
		print("Message len:\t\t",len(message))
		print("Message with padding:\t",pad_msg.hex())
		print("\nKey:\t\t\t",key.hex())
		if (mode!=4): print("IV:\t\t\t",iv.hex())
		print("\nCipher:\t\t\t",ciphertext.hex())
		# print("Decrypt:\t\t",rtn.decode())
		# print("Decrypt:\t\t",bytes_to_hex(rtn))
		print("Decrypt:\t\t",rtn.hex())

		if rtn != message:
			print("[\033[91mERROR\033[0m]", " Encrypt/Decrypt error.")

	else:
		if (mode == 6):
			cipher = Cipher(algorithms.AES128(key), modes.ECB())
			encryptor = cipher.encryptor()
			cfb1 = CFB.CFB1(iv, encryptor)
			ciphertext = cfb1.update(message)
			print("Type:\t\t\t","AES")
			print("Mode:\t\t\t","CFB1")
			print("Message:\t\t",message[0])
			print("Message len:\t\t",len(message))
			print("\nKey:\t\t\t",key.hex())
			print("IV:\t\t\t",iv.hex())
			print("\nCipher:\t\t\t",ciphertext[0])



# The function test tells that cipher.encryptor() will overwrite
# the previous result. We should keep the encryptor the same.
def do_aes_CBC(message, key=None, iv=None, mode=0):

	# keysize=16
	# mode=0

	if iv is None:
		iv = os.urandom(16)
	
	if key is None:
		key = os.urandom(16)

	padder = padding.PKCS7(128).padder()
	unpadder = padding.PKCS7(128).unpadder()
	
	cipher=None

	if (mode==0): 
		cipher = Cipher(algorithms.AES128(key), modes.CBC(iv))
	if (mode==1): 
		cipher = Cipher(algorithms.AES128(key), modes.OFB(iv))
	if (mode==2): 
		cipher = Cipher(algorithms.AES128(key), modes.CFB(iv))
	if (mode==3): 
		cipher = Cipher(algorithms.AES128(key), modes.CTR(iv))
	if (mode==4): 
		cipher = Cipher(algorithms.AES128(key), modes.ECB())
		
	# ciphertext, rtn, pad_msg = cipher_core_once(cipher, message, padder, unpadder)
	# print("Type:\t\t\t",cipher.algorithm.name)
	# print("Mode:\t\t\t",cipher.mode.name)
	# print("Message:\t\t",message.hex())
	# print("Message len:\t\t",len(message))
	# print("Message with padding:\t",pad_msg.hex())
	# print("\nKey:\t\t\t",key.hex())
	# if (mode!=4): print("IV:\t\t\t",iv.hex())
	# print("\nCipher:\t\t\t",ciphertext.hex())
	# # print("Decrypt:\t\t",rtn.decode())
	# # print("Decrypt:\t\t",bytes_to_hex(rtn))
	# print("Decrypt:\t\t",rtn.hex())

	# if rtn != message:
	# 	print("[\033[91mERROR\033[0m]", " Encrypt/Decrypt error.")
	pad_flag = False

	encryptor = cipher.encryptor()

	# str=padder.update(message.encode())+padder.finalize()
	
	# Do not pad if message already fit in several blocks. 
	if len(message) % 16 != 0:
		pad_flag = True
	
	if pad_flag:
		pad_msg=padder.update(message)+padder.finalize()
	else:
		pad_msg = message

	# pad_msg=padder.update(message)+padder.finalize()

	ciphertext = encryptor.update(pad_msg[:16])
	# encryptor = cipher.encryptor()
	ciphertext += encryptor.update(pad_msg[16:])
	ciphertext += encryptor.finalize()

	print("Type:\t\t\t",cipher.algorithm.name)
	print("Mode:\t\t\t",cipher.mode.name)
	print("Message:\t\t",message.hex())
	print("Message len:\t\t",len(message))
	print("Message with padding:\t",pad_msg.hex())
	print("\nKey:\t\t\t",key.hex())
	if (mode!=4): print("IV:\t\t\t",iv.hex())
	print("\nCipher:\t\t\t",ciphertext.hex())



def do_ecb_mont_test(message, key):
	PT = message
	Key = key
	for i in range(100):
		print(f"KEY[{i}] = {Key.hex()}")
		print(f"PLAINTEXT = {PT.hex()}")
		cipher = Cipher(algorithms.AES128(Key), modes.ECB())
		CT = []
		for j in range(1000):
			padder = padding.PKCS7(128).padder()
			unpadder = padding.PKCS7(128).unpadder()
			ct_j, _, _ = cipher_core_once(cipher, PT, padder, unpadder)
			CT.append(ct_j)
			PT = ct_j

		Key = bytes(a ^ b for a, b in zip(Key, CT[-1]))
		print(f"CIPHERTEXT = {CT[-1].hex()}\n")
		PT = CT[-1]
	return



# Test success
# The key point is that in the same stream, we need to keep
# encryptor the same.
def do_cbc_mont_test(message, key, iv):
	PT = message
	Key = key
	IV = iv
	# print(f"Key[{i}] = {Key.hex()}")
	# print(f"PLAINTEXT = {PT.hex()}")
	for i in range(100):
		print(f"KEY[{i}] = {Key.hex()}")
		print(f"IV[{i}] = {IV.hex()}")
		print(f"PLAINTEXT = {PT.hex()}")

		# padder = padding.PKCS7(128).padder()
		# unpadder = padding.PKCS7(128).unpadder()
		# cipher = Cipher(algorithms.AES128(Key), modes.ECB())
		cipher = Cipher(algorithms.AES128(Key), modes.CBC(IV))
		encryptor = cipher.encryptor()
		CT = []
		for j in range(1000):
			# ct_j = cipher_core_update(encryptor, PT, padder)
			ct_j = cipher_core_update(encryptor, PT)
			if j == 0:
				# cipher = Cipher(algorithms.AES128(Key), modes.CBC(IV))
				# ct_j, _, _ = cipher_core(cipher, PT, padder, unpadder)

				# ct_j = cipher_core_update(encryptor, PT, padder)

				# PT = bytes(a ^ b for a, b in zip(PT, IV))
				# ct_j = cipher_core_update(cipher, PT, padder) + cipher_core_finalize(cipher)
				PT = IV
			else:
				# cipher = Cipher(algorithms.AES128(Key), modes.ECB())
				# cipher = Cipher(algorithms.AES128(Key), modes.ECB())
				# ct_j, _, _ = cipher_core(cipher, PT, padder, unpadder)

				# ct_j = cipher_core_update(encryptor, PT, padder)

				# PT = bytes(a ^ b for a, b in zip(PT, CT[j-1]))
				# ct_j = cipher_core_update(cipher, PT, padder) + cipher_core_finalize(cipher)
				PT = CT[j-1]
			CT.append(ct_j)
		
		ct_j += cipher_core_finalize(encryptor)
		print(f"CIPHERTEXT = {ct_j.hex()}\n")
		Key = bytes(a ^ b for a, b in zip(Key, ct_j))
		IV = ct_j
		PT = CT[-2]
	return


def do_ofb_mont_test(message, key, iv):
	PT = message
	Key = key
	IV = iv
	for i in range(100):
		print(f"KEY[{i}] = {Key.hex()}")
		print(f"IV[{i}] = {IV.hex()}")
		print(f"PLAINTEXT = {PT.hex()}")

		cipher = Cipher(algorithms.AES128(Key), modes.OFB(IV))
		encryptor = cipher.encryptor()
		CT = []
		for j in range(1000):
			# ct_j = cipher_core_update(encryptor, PT, padder)
			ct_j = cipher_core_update(encryptor, PT)
			if j == 0:
				PT = IV
			else:
				PT = CT[j-1]
			CT.append(ct_j)
		
		ct_j += cipher_core_finalize(encryptor)
		print(f"CIPHERTEXT = {ct_j.hex()}\n")
		Key = bytes(a ^ b for a, b in zip(Key, ct_j))
		IV = ct_j
		PT = CT[-2]
	return

def do_cfb1_mont_test(message, key, iv):
	PT = message
	Key = key
	IV = iv
	for i in range(100):
		print(f"KEY[{i}] = {Key.hex()}")
		print(f"IV[{i}] = {IV.hex()}")
		print(f"PLAINTEXT = {PT[0]}")

		cipher = Cipher(algorithms.AES128(Key), modes.ECB())
		encryptor = cipher.encryptor()
		cfb1 = CFB.CFB1(IV, encryptor)
		CT = []
		for j in range(1000):
			# ct_j = cipher_core_update(encryptor, PT, padder)
			# print(f"PT:{PT.hex()}")
			# ct_j = cipher_core_update(encryptor, PT)
			# print(f"at j = {j}, PT = {PT}")
			ct_j = cfb1.update(PT)
			# print(f"ct_j:{ct_j.hex()}")
			# print(type(PT), type(ct_j))
			if j == 0:
				# print(f"IV[{j}]: {IV[j]}, {type(IV[j])} bytes: {bytes(IV[j])}")
				PT = [BitJ(IV, j)]
				# print(f"PT:{PT.hex()}")
			else:
				if j < 128:
					PT = [BitJ(IV, j)]
				else:
					# print(CT[j-128])
					PT = [CT[j-128]]
			# CT.append(ct_j)
			CT.extend(ct_j)
		
		ct_j += cipher_core_finalize(encryptor)
		print(f"CIPHERTEXT = {ct_j[0]}\n")
		# print(type(byte_list_to_bytes(CT[j-15:])), " : ", byte_list_to_bytes(CT[j-15:]))
		# print(type(Key), " : ", Key.hex())

		Key = bytes(a ^ b for a, b in zip(Key, bit_list_to_bytes(CT[j-127:])))
		IV = bit_list_to_bytes(CT[j-127:])
		PT = [CT[j-128]]
	return

def do_cfb8_mont_test(message, key, iv):
	PT = message
	Key = key
	IV = iv
	for i in range(100):
		print(f"KEY[{i}] = {Key.hex()}")
		print(f"IV[{i}] = {IV.hex()}")
		print(f"PLAINTEXT = {PT.hex()}")

		cipher = Cipher(algorithms.AES128(Key), modes.CFB8(IV))
		encryptor = cipher.encryptor()
		CT = []
		for j in range(1000):
			# ct_j = cipher_core_update(encryptor, PT, padder)
			# print(f"PT:{PT.hex()}")
			ct_j = cipher_core_update(encryptor, PT)
			# print(f"ct_j:{ct_j.hex()}")
			# print(type(PT), type(ct_j))
			if j == 0:
				# print(f"IV[{j}]: {IV[j]}, {type(IV[j])} bytes: {bytes(IV[j])}")
				PT = ByteJ(IV, j)
				# print(f"PT:{PT.hex()}")
			else:
				if j < 16:
					PT = ByteJ(IV, j)
				else:
					PT = CT[j-16]
			CT.append(ct_j)
		
		ct_j += cipher_core_finalize(encryptor)
		print(f"CIPHERTEXT = {ct_j.hex()}\n")
		# print(type(byte_list_to_bytes(CT[j-15:])), " : ", byte_list_to_bytes(CT[j-15:]))
		# print(type(Key), " : ", Key.hex())

		Key = bytes(a ^ b for a, b in zip(Key, byte_list_to_bytes(CT[j-15:])))
		IV = byte_list_to_bytes(CT[j-15:])
		PT = CT[j-16]
	return

def do_cfb8self_mont_test(message, key, iv):
	PT = message
	Key = key
	IV = iv
	for i in range(100):
		print(f"KEY[{i}] = {Key.hex()}")
		print(f"IV[{i}] = {IV.hex()}")
		print(f"PLAINTEXT = {PT.hex()}")

		cipher = Cipher(algorithms.AES128(Key), modes.ECB())
		encryptor = cipher.encryptor()
		cfb8 = CFB.CFB8(IV, encryptor)
		CT = []
		for j in range(1000):
			# ct_j = cipher_core_update(encryptor, PT, padder)
			# print(f"PT:{PT.hex()}")
			# ct_j = cipher_core_update(encryptor, PT)
			ct_j = cfb8.update(PT)
			# print(f"ct_j:{ct_j.hex()}")
			# print(type(PT), type(ct_j))
			if j == 0:
				# print(f"IV[{j}]: {IV[j]}, {type(IV[j])} bytes: {bytes(IV[j])}")
				PT = ByteJ(IV, j)
				# print(f"PT:{PT.hex()}")
			else:
				if j < 16:
					PT = ByteJ(IV, j)
				else:
					PT = CT[j-16]
			CT.append(ct_j)
		
		ct_j += cipher_core_finalize(encryptor)
		print(f"CIPHERTEXT = {ct_j.hex()}\n")
		# print(type(byte_list_to_bytes(CT[j-15:])), " : ", byte_list_to_bytes(CT[j-15:]))
		# print(type(Key), " : ", Key.hex())

		Key = bytes(a ^ b for a, b in zip(Key, byte_list_to_bytes(CT[j-15:])))
		IV = byte_list_to_bytes(CT[j-15:])
		PT = CT[j-16]
	return


def do_cfb128_mont_test(message, key, iv):
	PT = message
	Key = key
	IV = iv
	for i in range(100):
		print(f"KEY[{i}] = {Key.hex()}")
		print(f"IV[{i}] = {IV.hex()}")
		print(f"PLAINTEXT = {PT.hex()}")

		cipher = Cipher(algorithms.AES128(Key), modes.CFB(IV))
		encryptor = cipher.encryptor()
		CT = []
		for j in range(1000):
			# ct_j = cipher_core_update(encryptor, PT, padder)
			ct_j = cipher_core_update(encryptor, PT)
			if j == 0:
				PT = IV
			else:
				PT = CT[j-1]
			CT.append(ct_j)
		
		ct_j += cipher_core_finalize(encryptor)
		print(f"CIPHERTEXT = {ct_j.hex()}\n")
		Key = bytes(a ^ b for a, b in zip(Key, ct_j))
		IV = ct_j
		PT = CT[-2]
	return

def print_mont_test_message(mode, message, key, iv):

	if (mode==0): 
		cipher = Cipher(algorithms.AES128(key), modes.CBC(iv))
	if (mode==1): 
		cipher = Cipher(algorithms.AES128(key), modes.OFB(iv))
	if (mode==2): 
		cipher = Cipher(algorithms.AES128(key), modes.CFB(iv))
	if (mode==5): 
		cipher = Cipher(algorithms.AES128(key), modes.CFB8(iv))
	if (mode==3): 
		cipher = Cipher(algorithms.AES128(key), modes.CTR(iv))
	if (mode==4): 
		cipher = Cipher(algorithms.AES128(key), modes.ECB())
	if (mode==6): 
		print("Monte Carlo Test")
		print("Type:\t\t\t","AES")
		print("Mode:\t\t\t","CFB1")
		print("Message:\t\t",message[0])
		print("Message len:\t\t",len(message))
		print("\nKey:\t\t\t",key.hex())
		if (mode!=4): print("IV:\t\t\t",iv.hex())
		print("\n")
		return
	print("Monte Carlo Test")
	print("Type:\t\t\t",cipher.algorithm.name)
	print("Mode:\t\t\t",cipher.mode.name)
	print("Message:\t\t",message.hex())
	print("Message len:\t\t",len(message))
	print("\nKey:\t\t\t",key.hex())
	if (mode!=4): print("IV:\t\t\t",iv.hex())
	print("\n")

def do_aes_mont_test(message, key, iv, mode):
	print_mont_test_message(mode, message, key, iv)
	if (mode==0): 
		# cipher = Cipher(algorithms.AES128(key), modes.CBC(iv))
		do_cbc_mont_test(message, key, iv)
	if (mode==1): 
		# cipher = Cipher(algorithms.AES128(key), modes.OFB(iv))
		do_ofb_mont_test(message, key, iv)
	if (mode==2): 
		# cipher = Cipher(algorithms.AES128(key), modes.CFB(iv))
		do_cfb128_mont_test(message, key, iv)
	if (mode==5): 
		# cipher = Cipher(algorithms.AES128(key), modes.CFB(iv))
		# do_cfb8_mont_test(message, key, iv)
		do_cfb8self_mont_test(message, key, iv)
	if (mode==6): 
		# cipher = Cipher(algorithms.AES128(key), modes.CFB(iv))
		# do_cfb8_mont_test(message, key, iv)
		do_cfb1_mont_test(message, key, iv)
	if (mode==3): 
		cipher = Cipher(algorithms.AES128(key), modes.CTR(iv))
	if (mode==4): 
		# cipher = Cipher(algorithms.AES128(key), modes.ECB())
		do_ecb_mont_test(message, key)


def main():

	config_file_path = 'config.txt'
	config = read_config(config_file_path)
	# print(config)
	count = 0
	for item in config:
		# print(item)
		if len(item['PLAINTEXT']) == 1:
			message = [int(item['PLAINTEXT'])]
		else:
			message = hex_to_bytes(item['PLAINTEXT'])
		key 	= hex_to_bytes(item['KEY'])
		if 'IV' in item:
			iv 	= hex_to_bytes(item['IV'])
		else:
			iv	= hex_to_bytes("00"*16)
		# print(message)
		# print(key)
		# print(iv)

		mode = mode_to_number(item['MODE'])
		# print(f"Number mode: {mode}")
		if mode is None:
			print("\n===========================\n")
			print("[\033[91mERROR\033[0m]", f" Error mode {item['MODE']} at round {count}.")
			print("\n===========================")
			count += 1
			continue
		
		# # do_sm4(message, padder, unpadder, key, iv, mode)
		if 'MONT' in item:
			print(f"\n===== Run {count} round aes mont test =====\n")
			# print("Do mont test")
			do_aes_mont_test(message, key, iv, mode)
		else:
			# print("Do normal test")
			print(f"\n===== Run {count} round aes normal test =====\n")
			do_aes(message, key, iv, mode)
			# do_aes(message, key, iv, mode)
		print("\n===========================")

		count += 1

	


if __name__ == "__main__":
    main()