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
	
def hex_list_to_bytes_list(hex_list):
	res = []
	for hex_str in hex_list:
		if "0x" in hex_str:
			res.append(codecs.decode(hex_str[2:], 'hex'))
		else:
			res.append(codecs.decode(hex_str, 'hex'))

	return res

def bytes_to_hex(byte_str):
    return codecs.encode(byte_str, 'hex').decode('utf-8')

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

def read_config(file_path):
	config_list = []
	with open(file_path, 'r') as file:
		lines = file.readlines()

	current_config = {}
	plaintext_lines = []
	key_lines = []
	reading_plaintext = False
	reading_key = False
	for line in lines:
		line = line.replace(" ", "")
		# line = line.strip()
		line = line.split('#')[0].strip()
		if not line:
			if current_config:
				if len(current_config['PLAINTEXT']) == 1:
					current_config['PLAINTEXT'] = current_config['PLAINTEXT'][0]
				if len(current_config['KEY']) == 1:
					current_config['KEY'] = current_config['KEY'][0]
				config_list.append(current_config)
				current_config = {}
			continue

		if 'PLAINTEXTstart' in line:
			reading_plaintext = True
			continue
		elif 'PLAINTEXTend' in line:
			reading_plaintext = False
			current_config['PLAINTEXT'] = plaintext_lines
			plaintext_lines = []
			continue

		if 'KEYstart' in line:
			reading_key = True
			continue
		elif 'KEYend' in line:
			reading_key = False
			current_config['KEY'] = key_lines
			key_lines = []
			continue

		if reading_plaintext:
			plaintext_lines.append(line)
		elif reading_key:
			key_lines.append(line)
		elif '=' in line:
			key, value = line.split('=', 1)
			current_config[key] = value

	if current_config:
		if len(current_config['PLAINTEXT']) == 1:
			current_config['PLAINTEXT'] = current_config['PLAINTEXT'][0]
		if len(current_config['KEY']) == 1:
			current_config['KEY'] = current_config['KEY'][0]
		config_list.append(current_config)

	return config_list


def cipher_core(cipher, message, padder, unpadder):

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
def cipher_core_update(encryptor, message):

	# pad_flag = False

	# encryptor = cipher.encryptor()

	# str=padder.update(message.encode())+padder.finalize()
	
	# Do not pad if message already fit in several blocks. 
	# if len(message) % 16 != 0:
	# 	pad_flag = True
	
	# if pad_flag:
	# 	pad_msg=padder.update(message)+padder.finalize()
	# else:
	# 	pad_msg = message
	pad_msg = message

	# pad_msg=padder.update(message)+padder.finalize()

	ciphertext = encryptor.update(pad_msg)

	return ciphertext

def cipher_core_finalize(encryptor):
	# encryptor = cipher.encryptor()
	return encryptor.finalize()

def do_sm4(message, key=None, iv=None, mode=0):

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
		cipher = Cipher(algorithms.SM4(key), modes.CBC(iv))
	if (mode==1): 
		cipher = Cipher(algorithms.SM4(key), modes.OFB(iv))
	if (mode==2): 
		cipher = Cipher(algorithms.SM4(key), modes.CFB(iv))
	if (mode==5): 
		cipher = Cipher(algorithms.SM4(key), modes.CFB8(iv))
	if (mode==3): 
		cipher = Cipher(algorithms.SM4(key), modes.CTR(iv))
	if (mode==4): 
		cipher = Cipher(algorithms.SM4(key), modes.ECB())
		
	if cipher is not None:
		ciphertext, rtn, pad_msg = cipher_core(cipher, message, padder, unpadder)
			
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

		# res_list.append(ciphertext)

		# if rtn != message:
		# 	print("[\033[91mERROR\033[0m]", " Encrypt/Decrypt error.")
	else:
		if (mode == 6):
			cipher = Cipher(algorithms.SM4(key), modes.ECB())
			encryptor = cipher.encryptor()
			cfb1 = CFB.CFB1(iv, encryptor)
			ciphertext = cfb1.update(message)
			# print("Type:\t\t\t","AES")
			# print("Mode:\t\t\t","CFB1")
			# print("Message:\t\t",message[0])
			# print("Message len:\t\t",len(message))
			# print("\nKey:\t\t\t",key.hex())
			# print("IV:\t\t\t",iv.hex())
			# print("\nCipher:\t\t\t",ciphertext[0])
			# res_list.append(ciphertext)

	return ciphertext


def do_ecb_mont_test(message, key):
	PT = message
	Key = key
	for i in range(100):
		print(f"KEY[{i}] = {Key.hex()}")
		print(f"PLAINTEXT = {PT.hex()}")
		cipher = Cipher(algorithms.SM4(Key), modes.ECB())
		# cipher = Cipher(algorithms.AES128(Key), modes.ECB())
		CT = []
		for j in range(1000):
			padder = padding.PKCS7(128).padder()
			unpadder = padding.PKCS7(128).unpadder()
			ct_j, _, _ = cipher_core(cipher, PT, padder, unpadder)
			CT.append(ct_j)
			PT = ct_j
			# print(f"CT[{j}]: {ct_j.hex()}")
		Key = bytes(a ^ b for a, b in zip(Key, CT[-1]))
			# cipher = Cipher(algorithms.SM4(Key), modes.ECB())
			
		print(f"CIPHERTEXT = {CT[-1].hex()}\n")
		PT = CT[-1]
	return

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
		cipher = Cipher(algorithms.SM4(Key), modes.CBC(IV))
		encryptor = cipher.encryptor()
		CT = []
		for j in range(1000):
			# ct_j = cipher_core_update(encryptor, PT, padder)
			ct_j = cipher_core_update(encryptor, PT)
			if j == 0:
				# cipher = Cipher(algorithms.SM4(Key), modes.CBC(IV))
				# ct_j, _, _ = cipher_core_update(cipher, PT, padder, unpadder)
				PT = IV
			else:
				# cipher = Cipher(algorithms.SM4(Key), modes.ECB())
				# ct_j, _, _ = cipher_core_update(cipher, PT, padder, unpadder)
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
	# print(f"Key[{i}] = {Key.hex()}")
	# print(f"PLAINTEXT = {PT.hex()}")
	for i in range(100):
		print(f"KEY[{i}] = {Key.hex()}")
		print(f"IV[{i}] = {IV.hex()}")
		print(f"PLAINTEXT = {PT.hex()}")

		# padder = padding.PKCS7(128).padder()
		# unpadder = padding.PKCS7(128).unpadder()
		cipher = Cipher(algorithms.SM4(Key), modes.OFB(IV))
		encryptor = cipher.encryptor()
		CT = []
		for j in range(1000):
			# ct_j = cipher_core_update(encryptor, PT, padder)
			ct_j = cipher_core_update(encryptor, PT)
			if j == 0:
				# cipher = Cipher(algorithms.SM4(Key), modes.CBC(IV))
				# ct_j, _, _ = cipher_core_update(cipher, PT, padder, unpadder)
				PT = IV
			else:
				# cipher = Cipher(algorithms.SM4(Key), modes.ECB())
				# ct_j, _, _ = cipher_core_update(cipher, PT, padder, unpadder)
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

		# Not support for SM4
		# cipher = Cipher(algorithms.SM4(Key), modes.CFB8(IV))
		cipher = Cipher(algorithms.SM4(Key), modes.ECB())
		encryptor = cipher.encryptor()
		cfb8 = CFB.CFB8(IV, encryptor)
		CT = []
		for j in range(1000):

			ct_j = cfb8.update(PT)

			if j == 0:
				PT = ByteJ(IV, j)
			else:
				if j < 16:
					PT = ByteJ(IV, j)
				else:
					PT = CT[j-16]
			CT.append(ct_j)
		
		ct_j += cipher_core_finalize(encryptor)
		print(f"CIPHERTEXT = {ct_j.hex()}\n")

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

		cipher = Cipher(algorithms.SM4(Key), modes.CFB(IV))
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
		cipher = Cipher(algorithms.SM4(key), modes.CBC(iv))
	if (mode==1): 
		cipher = Cipher(algorithms.SM4(key), modes.OFB(iv))
	if (mode==2): 
		cipher = Cipher(algorithms.SM4(key), modes.CFB(iv))
	if (mode==5): 
		cipher = Cipher(algorithms.SM4(key), modes.CFB8(iv))
	if (mode==3): 
		cipher = Cipher(algorithms.SM4(key), modes.CTR(iv))
	if (mode==4): 
		cipher = Cipher(algorithms.SM4(key), modes.ECB())
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

def do_sm4_mont_test(message, key, iv, mode):
	print_mont_test_message(mode, message, key, iv)
	if (mode==0): 
		# cipher = Cipher(algorithms.SM4(key), modes.CBC(iv))
		do_cbc_mont_test(message, key, iv)
	if (mode==1): 
		# cipher = Cipher(algorithms.SM4(key), modes.OFB(iv))
		do_ofb_mont_test(message, key, iv)
	if (mode==2): 
		# cipher = Cipher(algorithms.SM4(key), modes.CFB(iv))
		do_cfb128_mont_test(message, key, iv)
	if (mode==5): 
		# cipher = Cipher(algorithms.SM4(key), modes.CFB8(iv))
		do_cfb8_mont_test(message, key, iv)
	if (mode==6):
		do_cfb1_mont_test(message, key, iv)
	if (mode==3): 
		cipher = Cipher(algorithms.SM4(key), modes.CTR(iv))
	if (mode==4): 
		# cipher = Cipher(algorithms.SM4(key), modes.ECB())
		do_ecb_mont_test(message, key)


def GFSbox(messages_list, key, iv, mode, item, count):
	res_list = []
	if 'MONT' in item:
		print(f"\n===== Run {count} round sm4 mont test =====\n")
		# print("Do mont test")
		# do_aes_mont_test(message, key, iv, mode)
		print("No need for mont test.")
	else:
		# print("Do normal test")
		print(f"\n===== Run {count} round sm4 GFSbox test =====\n")
		print("Type:\t\t\t","SM4")
		print("Mode:\t\t\t",item['MODE'])
		print("\nKey:\t\t\t",key.hex())
		if (mode!=4): print("IV:\t\t\t",iv.hex())
		print("------- All Messages -------")
		for message in messages_list:
			print(message.hex())
		print("----------------------\n")

		for message in messages_list:
			# print("----------------------")
			ciphertext = do_sm4(message, key, iv, mode)
			res_list.append(ciphertext)
			# print("----------------------\n")
	
	print("------- All Result -------")
	for ciphertext in res_list:
		print(ciphertext.hex())
	print("----------------------\n")
	
def KeySbox(message, key_list, iv, mode, item, count):
	res_list = []
	if 'MONT' in item:
		print(f"\n===== Run {count} round sm4 mont test =====\n")
		# print("Do mont test")
		# do_aes_mont_test(message, key, iv, mode)
		print("No need for mont test.")
	else:
		# print("Do normal test")
		print(f"\n===== Run {count} round sm4 KeySbox test =====\n")
		print("Type:\t\t\t","SM4")
		print("Mode:\t\t\t",item['MODE'])
		print("\nMessage:\t\t",message.hex())
		print("------- All Keys -------")
		for key in key_list:
			print(key.hex())
		print("----------------------\n")
		for key in key_list:
			# print("----------------------")
			ciphertext = do_sm4(message, key, iv, mode)
			res_list.append(ciphertext)
			# print("----------------------\n")
	
	print("------- All Result -------")
	for ciphertext in res_list:
		print(ciphertext.hex())
	print("----------------------\n")
	check_res("KeySbox", res_list)


def VarTxt(messages_list, key, iv, mode, item, count):
	res_list = []
	if 'MONT' in item:
		print(f"\n===== Run {count} round sm4 mont test =====\n")
		# print("Do mont test")
		# do_aes_mont_test(message, key, iv, mode)
		print("No need for mont test.")
	else:
		# print("Do normal test")
		print(f"\n===== Run {count} round sm4 VarTxt test =====\n")
		print("Type:\t\t\t","SM4")
		print("Mode:\t\t\t",item['MODE'])
		print("\nKey:\t\t\t",key.hex())
		print("------- All Messages -------")
		for message in messages_list:
			print(message.hex())
		print("----------------------\n")
		for message in messages_list:
			# print("----------------------")
			ciphertext = do_sm4(message, key, iv, mode)
			res_list.append(ciphertext)
			# print("----------------------\n")
	
	print("------- All Result -------")
	for ciphertext in res_list:
		print(ciphertext.hex())
	print("----------------------\n")
	check_res("VarTxt", res_list)

def VarKey(message, key_list, iv, mode, item, count):
	res_list = []
	if 'MONT' in item:
		print(f"\n===== Run {count} round sm4 mont test =====\n")
		# print("Do mont test")
		# do_aes_mont_test(message, key, iv, mode)
		print("No need for mont test.")
	else:
		# print("Do normal test")
		print(f"\n===== Run {count} round sm4 VarKey test =====\n")
		print("Type:\t\t\t","SM4")
		print("Mode:\t\t\t",item['MODE'])
		print("\nMessage:\t\t",message.hex())
		print("------- All Keys -------")
		for key in key_list:
			print(key.hex())
		print("----------------------\n")
		for key in key_list:
			# print("----------------------")
			ciphertext = do_sm4(message, key, iv, mode)
			res_list.append(ciphertext)
			# print("----------------------\n")
	
	print("------- All Result -------")
	for ciphertext in res_list:
		print(ciphertext.hex())
	print("----------------------\n")
	check_res("VarKey", res_list)




ground_truth = {
	"KeySbox": [
		0x24C1211CCEC3D57786B792B5595304E9,
		0xD5284C4176BCFDDEABAD8A2563A9ABE3,
		0x35B7348BC90CF5CBFDDF25188C67CA4B,
		0xCE6CE09807532864619F0BF6236F0BF5,
		0x6BBEC7055320CABBB31500079F256B70,
		0xFA9A9118BFD342457757139733628CB5,
		0x56AD91AE0806BC037A5BDAC0F2046284,
		0xD3CD70D616945372CD0F510DD2F92218,
		0x970B6B5CD60D38EF99C2FFD0AEE70E9A,
		0x969FDCF780DB7469B4CEA1A244476625,
		0x8784EF897C3D6855DB8C578D67ADE77E,
		0x1F14372DEC4BD49D0A747AF5D48E9FBD,
		0x22E16AFFAFA69C751F51D949F8CAF5DC,
		0x9E418DACA36479EAEECD6AA8B01CB847,
		0xEB67AAE0BC21F2B81DCDE8CAE4EBCC36,
		0xF042ABFCCCD0B8C24C42A297C1B2471A,
		0x856757C8609EDDEB99C8701B57990EA3,
		0xDDE3FBE51163E2FE6D7D4DDC388E05D3,
		0x2763CEDEA486955BD8E42D7997336A45,
		0x1EA56F24675CBF34E89F6A0C58B6D503,
		0xD99114290B1C8AE531EBF8DB9BCCF71D
	],
	"VarTxt": [
		0x4DA36EE207E092A8979043E396C05BB6,
		0x9CC00DEF6DF2C53D6510D9FCF8E25E2A,
		0x8E537B78FF2464D10AE6955AAED0307E,
		0x114E21591C76DA760628F14023EDD0DF,
		0x8E71152433D5CF7BCA35431B81223228,
		0x2689CDA6CD052DEDD197A428110DF45A,
		0x6E3E6110B92C724568B7FC3B369E5B79,
		0x2D43C5F3D6B6639890CC72D7D673440D,
		0x488760BC1E78AE51881123EEE8E39306,
		0xBB803259900ED98AF41E2FC18FF2CE10,
		0xE47C677194CED1A9BEC08F157D6C8025,
		0x6EA07FFB3E354DCD4D08D8B05353C9B5,
		0x299CCE0E19C6763F85878E8365581304,
		0x647962698C33D608D5B889E5E209AA94,
		0x0929D56BCF6D579E6E6BFD1C5E3BB134,
		0x377154071B97CC96F2DA6E9A65E02043,
		0x4308D9ADD0467768253A65271D519E06,
		0xFD66AFB5D63194EF952EBE6E4EBABFE9,
		0x1DE04B7AC1FD88DCCCB3A26412247045,
		0xCE0A7D07756A5B2A38754DDB5564698B,
		0xAB35D70C896ADBA2D7791B91122B0002,
		0xA3C92831A3EFB305527DF1B375CA7A29,
		0xE596D5E96F6C41BE26BC0721DFEE4E08,
		0xA47477AA62FAD83CD9CB38B819FCA504,
		0x4143D9AE012C1C9D7216127C1BE689F7,
		0xD2A4F0C132B42648E5CAAAC632BDDAA3,
		0xAAB1D89620586BB77AF430582182A4F9,
		0xF08EE1AB0CB06CF32EE5DB9C2440EACE,
		0x70066D543DC2F421FDE5636692546532,
		0x9D4DBEE72BE20D177283BD0EAE7C053D,
		0x7D061D68284B2B41914F6BE6468D3AD8,
		0x57B69746C22B3A6C8AED7D524E4A36F8,
		0x380FC98BB19F6F3718D66360FD057B36,
		0x823488EE0430EC669CFFC828507CF8DA,
		0x07A952DC90F5C3D7041DE18B85C61FBD,
		0xEC1E9919E9D75EBC6A9BD8F5E2FF6BDD,
		0xB3042D1D21871AEEACD93036B3170961,
		0xCCAB9407EBB3328805FC5C4083A599FC,
		0x42D7840BB3040822D1321242FA49A830,
		0xFD992CA6AD92696A544D7D41CE4615F7,
		0x7EDEE85509FEE9FCF4588BC0CDC2A92D,
		0xD380E5F04C2338916E3A30602DE40653,
		0x469493ECC27F02F7EB367BB455D0BF45,
		0xCE63ABA18075BD36CCADE15C723E489A,
		0xC6FBE2995E001531D5D77579F1C87311,
		0x0C2C65F05B2D91ED9595D89C5EB9A576,
		0xDE0FCAD8D9EB7A9B3DC2E16BFAE73EFA,
		0x4B07F17237439FF22FF521AF74121D94,
		0x48F1E926AD194E59B128D569873D23A5,
		0x18523706A08E77FAC7A53C39E0425DBF,
		0x5EC6140EB36461AB243EC0C218A42F96,
		0x896B5FA82261FB92A7E2CFFD1FC39B16,
		0x8E0BC0DA212037600DCDB282DEA2A4C0,
		0x111D289466E2E47CF97DBFB1DC3793E1,
		0x9005611B8FDB55EF222B52D8AAE090E3,
		0x8A13722092B7FB0B805D2C56055E44FB,
		0x0286F8545EF098B7F7E35CC718922AB4,
		0x1825F87813FD7349273C8E1CA4E09689,
		0x35F2ADFAEC121EC6122FD0579F1F8873,
		0x4ECF8DDFC0A4A7ED9C0D51A97F94D70E,
		0x523AF9498428007EB480557B622B9BFF,
		0x0CBCC715A0517BF9FE2C3C4281A1168B,
		0x2338D091A6D017C5DA827FBE1CA12C84,
		0x163B1D6C7497A9C8E82A0D500A4A0A60,
		0x180FA8832A7657E5F535670455D4D1C9,
		0x5FB88A7D2757949F5203BD30D8F3DF7B,
		0xCB2D11B0F27868B4E71C8DF7EE6EEA32,
		0xA0B7E2E9A84F8DB86D3838F9D900CB68,
		0xF0BF47040E328C470836C5272C472609,
		0x3D896660B0EFC80CF15D721EB477477D,
		0x2385C0D9553E7C51B511AF5234608FD2,
		0x497658BAD829D511FE5E639312059535,
		0xBF6A88AE1556CD359B0830E977BFCD2A,
		0x409F8BF304186D3ECDE2F46882049B9E,
		0xA1A060E5F60D55DC2E9A6F3E4AF68489,
		0x2E07038F7287B34A31D7129D2418391B,
		0x2B45E68332E97EC4D6B5FE1C87A1036A,
		0x60CE238173F4E701CF1BC40713966CD4,
		0xF879E9B83F0122970181C9310CE29E58,
		0xCBCA527F657A116F4ACC228782176A37,
		0x02CBE6079AEA0114A0C0B434AA5D4498,
		0x2C3CB6732ED33CB380A14D251E553671,
		0xE19F6774F653AF9AD67F1A9857D5F8C4,
		0x48FD056D43208A675E5B81B4A1D77E62,
		0x729006B3CAD3B6E006266EB23A60BDE1,
		0x06BA14EAACA1FE2BFA21A29CB93A52F4,
		0x0F46B1EFB68E1774F079BD650EEF192C,
		0x559F5F95A14764FEE94DBFC5F543AF42,
		0x93B8B5E2C67B91B3CB257BF2BCCBB9E9,
		0xABA86D7D4ABBF9876BBAEFFAF1D62F17,
		0x26B2A4EB5409A34D3BAEAB74C1FD4B07,
		0x18A9F7C74CA7E554925AAB924577E385,
		0x784BE8D9264E30C656BA4477AB48EC17,
		0xA8F31B30A3CB7761C740C7ED742878B8,
		0x3F4C329B217F6362F00F7CC6EBF56490,
		0x2D7E26B66D1F034AB983434825009AED,
		0xF9F28C34F98D4C0605EF857A74279D6A,
		0x5B231E908EF442E3E4165D2DD77CB49F,
		0x3FF6546AC9A5C5DF2DC5ABC4A857A5D8,
		0x3ECC8A2718F8AEB7F5969556A88AD46D,
		0x196543ED2DBC4C51194302EBE90FE8D1,
		0x63ED18C062FE75ACB621286124D82133,
		0x0C0F99FFD919816400B2C65D420482AF,
		0x776FDC4D33EF3F0028D2002DD0523697,
		0x3CADBCCFA8BB8CC94AE52968AE7EA70E,
		0xAA4D3A992FA511718ADDAB8D34DC11B0,
		0x7E74E500129B1806D5F4BE12781373B3,
		0xB6AD5E3331F4D2F424EC43A6B65AA913,
		0x7C731CE76ED15ABBC77D194CA9E11960,
		0xB4D74AF6B0DA8408532A1E4AD34A22F5,
		0x83A7576A78622292F849D017339A2C2D,
		0x38C51B8E3180C01F3883E2645DE5CEE1,
		0x9783B27B5E1BA174592A86065AC755A6,
		0x299EC522F58B0A396E4263E72E9B064E,
		0x509B67AE01CC59E56BCBB895C3EF7F0B,
		0x651BD7013721AB53A9A754465B6A6D59,
		0x6D2B17718B74C159DB1F16AF06BDA2EF,
		0xE98681CB2041986F455D941D964FBF7F,
		0x817DB83D3297B91F7693027E0454C99B,
		0xA48D41718EEB262CEC7727E3B0F8952B,
		0x78AD2FDE0F11D06575738E480258BA5B,
		0x0F64F87F242BCAE60CA7BBFA9824745F,
		0xB48AB5280126E674A4A7C6E51511B445,
		0x71C1D40EFBFE2CC952B0684F6D4CE8FD,
		0x556E7D5F248E39FA96641F068BBC1AEF,
		0x436D0A5E92CFD6F076B0C95E3941857E,
		0xFB0C767BBA05399469082CCEC103A7AE,
		0x61EB6915E56E4E80B5048D06AC8FE3A9
	],
	"VarKey": [
		0xF8536C64AECF6FA98E348AB2C2474B59,
		0x85BB2A6888DD415FD31F6CED018C2593,
		0xF63C1B83BFA4ABC86CDA3C9DDA5BE4D6,
		0xD5054C7F0E66C18E520975811F3F4BA0,
		0x3AB6A364D9FBEECCD042DB62DE1DBBB6,
		0x52D1232602F10355DEA3527B27879006,
		0x244CAE84229535A3705EDFD5D81F3C73,
		0x366D6A5F4EE1B25D6D9D3974CBA43B48,
		0x1C9AFD8118B31F47394903FB0C5CA9F3,
		0xB6E262A048D674F1AB5E2009B175AF44,
		0x5FAE645EAED6AA6DD91CC1F3B5B940C6,
		0x879D46C9D0D32783B0B92DCFC863B7CF,
		0xD5BF3AFFC9A6095BF5A186C33D26F5F6,
		0x090AB931E1C974EFD09625EEE72F1733,
		0xB68226250F2600CDF3905CBD209B099A,
		0x17064A14CF4CD01547456BB1DE019F07,
		0x4D251E23CC2C55969515C57382AF92DF,
		0xA4FAF95BC4798DEFD25A6C68B77A1918,
		0x94A6D9820BD6D0C68D6D147DF2BCA37F,
		0xF77F55D9558DC4B6B5570B3D1D920BB0,
		0xC1943F98E6E65A643DBB3B1E14E4DBCD,
		0x4912DF00C618491660B44CB3B470E600,
		0x574F52ECCD7579678BBA5A688151DDBC,
		0x90702B63792E1F05C0D68FBEA6E8D1DB,
		0x27B92ABC8E5A92C0B82FE1927BAEFDDC,
		0x2CDC260D1DDC8EA2D19380A0888EEFAB,
		0xE19796B177D37C00CDD03D384883F387,
		0x0EDDC928CAF73A643E5C14AD40121FCE,
		0xFE691484109D5C02F2348EEB4879FFFF,
		0x5A50FC4EB051CD0B2CC3DDF87FC8E07B,
		0x45602A6D64866C1B0DF58858A5DD24C3,
		0x9E302677838645272E2A4BC5AAD11FA1,
		0x48B0CDC73A808769424B6DC86DAF0F53,
		0x23A5098EEBBB29A2D35E9EBCC02E67D8,
		0x3CCCAA243AFAAAE0436784222FD47F05,
		0x307320E0336DECF8C3C7FCA6FA1CC2CD,
		0x5D972B4E877582E4DA31C6A3CC3949F2,
		0x44D1698E444E95F4290F81A4427B1A31,
		0xE650669488CD1953B59FD549B5DA3FA7,
		0xD05E709A4125F7D3635487C7B9FE5F5C,
		0x66EACC65CD21DC0BD823FA3D06B8F58B,
		0x913EC9EF96587CC3DF5CBA8996194829,
		0x0E4AEC04E09F26AC2DF4CB814788529B,
		0x7934F9C41A0D82B9F896869ADB710365,
		0x3CD8063B2C2B9E5142E172F599B20DD8,
		0xDDC648119D45D751169E45E602DCE2E7,
		0xA49F7CAA473D01D3449F99541479E542,
		0x06960E5D3BC351903EF93BBA2EF0782E,
		0xF8DCDD987F61A9A131915710DB38D928,
		0x2BB7B4A1D3AA239D61B159EC66BC92CF,
		0xD1E15C74B15C79FBB9051895D2ECD76D,
		0x0BBD9AA1210ADCA231E95D76FC50561C,
		0x0CCB407B387F3D408E98D8E278F89B25,
		0x94674A72A481E38B5744AB6055449CE6,
		0x30DE816142FCD399345DB8B22D7154E3,
		0x2FDDDA7F619DAA5DEAC9F7B4FB327EC3,
		0xE49797AD6295A86202C9FCDA944EEBE4,
		0x040F72B619215FD92A3EDF210294451F,
		0x1B69BEC499CE8140134D7717CA7D771A,
		0x328FBAA7844A24B123943412A86CA0F7,
		0xD35A98B6C30E3991178C3233D0614D15,
		0x31E02D6A0057B067A6F626CA1D97C85C,
		0xEACBD81416A68B3270CFDF00331B8F53,
		0xA7A867EB92BBC21C057F30466F564A16,
		0x3DF96A5D3CAE266E7CC5EC385305460D,
		0x50CBE1910DED3F4DFA0410D8D99ED76B,
		0x5273AF925025050E4DCE3312CD1335D7,
		0xA783FBBEBCF07B32B99958D9FB807079,
		0xC55B3C08B1C9AE0F3299B1E96870DF70,
		0xAE5C4C3F242056704D53AA74F4A70E23,
		0xCB3349E1522F17C426DBD8423A065A0B,
		0x8A017025837D80D13CDF2EEAF9352D2F,
		0x482A9B8E22F36BCF9FF8CFD07E3D1E0B,
		0xC63339DFC83DF4F6AE93A6653ED623FF,
		0x27D874C1047F8FEE7F0E70FD2600663F,
		0x40C767C0075D301888FD0CD50D880044,
		0x527C72515E6A64E9EBE39DF22BB1169F,
		0xD02B1A906675A4F8EBF51298306B6646,
		0x4A6D5F2B689A03212C1A1E09A0DE1B66,
		0x5ED236B9D469F912B2502CF4EBD9043F,
		0x32A5991CB5A0439390AD9AC4BAF74616,
		0x8A7A967A82522B08144285156D6156D1,
		0x7F879CAB0C3CD3CECD71020EECE55603,
		0x1F089F4B77EFCD9DA6EA8F21D76C2AEF,
		0x72B6A9536320CBD46F890B4811574EB5,
		0xA5FE8A8ACDE0560043AD64818C31393D,
		0x6164691BE29BE3360E5F93B439F6D9D9,
		0x5B3DBD6D2D3C90E4A32A65CD91F59292,
		0x8C484B4A3E4F49CEB17AC138857557F6,
		0x13BD37FC35E0D449468BAB42D7F87923,
		0xA32C736E66FA27C9E533A54A895FA2E3,
		0xC32318579CB145F7C88C4B9C5BBE1414,
		0x907CFF4A1F48FD58DED32D443D1E4A19,
		0xA20BAFCDCB1987D2C2CB17851E876217,
		0x859AF09F9E3D75B8CF45750F7EE9E3B8,
		0xAB3AC94162A8F10A4A767480FC130D98,
		0xDB390ABB2C2DA0AD8F1728557D41E868,
		0x8A4312CAE1E5173B8E808E44E748F350,
		0xD1580CE556E684475BC74CBFBAEA5289,
		0x5A264E3FAF7D6AAF0137F361D3FA0D8D,
		0x67C7750B2F35D1702AA0A30ECDCFC2EA,
		0x2B24471DCD90F639ED0536C71B24F55F,
		0xDFA7910286AD626A73B8D710E7F243C1,
		0x660B690B61A43B902C94C78F5714832F,
		0x1F1DEA09B10677A894A96267293F9417,
		0x853B20574C29106F9E1F83E8930AE8BB,
		0x934492EF562D9078BEFB9BF5F2071CC1,
		0xDF2AE5F73D6510F8DED22215609D7D08,
		0x26CB5F500EEED1D131313840CD8B3040,
		0x8AD35D9CF954E571475DCBCDEA44AA14,
		0xC466B43AC88FD77DF4FBD69484B9A9A4,
		0x45588742CA52F60EF5D58CA565293602,
		0x3BB2EDF378CECD75292D276D389DE2DE,
		0xFF394C3E1895CB24685B9D6096C5DB72,
		0x4C0D0966E41CB5BAC0E3668D2AF72F9C,
		0xA4FA28F5F68BB13D1EE153740EEC6D6D,
		0x48765F329B142E73E073B89C3A6EE9BA,
		0xE619F9DEFFE7E13773D1E5B465686BA0,
		0x66D081973137368E4294153E80D36C2B,
		0x1AA34CD69F6A2F69C08B5BC7F52A833A,
		0xEDF5C2BC2AA595AC4187DDBC7D0478CE,
		0x847E15F0DD81B581362D5861ECBD1EF3,
		0x5E3469478C3FD451BBB934F5A04BF60C,
		0xC12B698AA51D29BEDA71D2A05ADB245E,
		0xBB709D1889E9916EE5EE0572CCFE1BCC,
		0xAD25B57513400AB815797E6CA176151D,
		0x11F56E9EE5E17AB1B029E1ABF13564E2,
		0xE28F2C531ED6183DD16487C1614710E6
	]
}

def check_res(test_name, res):
	if test_name not in ground_truth:
		print("[No Ground Truth]")
	else:
		for i in range(len(res)):
			if int(res[i].hex(), 16) != ground_truth[test_name][i]:
				print(f"At index {i}\n\tres: 0x{res[i].hex()}\n\tground_truth: {hex(ground_truth[test_name][i])}")

	print("[Res Check Finish]")



def main():
	# message="Hello"

	# if (len(sys.argv)>1):
	# 	message=str(sys.argv[1])
	# if (len(sys.argv)>2):
	# 	mode=int(sys.argv[2])

	# if (len(sys.argv)>1):
	# 	mode=int(sys.argv[1])

	config_file_path = 'config2.txt'
	config = read_config(config_file_path)
	# print(config)
	count = 0
	for item in config:
		# res_list = []
		# print(item)
		messages_list = []
		key_list = []

		mode = mode_to_number(item['MODE'])
		# print(f"Number mode: {mode}")
		if mode is None:
			print("\n===========================\n")
			print("[\033[91mERROR\033[0m]", f" Error mode {item['MODE']} at round {count}.")
			print("\n===========================")
			count += 1
			continue

		if item['TEST'] == "GFSbox":
			# if len(item['PLAINTEXT']) == 1:
			# 	item['PLAINTEXT'] = "0" + item['PLAINTEXT']
			messages_list = hex_list_to_bytes_list(item['PLAINTEXT'])
			key 	= hex_to_bytes(item['KEY'])
			if 'IV' in item:
				iv 	= hex_to_bytes(item['IV'])
			else:
				iv	= hex_to_bytes("00"*16)
			GFSbox(messages_list, key, iv, mode, item, count)
		elif item['TEST'] == "KeySbox":
			message = hex_to_bytes(item['PLAINTEXT'])
			key_list 	= hex_list_to_bytes_list(item['KEY'])
			if 'IV' in item:
				iv 	= hex_to_bytes(item['IV'])
			else:
				iv	= hex_to_bytes("00"*16)
			KeySbox(message, key_list, iv, mode, item, count)
		elif item['TEST'] == "VarTxt":
			messages_list = hex_list_to_bytes_list(item['PLAINTEXT'])
			key 	= hex_to_bytes(item['KEY'])
			if 'IV' in item:
				iv 	= hex_to_bytes(item['IV'])
			else:
				iv	= hex_to_bytes("00"*16)
			VarTxt(messages_list, key, iv, mode, item, count)
		elif item['TEST'] == "VarKey":
			message = hex_to_bytes(item['PLAINTEXT'])
			key_list 	= hex_list_to_bytes_list(item['KEY'])
			if 'IV' in item:
				iv 	= hex_to_bytes(item['IV'])
			else:
				iv	= hex_to_bytes("00"*16)
			VarKey(message, key_list, iv, mode, item, count)
		
		# print(messages_list)
		# print(key)
		# print(iv)
		
		print("\n===========================")

		count += 1

		

	


if __name__ == "__main__":
    main()