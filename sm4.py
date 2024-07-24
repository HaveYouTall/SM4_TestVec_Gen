# ref: https://asecuritysite.com/symmetric/symsm4
import os
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives import padding
import sys

message="Hello"

keysize=16
iv = os.urandom(16)
mode=0

if (len(sys.argv)>1):
	message=str(sys.argv[1])
if (len(sys.argv)>2):
	mode=int(sys.argv[2])

key = os.urandom(keysize)

padder = padding.PKCS7(128).padder()

unpadder = padding.PKCS7(128).unpadder()

cipher=None

if (mode==0): 
	cipher = Cipher(algorithms.SM4(key), modes.CBC(iv))
if (mode==1): 
	cipher = Cipher(algorithms.SM4(key), modes.OFB(iv))
if (mode==2): 
	cipher = Cipher(algorithms.SM4(key), modes.CFB(iv))
if (mode==3): 
	cipher = Cipher(algorithms.SM4(key), modes.CTR(iv))
if (mode==4): 
	cipher = Cipher(algorithms.SM4(key), modes.ECB())

encryptor = cipher.encryptor()


str=padder.update(message.encode())+padder.finalize()

ciphertext = encryptor.update(str ) + encryptor.finalize()

# Now decrypt

decryptor = cipher.decryptor()


rtn=unpadder.update(decryptor.update(ciphertext) + decryptor.finalize())+unpadder.finalize()	

	
print("Type:\t\t\t",cipher.algorithm.name)
print("Mode:\t\t\t",cipher.mode.name)
print("Message:\t\t",message)
print("Message with padding:\t",str)
print("\nKey:\t\t\t",key.hex())
if (mode!=4): print("IV:\t\t\t",iv.hex())
print("\nCipher:\t\t\t",ciphertext.hex())
print("Decrypt:\t\t",rtn.decode())