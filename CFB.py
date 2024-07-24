##########################
# By HaveYouTall         #
# Date: 2024-07-24		 #
# Implement CFB1/8       #
##########################

import codecs
class CFB8:
    def __init__(self, iv, encryptor):
        self.encryptor = encryptor
        self.feedback = iv

    # encrypt
    def update(self, plaintext):
        ciphertext = bytearray()
        for byte in plaintext:
            # Encrypt the feedback
            encrypted_feedback = self.encryptor.update(self.feedback)
            # Take the first byte of the encrypted feedback
            encrypted_byte = encrypted_feedback[0]
            # XOR with the plaintext byte to get the ciphertext byte
            cipher_byte = byte ^ encrypted_byte
            ciphertext.append(cipher_byte)
            # Update the feedback with the ciphertext byte
            self.feedback = self.feedback[1:] + bytes([cipher_byte])
        return bytes(ciphertext)
    
    # def decrypt(self, ciphertext):
    #     plaintext = bytearray()
    #     for byte in ciphertext:
    #         # Encrypt the feedback
    #         encrypted_feedback = self.encryptor.encrypt(self.feedback)
    #         # Take the first byte of the encrypted feedback
    #         encrypted_byte = encrypted_feedback[0]
    #         # XOR with the ciphertext byte to get the plaintext byte
    #         plain_byte = byte ^ encrypted_byte
    #         plaintext.append(plain_byte)
    #         # Update the feedback with the ciphertext byte
    #         self.feedback = self.feedback[1:] + bytes([byte])
    #     return bytes(plaintext)
    
    

class CFB1:
    def __init__(self, iv, encryptor):
        self.encryptor = encryptor
        self.feedback = iv
    
    # encrypt
    # plaintext should be a bit array.
    # ciphertext is also a bit array
    # ref: https://nvlpubs.nist.gov/nistpubs/Legacy/SP/nistspecialpublication800-38a.pdf
    # 
    # Take openssl implementation as example.
    # ref1: https://github.com/openssl/openssl/blob/master/crypto/modes/cfb128.c#L186
    # ref2: https://github.com/openssl/openssl/blob/master/crypto/modes/cfb128.c#L150
    # OpenSSL says IV update is like we left shif IV bytes by 's' bit 
    #   (here s is 1, and IV should be transfered to hex representation
    #   and treated like a normal data, e.g., b'\x32\x24\xaa' is treated 
    #   like 0x3224aa, then do the left shift for 0x3224aa), 
    #   finally append the cipher_bit into it.
    def update(self, plaintext_bits):
        ciphertext_bits = []
        for bit in plaintext_bits:
            # Encrypt the feedback
            encrypted_feedback = self.encryptor.update(self.feedback)
            # print(f"encrypt iv: {encrypted_feedback.hex()}")
            # Take the first bit of the encrypted feedback
            encrypted_bit = (encrypted_feedback[0] >> 7) & 1
            # XOR with the plaintext bit to get the ciphertext bit
            cipher_bit = bit ^ encrypted_bit
            ciphertext_bits.append(cipher_bit)
            # Update the feedback with the ciphertext bit
            # self.feedback = self.feedback[:-1] + bytes([((self.feedback[15]) & 0xfe) | (cipher_bit & 1)])
            tmp = int(self.feedback.hex(), 16)
            tmp = (tmp << 1) & 0xffffffffffffffffffffffffffffffff
            tmp |= (cipher_bit & 1)
            # print(hex(tmp)[2:].zfill(32), len(hex(tmp)[2:].zfill(32)))
            # Transfer to bytes again.
            self.feedback = codecs.decode(hex(tmp)[2:].zfill(32), 'hex')
            # print(f"next iv: {self.feedback.hex()}")
        return ciphertext_bits

    # def decrypt(self, ciphertext_bits):
    #     plaintext_bits = []
    #     for bit in ciphertext_bits:
    #         # Encrypt the feedback
    #         encrypted_feedback = self.encryptor.encrypt(self.feedback)
    #         # Take the first bit of the encrypted feedback
    #         encrypted_bit = (encrypted_feedback[0] >> 7) & 1
    #         # XOR with the ciphertext bit to get the plaintext bit
    #         plain_bit = bit ^ encrypted_bit
    #         plaintext_bits.append(plain_bit)
    #         # Update the feedback with the ciphertext bit
    #         self.feedback = self.feedback[1:] + bytes([(self.feedback[15] << 1) | (bit & 1)])
    #     return plaintext_bits

    # encrypt
    # plaintext should be a bit array.
    # def update(self, plaintext):
    #     ciphertext = bytearray()
    #     bit_index = 0
    #     current_byte = 0

    #     for bit in plaintext:
    #         # Encrypt the feedback
    #         encrypted_feedback = self.encryptor.update(self.feedback)
    #         # Take the first bit of the encrypted feedback
    #         encrypted_bit = (encrypted_feedback[0] >> 7) & 1
    #         # XOR with the plaintext bit to get the ciphertext bit
    #         cipher_bit = bit ^ encrypted_bit
    #         # Store the ciphertext bit in the current byte
    #         current_byte = ((current_byte << 1) & 0xff) | cipher_bit
    #         bit_index += 1
    #         if bit_index == 8:
    #             # We have a full byte, add it to the ciphertext
    #             ciphertext.append(current_byte)
    #             bit_index = 0
    #             current_byte = 0
    #         # Update the feedback with the ciphertext bit
    #         # print(((self.feedback[15] << 1) & 0xff))
    #         self.feedback = self.feedback[1:] + bytes([((self.feedback[15] << 1) & 0xff) | (cipher_bit & 1)])
    #     if bit_index != 0:
    #         # If there are remaining bits, pad the byte with zeros and add it to the ciphertext
    #         current_byte <<= (8 - bit_index)
    #         current_byte &= 0xff
    #         ciphertext.append(current_byte)
    #     return bytes(ciphertext)

    # def decrypt(self, ciphertext):
    #     plaintext = bytearray()
    #     bit_index = 0
    #     current_byte = 0
    #     for bit in ciphertext:
    #         # Encrypt the feedback
    #         encrypted_feedback = self.encryptor.encrypt(self.feedback)
    #         # Take the first bit of the encrypted feedback
    #         encrypted_bit = (encrypted_feedback[0] >> 7) & 1
    #         # XOR with the ciphertext bit to get the plaintext bit
    #         plain_bit = bit ^ encrypted_bit
    #         # Store the plaintext bit in the current byte
    #         current_byte = (current_byte << 1) | plain_bit
    #         bit_index += 1
    #         if bit_index == 8:
    #             # We have a full byte, add it to the plaintext
    #             plaintext.append(current_byte)
    #             bit_index = 0
    #             current_byte = 0
    #         # Update the feedback with the ciphertext bit
    #         self.feedback = self.feedback[1:] + bytes([(self.feedback[15] << 1) | (bit & 1)])
    #     if bit_index != 0:
    #         # If there are remaining bits, pad the byte with zeros and add it to the plaintext
    #         current_byte <<= (8 - bit_index)
    #         plaintext.append(current_byte)
    #     return bytes(plaintext)