import base64, os
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import rsa, padding
from fcryptUtilities import *
from cryptography import exceptions

# python fcrypt.py -e destination_public_key_filename sender_private_key_filename
# input_plaintext_file ciphertext_file

# HaoEncryptor is an object which use hybrid encryption methods to encrypt and sign the given file
class HaoEncryptor(object):
    """An encryptor offers methods to encrypt and sign a file"""
    def __init__(self, dest_pub_key, sender_pri_key, in_text=None, out_cipher=None):
        super(HaoEncryptor, self).__init__()
        self.dest_pub_key = dest_pub_key
        self.sender_pri_key = sender_pri_key
        self.in_text = in_text
        self.out_cipher = out_cipher
        # self.content = self.in_text.read()
        # default encoding algorithm
        self.hash_algorithm = hashes.SHA512()
        # AES 256 bit key
        self.aes_key = os.urandom(32)
        # block size is 128 bit
        self.iv = os.urandom(16)

    # Contract: encrypt : _RSAPublicKey _RSAPrivateKey file file -> None
    # Purpose: Encrypt and sign the give file and write the cipher to the output file
    # Effects: Write cipher text to the output file
    def encrypt(self, dest_pub_key=None, sender_pri_key=None, in_text=None, out_cipher=None):
        if not dest_pub_key:
            dest_pub_key = self.dest_pub_key

        if not sender_pri_key:
            sender_pri_key = self.sender_pri_key

        if not in_text:
            in_text = self.in_text

        if not out_cipher:
            out_cipher = self.out_cipher

        if dest_pub_key.key_size != sender_pri_key.key_size:
            raise Exception("The two key sizes are different!")

        # 1. using RSA to encrypt aes key
        print("encrypting aes key...")
        output_blob = self.asymmetric_encryption(self.aes_key, dest_pub_key)

        # 2. using RSA to encrypt IV
        print("encrypting iv...")
        output_blob += self.asymmetric_encryption(self.iv, dest_pub_key)

        # 3. generate signature
        # Use Encrypt-then-MAC mode. Add signature to the end of message body.
        print("generating signature...")
        signature = self.sign(sender_pri_key, self.content)

        # 4. write message body
        print("encrypting msg body...")
        encrypted_msg = self.symmetric_encryption(self.aes_key, self.iv, self.content+signature)
        output_blob += encrypted_msg

        # 5. encode the cipher into 64-bit encoding for transfer
        out_cipher.write(base64.b64encode(output_blob))

    # Contract: asymmetric_encryption : str public_key_serialization -> String
    # Purpose: using RSA to encrypt aes key, IV
    # Return: Cipher message that is encrypted with given key using RSA
    def asymmetric_encryption(self, msg, encryption_key=None):
        if not encryption_key:
            encryption_key = self.dest_pub_key

        encrypted_msg = encryption_key.encrypt(
            msg,  # encryption message is the aes_key or iv in our case
            padding.OAEP(
                mgf=padding.MGF1(algorithm=self.hash_algorithm),
                algorithm=self.hash_algorithm,
                label=None))

        return encrypted_msg

    # Contract: symmetric_encryption : str str str -> str
    # Purpose: Using CTR mode to encrypt messages
    # Return: Cipher message that is encrypted with given key using AES
    def symmetric_encryption(self, encryption_key=None, iv=None, content=None):
        if not encryption_key:
            encryption_key = self.aes_key
        if not iv:
            iv = self.iv
        if not content:
            content = self.content

        msg_cipher = Cipher(algorithms.AES(encryption_key), modes.CTR(iv), backend=default_backend())
        msg_encryptor = msg_cipher.encryptor()

        encrypted_msg = msg_encryptor.update(content) + msg_encryptor.finalize()
        return encrypted_msg

    def symmetric_decryption(self, encryption_key=None, iv=None, enc_msg=None):
        cipher = Cipher(algorithms.AES(encryption_key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        msg = decryptor.update(enc_msg) + decryptor.finalize()
        return msg

    # Contract: sign : private_key_serialization str -> str
    # Purpose: Using RSA to sign the message contents
    # Return: A signature string that is generated based on the given key and contents
    def sign(self, signing_key=None, content=None):
        if not signing_key:
            signing_key = self.sender_pri_key
        if not content:
            content = self.content

        signer = signing_key.signer(
            padding.PSS(
                mgf=padding.MGF1(self.hash_algorithm),
                salt_length=padding.PSS.MAX_LENGTH
            ),
            self.hash_algorithm
        )
        signer.update(content)
        signature = signer.finalize()

        return signature
