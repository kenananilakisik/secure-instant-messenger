import base64
import cryptography # only for the library exception
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
from cryptography.hazmat.primitives.asymmetric import padding

# python fcrypt.py -d destination_private_key_filename sender_public_key_filename
# ciphertext_file output_plaintext_file


# HatDecryptor is an object that decrypts a piece of cipher using RSA and AES encryption and verify the cipher with
# its own signature
class HaoDecryptor(object):
    """docstring for HaoDecryptor"""
    def __init__(self, dest_pri_key, sender_pub_key, in_cipher=None, out_text=None):
        super(HaoDecryptor, self).__init__()
        self.dest_pri_key = dest_pri_key
        self.sender_pub_key = sender_pub_key
        self.in_cipher = in_cipher
        self.out_text = out_text
        if in_cipher:
            self.content = self.in_cipher.read()
            self.content64 = base64.b64decode(self.content)
        self.hash_algorithm = hashes.SHA512()

        if sender_pub_key:
            self.key_size = sender_pub_key.key_size / 8

    # Contract: decrypt : _RSAPrivateKey _RSAPublicKey file file -> None
    # Purpose: Decrypt and verify the give file and write the plain text to the output file
    # Effects: Write deciphered text to the output file
    def decrypt(self, dest_pri_key=None, sender_pub_key=None, in_cipher=None, out_text=None):
        if not dest_pri_key:
            dest_pri_key = self.dest_pri_key

        if not sender_pub_key:
            sender_pub_key = self.sender_pub_key

        if not in_cipher:
            in_cipher = self.content64

        if not out_text:
            out_text = self.out_text

        if dest_pri_key.key_size != sender_pub_key.key_size:
            raise Exception("The two key sizes are different!")

        ciphered_aes_key = in_cipher[:self.key_size]
        ciphered_iv = in_cipher[self.key_size:self.key_size*2]
        ciphered_content = in_cipher[self.key_size*2:]  # contains both message content and signature

        # 1. read and decrypt symmetric key
        print("decrypting aes key...")
        aes_key = self.asymmetric_decrypt(dest_pri_key, ciphered_aes_key)

        # 2. get the IV from cypher
        print("decrypting iv...")
        iv = self.asymmetric_decrypt(dest_pri_key, ciphered_iv)

        # 3. decrypt body using aes key
        print("decrypting body...")
        aes_cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv), backend=default_backend())
        msg_decryptor = aes_cipher.decryptor()

        # aes msg contains the text body and the sign of the text
        aes_msg = msg_decryptor.update(ciphered_content) + msg_decryptor.finalize()
        text_body = aes_msg[:0-self.key_size]
        signature = aes_msg[0-self.key_size:]

        # 4. verify the signature
        print("verifying signature...")
        self.verify_signature(sender_pub_key, signature, text_body)

        # 5. write the deciphered text body
        out_text.write(text_body)

    # Contract: asymmetric_decrypt : _RSAPrivateKey str -> str
    # Purpose: using RSA to decrypt aes key, IV
    # Return: Text message that is decrypted with given key using RSA
    def asymmetric_decrypt(self, decryption_key=None, cipher=None):
        if not cipher:
            cipher = self.content64[:self.dest_pri_key.key_size]
        if not decryption_key:
            decryption_key = self.dest_pri_key

        decrypted_msg = decryption_key.decrypt(cipher,
                                               padding.OAEP(mgf=padding.MGF1(algorithm=self.hash_algorithm),
                                                            algorithm=self.hash_algorithm,
                                                            label=None))
        return decrypted_msg

    def symmetric_decryption(self, aes_key, iv, content=None):
        cipher = Cipher(algorithms.AES(aes_key), modes.CTR(iv), backend=default_backend())
        decryptor = cipher.decryptor()
        msg = decryptor.update(content) + decryptor.finalize()
        return msg

    # Contract: verify_signature : _RSAPublicKey str str -> None
    # Purpose: Verify the signature with the sender's public key and given content
    # Effects: Notify the caller if the verification fails
    def verify_signature(self, verify_key, signature, content):
        verifier = verify_key.verifier(signature,
                                       padding.PSS(mgf=padding.MGF1(self.hash_algorithm),
                                                   salt_length=padding.PSS.MAX_LENGTH),
                                       self.hash_algorithm)
        verifier.update(content)

        try:
            verifier.verify()
            return True
        except cryptography.exceptions.InvalidSignature:
            return False

