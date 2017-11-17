from enum import Enum
import socket
import os

from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.backends import default_backend

# send messages format:
# (SENDER_NAME, MESSAGE)

class ServerSettings(object):
    def __init__(self):
        self.rsa_pub_key = None
        self.rsa_pri_key = None
        self.ip = "10.0.0.47"
        self.port = 62659


class ClientSettings(object):
    def __init__(self):
        self.rsa_pub_key = None
        self.rsa_pri_key = None
        self.server_rsa_pub_key = None
        self.server_ip = "10.0.0.47"
        self.server_port = 62659
        self.session_key = ""
        self.username = ''


class MessageType(Enum):
    signin = 0
    signout = 1
    list = 2
    send = 3
    chat_request = 4
    dh = 5
    error = 6


class Message(object):
    """docstring for ChatMassage"""

    def __init__(self, msgType=MessageType.send):
        super(Message, self).__init__()
        self.username = ''
        self.type = msgType
        self.msg_number = -1
        self.cookie = None
        self.client_pub_key = ''
        self.talk_to = ''
        self.owner = ''
        self.n1 = ''
        self.n2 = ''
        self.n3 = ''

class AsyncKeyPair(object):
    """docstring for AsyncKeyPair"""

    def __init__(self, keyLen=1024):
        # super(AsyncKeyPair, self).__init__()
        self.keyLen = keyLen
        self.key_gen()

    def key_gen(self):
        self.key = rsa.generate_private_key(
            public_exponent=65537,
            key_size=self.keyLen,
            backend=default_backend()
        )

        # self.private_key_str = self.key.private_bytes(
        #     serialization.Encoding.PEM,
        #     serialization.PrivateFormat.PKCS8,
        #     serialization.NoEncryption())

        # self.public_key_str = self.key.public_key().public_bytes(
        #     serialization.Encoding.OpenSSH,
        #     serialization.PublicFormat.OpenSSH
        # )

        self.private_key_str = self.key.private_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PrivateFormat.TraditionalOpenSSL,
            encryption_algorithm=serialization.NoEncryption()
        )

        self.public_key_str = self.key.public_key().public_bytes(
            encoding=serialization.Encoding.PEM,
            format=serialization.PublicFormat.SubjectPublicKeyInfo
            # format = serialization.PrivateFormat.TraditionalOpenSSL,
            # encryption_algorithm=serialization.NoEncryption()
        )

    def get_pub_key(self):
        return self.key.public_key()

    def get_pri_key(self):
        return self.key


def hash_string_to_int(val):
    pass

def generate_nounce():
    return os.urandom(16)


def generate_stateless_cookie(secret, ip, port=''):
    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
    digest.update(ip)
    digest.update(port)
    digest.update(secret)

    return digest.finalize()


# CONTRACT: -> Tuple
# GIVEN: None
# RETURNS: a tuple with 2 strings, 1st is the ip address of the local machine,
#          2nd is an open port which the socket can use
# EFFECTS: To find out the IP address on the running machine and an open port number
def get_src_address():
    # create a dummy socket to find out our ip and open port of this machine
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.connect(('google.com', 80))
    res = sock.getsockname()
    # close it for raw sockets to use later
    sock.close()
    return res


if __name__ == '__main__':
    # print(get_src_address())
    rsa_key_pair = AsyncKeyPair()
    print(rsa_key_pair.private_key_str)
    print(rsa_key_pair.public_key_str)
