import pickle
import base64
import time
import random

from ChatUtil import *
from fcryptEncrypt import *

def signout(sock, client_server_ip, client_server_port, settings, USER_TABLE):

    n7 = generate_nounce()
    iv = os.urandom(16)
    encryptor = HaoEncryptor(None,None)
    body = int(time.time())
    body_string = pickle.dumps(body)
    body_cipher = encryptor.symmetric_encryption(settings.session_key,iv,body_string)

    signout_msg = Message(MessageType.signout)
    signout_msg.msg_number = 1
    signout_msg.cipher = body_cipher
    signout_msg.iv = iv
    signout_msg.username = settings.username

    # send server signout
    sock.sendto(pickle.dumps(signout_msg), (settings.server_ip, int(settings.server_port)))
