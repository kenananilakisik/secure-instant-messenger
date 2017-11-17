import pickle
import base64
import time
import random

from ChatUtil import *
from fcryptEncrypt import *


def list(sock, client_server_ip, client_server_port, settings):
    # List 1 format: Kas{"list", N11, T}
    list_msg1 = Message(MessageType.list)
    list_msg1.msg_number = 1

    msg_1_nounce = random.randint(0, 100000000)
    msg_1_ts = int(time.time())

    msg_1_body = pickle.dumps((msg_1_nounce, msg_1_ts))

    list_msg1.iv = generate_nounce()
    msg_1_body_cipher = settings.encryptor.symmetric_encryption(settings.session_key, list_msg1.iv, msg_1_body)

    list_msg1.cipher = msg_1_body_cipher
    msg_1_stream = pickle.dumps(list_msg1)

    sock.sendto(msg_1_stream, (settings.server_ip, settings.server_port))

    #### Msg 2
    received_data, received_addr = sock.recvfrom(4096)
    list_msg_2 = pickle.loads(received_data)
    if list_msg_2.type == MessageType.list and list_msg_2.msg_number == 2:
        list_msg_2_body = pickle.loads(settings.decryptor.symmetric_decryption(settings.session_key,
                                                                  list_msg_2.iv,
                                                                  list_msg_2.cipher))
        list_msg_2_client_list = list_msg_2_body[0]
        list_msg_2_nounce = list_msg_2_body[1]
        list_msg_2_timestamp = list_msg_2_body[2]

        if list_msg_2_nounce == (msg_1_nounce + 1) and (list_msg_2_timestamp - msg_1_ts) < 5:
            print("Online Users:")
            for i in list_msg_2_client_list:
                if i.lower() == settings.username.lower():
                    continue
                print(i)