import pickle
import base64
import time
import random

from ChatUtil import *
from fcryptEncrypt import *

# Old send
# 1. ask server for targeting client's ip:port
# 2. send message to targeting client's ip:port
# sock.sendto(pickle.dumps(("SEND", [cmd_splited[1]])), (settings.server_ip, settings.server_port))
#
# try:
#     received_data, received_addr = sock.recvfrom(4096)
#     received_msg = pickle.loads(received_data)
#     status_code, data = received_msg
#
#     if status_code:
#         target_ip, target_port = data[0], data[1]
#         send_msg_body = cmd[len(cmd_splited[0]) + len(cmd_splited[1]) + 2:]
#         sock.sendto(pickle.dumps((settings.username, [send_msg_body])), (target_ip, int(target_port)))
#     else:
#         print(data)
# except Exception as errMsg:
#     print("Sending message failed: {}".format(errMsg))


def p2p_send(sock, client_server_ip, client_server_port, settings):
    pass
    # Kab {M1, T, N5}, HMAC(Kab, M1)
    # session_key_AB =