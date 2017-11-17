import os
import pickle
import SocketServer
import base64
import time
import random
import hashlib
import math

from fcryptUtilities import *
from fcryptEncrypt import *
from fcryptDecrypt import *
from sets import Set

from ChatUtil import *
from ChatUserTable import *

from cryptography.hazmat.primitives import serialization, hashes, hmac
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization


# ChatServerHandler is a request handler for handle UDP requests from Chat lients
class ChatServerHandler(SocketServer.BaseRequestHandler):
    """
    Chat Server handler handles 3 types of requests
    1. SIGN-IN
    2. LIST
    3. SEND MESSAGE
    """

    # handle : None -> None
    # Effect: handles the incoming UDP packets, parse the packet and reply the request with corresponding answer
    def handle(self):

        # DATA is always a tuple, 1st element is the command, 2nd element is the list contains all the messages
        # print("secret: {}".format(base64.b64encode(self.server.secret)))
        data = pickle.loads(self.request[0])

        sock = self.request[1]
        print("{}:{} wrote: {}".format(self.client_address[0], self.client_address[1], data))
        print('-------------------------------------------------')

        # sender_logged_in = False
        # sender_item = self.server.user_table.

        if data.type == MessageType.signout:
            decryptor = HaoDecryptor(None, None)
            # session_key = self.server.user_table.get_client_session_key(data.username)

            session_key = self.server.user_table.get_client_by_name(data.username).session_key

            if not session_key:
                return

            body_string = decryptor.symmetric_decryption(session_key, data.iv, data.cipher)
            body = pickle.loads(body_string)
            ts = int(body)

            if int(time.time()) - ts < 10:
                print("signing out: " + data.username)
                signout_client = self.server.user_table.get_client_by_name(data.username)
                signout_client.is_online = False
                signout_client.session_key = None

        elif data.type == MessageType.signin:
            online_users = self.server.user_table.get_online_clients_name()

            if data.username.lower() in online_users:
                # user is already online
                # response.signed_in_flag = False
                err_msg = Message(MessageType.error)
                err_msg.body = "Username is already signed in from another place."
                sock.sendto(pickle.dumps(err_msg), self.client_address)
                return

            if data.msg_number == 1:
                self.server.login_table[self.client_address[0] + ':' + str(self.client_address[1])] = \
                    data.client_pub_key

                client_pub_key = data.client_pub_key

                signin_msg_2 = Message(MessageType.signin)
                signin_msg_2.msg_number = 2
                signin_msg_2.cookie = generate_stateless_cookie(self.server.secret,
                                                                self.client_address[0],
                                                                str(self.client_address[1]))
                sock.sendto(pickle.dumps(signin_msg_2), self.client_address)

            elif data.msg_number == 3:
                # sign in message 3: C, [{username, N1, dh_pub_key}s]A
                cookie = generate_stateless_cookie(self.server.secret,
                                                   self.client_address[0],
                                                   str(self.client_address[1]))

                if data.cookie == cookie:
                    msg_3_body = pickle.loads(self.server.decryptor.asymmetric_decrypt(self.server.settings.rsa_pri_key,
                                                                                       data.cipher))

                    username = msg_3_body[0]
                    n1 = msg_3_body[1]

                    client_item = self.server.user_table.get_client_by_name(username)


                    # verify the signature
                    client_pub_key_pem = self.server.login_table[
                        self.client_address[0] + ':' + str(self.client_address[1])]

                    if (not client_item) or (not client_pub_key_pem):
                        return

                    client_item.pub_key_pem = client_pub_key_pem

                    client_pub_key = serialization.load_pem_public_key(client_pub_key_pem, backend=default_backend())

                    msg_3_stream = pickle.dumps(data.cookie +
                                                username +
                                                str(n1) +
                                                str(data.dh_g) +
                                                str(data.dh_p) +
                                                str(data.dh_y))

                    verification_res = self.server.decryptor.verify_signature(client_pub_key,
                                                                              data.signature,
                                                                              msg_3_stream)

                    if not verification_res:
                        return

                    # generate DH key
                    s_pn = dh.DHParameterNumbers(data.dh_p, data.dh_g)
                    s_parameters = s_pn.parameters(default_backend())
                    s_peer_public_numbers = dh.DHPublicNumbers(data.dh_y, s_pn)
                    s_peer_public_key = s_peer_public_numbers.public_key(default_backend())

                    s_private_key = s_parameters.generate_private_key()
                    s_public_key = s_private_key.public_key()
                    s_shared_key = s_private_key.exchange(s_peer_public_key)

                    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                    digest.update(s_shared_key)
                    digest_s_shared_key = digest.finalize()

                    # add shared key to the self.server.user_table
                    client_item.session_key = digest_s_shared_key
                    client_item.ip = self.client_address[0]
                    client_item.port_send = self.client_address[1]

                    client_item.session_key = digest_s_shared_key

                    n2 = generate_nounce()
                    client_item.last_nounce = n2

                    ###############################################################################################
                    # sign in message 4: [dh_pub_key, Kas{N1+1, N2}, hash(2^as %p, 2^SW % p)]s
                    signin_msg_4 = Message(MessageType.signin)
                    signin_msg_4.msg_number = 4

                    # 2^s % p
                    signin_msg_4.dh_y = s_public_key.public_numbers().y

                    # Kas{N1+1, N2}
                    msg_clear = (n1 + 1, n2)
                    signin_msg_4.iv = os.urandom(16)
                    signin_msg_4.cipher = self.server.encryptor.symmetric_encryption(client_item.session_key,
                                                                                     signin_msg_4.iv,
                                                                                     pickle.dumps(msg_clear))

                    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                    digest.update(s_shared_key)
                    # digest.update(client_item.password_hash)
                    signin_msg_4.hash = digest.finalize()

                    ###############################################################################################
                    # Signing message 4
                    msg4_signature = self.server.encryptor.sign(self.server.settings.rsa_pri_key,
                                                                bin(signin_msg_4.dh_y))
                    signin_msg_4.signature = msg4_signature
                    ###############################################################################################

                    sock.sendto(pickle.dumps(signin_msg_4), self.client_address)
                else:
                    print("wrong cookie")
                    return

            elif data.msg_number == 5:
                #############################################################################################
                client_item = self.server.user_table.get_client_by_ip_send_port(self.client_address[0],
                                                                                self.client_address[1])
                username = client_item.username
                saved_password = client_item.password_hash

                # decrypt cipher
                msg_clear = pickle.loads(self.server.decryptor.symmetric_decryption(client_item.session_key,
                                                                                    data.iv,
                                                                                    data.cipher))
                n21 = msg_clear[0]
                pwd_hash = msg_clear[1]
                session_key_hash = msg_clear[2]
                listening_port = msg_clear[3]

                if pwd_hash == saved_password and \
                                session_key_hash == client_item.session_key and \
                                n21 == client_item.last_nounce:
                    # add client to the online table
                    client_item.port_listen = listening_port
                    client_item.is_online = True

                    sock.sendto(pickle.dumps(True), self.client_address)
                else:
                    sock.sendto(pickle.dumps(False), self.client_address)

        elif data.type == MessageType.list:
            if data.msg_number == 1:
                client_item = self.server.user_table.get_client_by_ip_send_port(self.client_address[0],
                                                                                self.client_address[1])
                if client_item:
                    session_key = client_item.session_key
                    msg_1_body = pickle.loads(
                        self.server.decryptor.symmetric_decryption(session_key, data.iv, data.cipher))
                    msg_1_nounce = msg_1_body[0]
                    msg_1_time = msg_1_body[1]

                    list_msg_2 = Message(MessageType.list)
                    list_msg_2.msg_number = 2

                    online_users = self.server.user_table.get_online_clients_name()
                    print(online_users)
                    list_msg_2_body = (online_users, int(msg_1_nounce) + 1, int(time.time()))

                    list_msg_2.iv = os.urandom(16)
                    list_msg_2.cipher = self.server.encryptor.symmetric_encryption(session_key, list_msg_2.iv,
                                                                                   pickle.dumps(list_msg_2_body))
                    list_msg_2_stream = pickle.dumps(list_msg_2)
                    sock.sendto(list_msg_2_stream, self.client_address)

        elif data.type == MessageType.chat_request:
            enc = self.server.encryptor
            dec = self.server.decryptor

            # ----------------------------------------------------------P2P MESSAGE 1(RECEIVE)
            if data.msg_number == 1:
                sender_client = self.server.user_table.get_client_by_ip_send_port(self.client_address[0],
                                                                                  self.client_address[1])

                keyAS = sender_client.session_key
                message = pickle.loads(dec.symmetric_decryption(keyAS, data.iv, data.cipher))

                n1 = message[0]
                talk_to_name = message[1]
                talk_to_client = self.server.user_table.get_client_by_name(talk_to_name)

                if sender_client and talk_to_client:
                    # ------------------------------------------------------P2P MESSAGE 2(SEND)
                    if talk_to_client.is_online:
                        p2p_msg2 = Message(MessageType.chat_request)
                        p2p_msg2.msg_number = 2
                        p2p_msg2.iv = os.urandom(16)
                        p2p_msg2.iv_for_bob = os.urandom(16)

                        ticket_to_bob = (sender_client.username, sender_client.pub_key_pem,
                                         sender_client.ip, sender_client.port_listen)

                        bob_session_key = self.server.user_table.get_client_by_name(talk_to_name).session_key

                        ticket_to_bob_cipher = enc.symmetric_encryption(bob_session_key,
                                                                        p2p_msg2.iv_for_bob,
                                                                        pickle.dumps(ticket_to_bob))

                        msg_2_body = (n1, talk_to_name, talk_to_client.ip, talk_to_client.port_listen,
                                      talk_to_client.pub_key_pem, ticket_to_bob_cipher)

                        p2p_msg2.cipher = enc.symmetric_encryption(sender_client.session_key,
                                                                   p2p_msg2.iv,
                                                                   pickle.dumps(msg_2_body))

                        sock.sendto(pickle.dumps(p2p_msg2), self.client_address)

                    else:
                        print(talk_to_client.username + " is offline")
