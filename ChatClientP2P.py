import sys
import SocketServer
import argparse
import threading
import pickle
import getpass
import base64
import os
import random

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
import os

from ChatUserTable import *
from ChatUtil import *

from fcryptEncrypt import *
from fcryptDecrypt import *

def p2p(sock, client_server_ip, client_server_port, settings, cmd_splited, USER_TABLE):
    server_ip = settings.server_ip
    server_port = settings.server_port

    enc = HaoEncryptor(None, None)
    dec = HaoDecryptor(None, None)

    # in clear
    msg1 = Message(MessageType.chat_request)
    msg1.msg_number = 1
    msg1.iv = os.urandom(16)

    # in cipher
    n1 = generate_nounce()
    send_to_client_name = cmd_splited[1]

    msg1_body = pickle.dumps((n1, send_to_client_name))
    msg1.cipher = enc.symmetric_encryption(settings.session_key, msg1.iv, msg1_body)

    sock.sendto(pickle.dumps(msg1),(server_ip, server_port))

    #---------------------------------------------------------MESSAGE 2(RECEIVE)
    received_data, received_addr = sock.recvfrom(8192)
    p2p_msg_2 = pickle.loads(received_data)

    if p2p_msg_2.type == MessageType.chat_request and p2p_msg_2.msg_number == 2:

        msg2_body_stream = dec.symmetric_decryption(settings.session_key,
                                                    p2p_msg_2.iv,
                                                    p2p_msg_2.cipher)
        msg2_body = pickle.loads(msg2_body_stream)

        n1s = msg2_body[0]
        talk_to = msg2_body[1]
        talk_to_ip = msg2_body[2]
        talk_to_port = msg2_body[3]
        talk_to_pub_key_pem = msg2_body[4]

        # ticket to Bob
        ticket_to_bob = msg2_body[5]

        # save the ip and port
        newClient = ClientItem()
        newClient.username = talk_to
        newClient.ip = talk_to_ip
        newClient.port_listen = talk_to_port
        newClient.pub_key_pem = talk_to_pub_key_pem

        #------------------------------------------------------------------------MESSAGE 3(SEND)
        if n1 == n1s:
            # msg 3: g^a % p, N4, ticket to bob = {"Alice", Apub, IP, port}
            msg3 = Message(MessageType.chat_request)
            msg3.msg_number = 3
            msg3.iv_for_bob = p2p_msg_2.iv_for_bob


            dh_parameters = dh.generate_parameters(generator=2, key_size=512, backend=default_backend())
            dh_pri_key = dh_parameters.generate_private_key()
            settings.dh_pri_key = dh_pri_key

            dh_pub_key = dh_pri_key.public_key()

            msg3.dh_g = dh_parameters.parameter_numbers().g
            msg3.dh_p = dh_parameters.parameter_numbers().p
            msg3.dh_y = dh_pub_key.public_numbers().y

            dh_params = (msg3.dh_g,msg3.dh_p,msg3.dh_y)
            dh_params_string = pickle.dumps(dh_params)

            ##########################################################################################################
            # Signing DH for PFS
            msg3_signature = settings.encryptor.sign(settings.rsa_pri_key, dh_params_string)
            msg3.signature = msg3_signature
            ##########################################################################################################

            n4 = generate_nounce()

            newClient.last_nounce = n4

            # nouce, ticket to bob
            msg3.n4 = n4
            msg3.ticket = ticket_to_bob

            # # TODO: actually encrypt it
            sock.sendto(pickle.dumps(msg3), (talk_to_ip, int(talk_to_port)))

            received_data, received_addr = sock.recvfrom(4096)
            p2p_msg_4 = pickle.loads(received_data)

            if p2p_msg_4.type == MessageType.chat_request and p2p_msg_4.msg_number == 4:#----------------------------------Message 4 Receive
                ########################################################################################################
                # Verify DH for PFS
                msg4_dh_params = (p2p_msg_4.dh_g, p2p_msg_4.dh_p, p2p_msg_4.dh_y)
                msg4_dh_params_string = pickle.dumps(msg4_dh_params)
                sign_pub_key = serialization.load_pem_public_key(talk_to_pub_key_pem, backend=default_backend())
                verification_result = settings.decryptor.verify_signature(sign_pub_key, p2p_msg_4.signature,
                                                                          msg4_dh_params_string)
                ########################################################################################################
                if verification_result:
                    c_pn = dh.DHParameterNumbers(p2p_msg_4.dh_p, p2p_msg_4.dh_g)
                    c_parameters = c_pn.parameters(default_backend())
                    c_peer_public_numbers = dh.DHPublicNumbers(p2p_msg_4.dh_y, c_pn)
                    c_peer_public_key = c_peer_public_numbers.public_key(default_backend())

                    session_key_ab = settings.dh_pri_key.exchange(c_peer_public_key)

                    digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
                    digest.update(session_key_ab)
                    digest_c_session_key = digest.finalize()

                    newClient.session_key = digest_c_session_key

                    #Alice Decryptes Nounces n4 and n5
                    decryptor = HaoDecryptor(None,None)
                    nounce_string = decryptor.symmetric_decryption(digest_c_session_key,p2p_msg_4.iv,p2p_msg_4.nounce_cipher)
                    nounces = pickle.loads(nounce_string)
                    n4_check = nounces[0]
                    n5 = nounces[1]

                    # print ("this is what I got from BOB as my N4")
                    # print n4_check

                    # Alice authenticates Bob
                    if newClient.last_nounce == n4_check:#-------------------------------------------------------------------Message 5 Send
                        iv = os.urandom(16)
                        encryptor = HaoEncryptor(None, None)
                        n5_cipher = encryptor.symmetric_encryption(digest_c_session_key,iv,n5)

                        p2p_msg_5 = Message(MessageType.chat_request)
                        p2p_msg_5.msg_number = 5
                        p2p_msg_5.cipher = n5_cipher
                        p2p_msg_5.iv = iv

                        sock.sendto(pickle.dumps(p2p_msg_5), received_addr)

                    else:
                        print "Client sent wrong response to the challenge"

                    return newClient
                else:
                    print "Signature wrong closing connection!"