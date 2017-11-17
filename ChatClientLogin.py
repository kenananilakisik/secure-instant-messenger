import pickle
import getpass
import base64
import hashlib
import random
import os

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes, serialization

from ChatUtil import *
from fcryptEncrypt import *


def login(sock, client_server_ip, client_server_port, settings):
    server_ip = settings.server_ip
    server_port = settings.server_port

    username = raw_input("Username: ")
    while not username:
        username = raw_input("Username: ")

    settings.username = username
    password = getpass.getpass()

    # 1. "login", Apub
    # 1.1. generate RSA key pairs for communication

    # sign in message contains:
    # 1. username
    # 2. client's ip, port
    # 3. client's public key

    # msg 1: send "login", Apub
    signin_msg_1 = Message(MessageType.signin)
    signin_msg_1.msg_number = 1
    signin_msg_1.client_pub_key = settings.rsa_pub_key_str

    # sign msg 1
    msg_1_stream = pickle.dumps(signin_msg_1)
    sock.sendto(msg_1_stream, (server_ip, server_port))
    received_data, received_addr = sock.recvfrom(4096)

    # msg 2: reply from server for msg 1
    signin_msg_2 = pickle.loads(received_data)

    if signin_msg_2.type == MessageType.signin and signin_msg_2.msg_number == 2:
        # sign in message 3: C, [{username, N1, dh_pub_key}s]A

        signin_msg_3 = Message(MessageType.signin)
        signin_msg_3.msg_number = 3

        # generate a private key for DH key exchange
        dh_parameters = dh.generate_parameters(generator=2, key_size=1024, backend=default_backend())
        dh_pri_key = dh_parameters.generate_private_key()
        dh_pub_key = dh_pri_key.public_key()

        # [{username, N1, 2^a mod p}s]A
        n1 = random.randint(0, 100000000)

        settings.server_pub_key = serialization.load_pem_public_key(settings.rsa_pub_key_str, backend=default_backend())

        # msg 3 cipher: username, N1
        signin_msg_3.cipher = settings.encryptor.asymmetric_encryption(pickle.dumps((username, n1)),
                                                                       settings.server_rsa_pub_key)

        signin_msg_3.cookie = signin_msg_2.cookie

        # DH key exchange
        # the server needs g, p, y to generate the shared key
        # p, g -> DHParameterNumbers
        # DHParameterNumbers, y -> peer_public_number -> peer_public_key
        # server_private_key, peer_public_key -> shared_key
        signin_msg_3.dh_g = dh_parameters.parameter_numbers().g
        signin_msg_3.dh_p = dh_parameters.parameter_numbers().p
        signin_msg_3.dh_y = dh_pub_key.public_numbers().y

        msg_3_stream = pickle.dumps(signin_msg_3.cookie +
                                    username +
                                    str(n1) +
                                    str(signin_msg_3.dh_g) +
                                    str(signin_msg_3.dh_p) +
                                    str(signin_msg_3.dh_y))

        msg_3_signature = settings.encryptor.sign(settings.rsa_pri_key, msg_3_stream)

        signin_msg_3.signature = msg_3_signature

        sock.sendto(pickle.dumps(signin_msg_3), (server_ip, server_port))

        ###############################################################################################
        # Client receive msg 4, calculate DH session key
        received_data, received_addr = sock.recvfrom(4096)
        signin_msg_4 = pickle.loads(received_data)

        if signin_msg_4.type == MessageType.signin and signin_msg_4.msg_number == 4:
            # sign in message 4: [dh_pub_key, Kas{N1+1, N2}, hash(2^as %p, 2^SW % p)]s
            ###############################################################################################
            # TODO : verify message 4
            verification_result = settings.decryptor.verify_signature(settings.server_rsa_pub_key,
                                                                      signin_msg_4.signature,
                                                                      bin(signin_msg_4.dh_y))
            if not verification_result:
                raise("Message 4 signature not match")
                return None
            ###############################################################################################

            c_pn = dh.DHParameterNumbers(dh_parameters.parameter_numbers().p, dh_parameters.parameter_numbers().g)
            c_peer_public_numbers = dh.DHPublicNumbers(signin_msg_4.dh_y, c_pn)
            c_peer_public_key = c_peer_public_numbers.public_key(default_backend())
            c_shared_key = dh_pri_key.exchange(c_peer_public_key)

            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(c_shared_key)
            digest_c_shared_key = digest.finalize()

            if not digest_c_shared_key == signin_msg_4.hash:
                print("Sign in Message 4, hashes does not match!")
                return None

            settings.session_key = digest_c_shared_key

            nounces_clear = pickle.loads(settings.decryptor.symmetric_decryption(settings.session_key,
                                                                    signin_msg_4.iv,
                                                                    signin_msg_4.cipher))
            if nounces_clear[0] != n1+1:
                print("Incorrect nounce")
                raise("Incorrect nounce in login message 4")
                return

            n2 = nounces_clear[1]
            ###############################################################################################
            # sign in message 5: [Kas{N2+1}, hash(2^as % p, 2^sw % p)]A
            signin_msg_5 = Message(MessageType.signin)
            signin_msg_5.msg_number = 5
            signin_msg_5.iv = os.urandom(16)

            pwd_hash = hashlib.sha256(password).hexdigest()

            msg_clear = pickle.dumps((n2, pwd_hash, digest_c_shared_key, client_server_port))
            msg_cipher = settings.encryptor.symmetric_encryption(digest_c_shared_key,
                                                                 signin_msg_5.iv,
                                                                 msg_clear)

            signin_msg_5.cipher = msg_cipher
            sock.sendto(pickle.dumps(signin_msg_5), (server_ip, server_port))
            ###############################################################################################
            received_data, received_addr = sock.recvfrom(1024)
            signin_msg_6 = pickle.loads(received_data)

            if signin_msg_6 == True:
                print("{}, you have logged in".format(username))
                return settings.session_key
            else:
                print("Log in FAILED!")
        else:
            print("Log in FAILED!")
    else:
        print("Log in FAILED!")
