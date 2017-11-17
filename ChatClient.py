import sys
import SocketServer
import argparse
import threading
import pickle
import base64
import socket
import threading, Queue

from ChatUtil import *
from ChatClientLogin import *
from ChatClientP2P import *
from ChatClientSend import *
from ChatClientList import *
from ChatUserTable import *
from ChatClientSignout import  *

from fcryptEncrypt import *
from fcryptDecrypt import *
from fcryptUtilities import *

from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives.asymmetric import dh
from cryptography.hazmat.primitives import hashes, hmac

PRIVATE_KEY = None
USER_TABLE = UserTable()

def run_udp_server(ip, port, settings):
    # Set up a UDP server
    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    listen_addr = (ip, port)
    sock.bind(listen_addr)

    while True:
        global USER_TABLE

        data, addr = sock.recvfrom(4096)
        data = pickle.loads(data)

        if data.type == MessageType.chat_request and data.msg_number == 3:

            # Gets DH contribution from other client, computes session key and sends own contribution
            c_pn = dh.DHParameterNumbers(data.dh_p, data.dh_g)
            c_parameters = c_pn.parameters(default_backend())
            c_peer_public_numbers = dh.DHPublicNumbers(data.dh_y, c_pn)
            c_peer_public_key = c_peer_public_numbers.public_key(default_backend())

            # TODO: saving the DH pri key for later
            c_private_key = c_parameters.generate_private_key()

            c_public_key = c_private_key.public_key() # for the other side
            c_session_key = c_private_key.exchange(c_peer_public_key)

            digest = hashes.Hash(hashes.SHA256(), backend=default_backend())
            digest.update(c_session_key)
            digest_c_session_key = digest.finalize()

            ticket_cipher = data.ticket
            decryptor = HaoDecryptor(None,None)
            ticket_string = decryptor.symmetric_decryption(settings.session_key, data.iv_for_bob, ticket_cipher)
            ticket = pickle.loads(ticket_string)

            dh_params = (data.dh_g, data.dh_p, data.dh_y)
            dh_params_string = pickle.dumps(dh_params)

            ##########################################################################################################
            # Load Pub Key
            sign_pub_key = serialization.load_pem_public_key(ticket[1], backend=default_backend())
            ##########################################################################################################
            # Verify DH for PFS
            verification_result = settings.decryptor.verify_signature(sign_pub_key,data.signature,dh_params_string)
            if verification_result:
                # send msg 4
                msg_4 = Message(MessageType.chat_request)
                msg_4.msg_number = 4
                msg_4.dh_g = data.dh_g
                msg_4.dh_p = data.dh_p
                msg_4.dh_y = c_public_key.public_numbers().y

                n4 = data.n4
                n5 = generate_nounce()

                newClient = ClientItem()
                newClient.username = ticket[0]
                newClient.pub_key_pem = ticket[1]
                newClient.ip = ticket[2]
                newClient.port_listen = ticket[3]
                newClient.session_key = digest_c_session_key
                newClient.last_nounce = n5

                USER_TABLE.add_client(newClient)

                # Encrypt n4 and n5 and send it to Alice
                iv = os.urandom(16)
                nounces = (n4,n5)
                nounce_string = pickle.dumps(nounces)
                encryptor = HaoEncryptor(None,None)
                nounce_string_cipher = encryptor.symmetric_encryption(digest_c_session_key,iv,nounce_string)

                msg_4.nounce_cipher = nounce_string_cipher
                msg_4.iv = iv

                dh_params4 = (msg_4.dh_g, msg_4.dh_p, msg_4.dh_y)
                dh_params4_string = pickle.dumps(dh_params4)
                ##########################################################################################################
                # Signing DH for PFS
                msg4_signature = settings.encryptor.sign(settings.rsa_pri_key, dh_params4_string)
                msg_4.signature = msg4_signature
                ##########################################################################################################

                sock.sendto(pickle.dumps(msg_4), addr)
            else:
                print "Signature wrong closing connection!"

        #Bob Authenticates Alice by checking n5
        # For some reason I was able to use n5 from the last step(message3) IDK if this was meant to happen but it works
        elif data.type == MessageType.chat_request and data.msg_number == 5:
            decryptor = HaoDecryptor(None,None)
            n5_check = decryptor.symmetric_decryption(digest_c_session_key,data.iv,data.cipher)

            if n5_check != n5:
                print "Response to the challenge is wrong!"
                return
        elif data.type == MessageType.send:
            sender_item = USER_TABLE.get_client_by_name(data.sender_name)

            decryptor = HaoDecryptor(None,None)

            msg = decryptor.symmetric_decryption(sender_item.session_key, data.iv, data.cipher)

            h = hmac.HMAC(sender_item.session_key, hashes.SHA256(), backend=default_backend())
            h.update(data.cipher)
            hmac_result = h.finalize()

            if hmac_result == data.hmac_result:
                print(data.sender_name + " said: " + msg)
            else:
                print("HMAC does not match!")

            sys.stdout.write("+> ")
            sys.stdout.flush()

########################################################################################################################
# The sender thread

# run_client : String String -> None
# Given: the IP and port number for the Chat Server
# Effect: Keep processing the commands from user input, send requests to the server or other clients
def run_client(client_server_ip, client_server_port, settings):
    global USER_TABLE

    print("To exit: press 'q', 'QUIT' or 'Ctrl-D'.")

    print("Client running on {}:{}".format(client_server_ip, client_server_port))
    client_rsa_key = AsyncKeyPair()

    encryptor = HaoEncryptor(settings.server_rsa_pub_key, client_rsa_key.get_pri_key())
    decryptor = HaoDecryptor(client_rsa_key.get_pri_key(), settings.server_rsa_pub_key)

    settings.encryptor = encryptor
    settings.decryptor = decryptor

    settings.rsa_pub_key = client_rsa_key.get_pub_key()
    settings.rsa_pub_key_str = client_rsa_key.public_key_str

    settings.rsa_pri_key = client_rsa_key.get_pri_key()
    settings.rsa_pri_key_str = client_rsa_key.private_key_str
    # settings.rsa_key = client_rsa_key.key

    # the table stores all the current conversations' client IP, port,
    settings.p2p_table = {}

    sock = socket.socket(socket.AF_INET, socket.SOCK_DGRAM)
    sock.settimeout(5)
    sock.bind(get_src_address())

    # the login process
    try:
        login(sock, client_server_ip, client_server_port, settings)
    except Exception as err:
        print("Login Failed: " + str(err))
        print("Please make sure you entered the correct server ip, server port, username, password.")
        return

    # the command sending process
    while True:
        try:
            cmd = raw_input("+> ")
        except EOFError as err_msg:
            # Catching the Control-D input from the keyboard
            print("Exiting the program. {}".format(err_msg))
            return

        cmd_splited = cmd.split()
        if len(cmd_splited) < 1:
            print("Invalid Command!")
            continue

        cmd_upper = cmd_splited[0].upper()

        if len(cmd_splited) == 1:
            if cmd_upper == 'Q' or cmd_upper == "QUIT" or cmd_upper == "EXIT" or cmd_upper == "LOGOUT":
                signout(sock, client_server_ip, client_server_port, settings, USER_TABLE)
                sys.exit()
            elif cmd_upper == "LIST":
                list(sock, client_server_ip, client_server_port, settings)

        elif len(cmd_splited) > 2:
            if cmd_upper == "SEND":
                receiver_name = cmd_splited[1]

                # if "Alice" is in the user table, don't need to add new client
                receiver_item = USER_TABLE.get_client_by_name(receiver_name)

                if not receiver_item:
                    try:
                        newClient = p2p(sock, client_server_ip, client_server_port, settings, cmd_splited, USER_TABLE)
                    except Exception as err:
                        print("P2P Authentication Failed: " + str(err))
                        print("The user is not reachable.")
                        continue

                    USER_TABLE.add_client(newClient)
                    receiver_item = newClient

                # p2p_send(sock, client_server_ip, client_server_port, settings)
                # 1. ask server for targeting client's ip:port
                # 2. send message to targeting client's ip:port
                msg = Message(MessageType.send)
                msg.msg_number = 1
                msg.sender_name = settings.username
                iv = os.urandom(16)
                msg.iv = iv

                msg_body = ' '.join(cmd_splited[2:])
                encryptor = HaoEncryptor(None, None)

                msg_body_cipher = encryptor.symmetric_encryption(receiver_item.session_key, iv, msg_body)
                msg.cipher = msg_body_cipher

                h = hmac.HMAC(receiver_item.session_key, hashes.SHA256(), backend=default_backend())
                h.update(msg.cipher)

                msg.hmac_result = h.finalize()

                msg_string = pickle.dumps(msg)
                sock.sendto(msg_string, (receiver_item.ip, int(receiver_item.port_listen)))


# main : None -> None
# Effect:
# 1. Process the command arguments
# 2. Run a listener UDP server thread for receive incoming messages
# 3. Run a thread for getting client's commands from the terminal
def main():
    ####################################################################################################################
    # Process terminal commands
    # python ChatClient.py -u Alice -sip server-ip -sp 9090
    host_address = get_src_address()

    if len(sys.argv) != 5:
        print("Usage: python ChatClient.py -sip server-ip -sp 9090")
        sys.exit(2)

    # read settings file
    settings = ClientSettings()
    settings.server_rsa_pub_key = read_public_key("clientSettings/server_public_key.der")
    settings.encryptor = HaoEncryptor(None, None)
    settings.decryptor = HaoDecryptor(None, None)

    parser = argparse.ArgumentParser()
    parser.add_argument("-u", "--user", type=str, help="the USERNAME")
    parser.add_argument("-sip", "--serverip", type=str, help="the chat server ip")
    parser.add_argument("-sp", "--serverport", type=long, help="the chat server port")
    args = parser.parse_args()

    if args.user:
        # USERNAME = args.user
        settings.username = args.user

    if args.serverip:
        # SERVERIP = args.serverip
        settings.server_ip = args.serverip

    if args.serverport:
        # SERVERPORT = args.serverport
        settings.server_port = args.serverport

    # print("You entered\nserver ip: {}\tserver port: {}".format(SERVERIP, SERVERPORT))
    print("You entered\nserver ip: {}\tserver port: {}".format(settings.server_ip, settings.server_port))
    ####################################################################################################################
    # starting the two threads for UDP communications and terminal commands handling
    # thread for listening incoming message from other clients

    listener_thread = threading.Thread(target=run_udp_server, args=(host_address[0], host_address[1], settings))
    listener_thread.daemon = True
    listener_thread.start()
    ip, port = host_address

    sender_thread = threading.Thread(target=run_client, args=(ip, port, settings))
    sender_thread.daemon = True
    sender_thread.start()

    # wait for the command handling thread quit first, then shutdown the listener server
    sender_thread.join()

if __name__ == '__main__':
    main()
