import os
import sys
import SocketServer
import argparse
import json

from fcryptUtilities import *
from fcryptEncrypt import *
from fcryptDecrypt import *

from ChatUtil import *
from ChatServerHandler import *
# from ChatServerConfiger import *
from ChatUserTable import *

HOST = "localhost"
PORT = 9090
key = ""
client_pub_key = ''
SECRET = ""

class ChatServer(SocketServer.UDPServer):
    def server_close(self):
        print("server closing")

# main : None -> None
# Effect:
# 1. Process the command arguments
# 2. Run a listener UDP server thread for receive incoming messages
def main():
    # server$ python ChatServer.py -sp 9090

    # get the host's ip and an open port number
    host_address = get_src_address()

    ####################################################################################################################
    # parsing the arguments
    if len(sys.argv) != 3:
        print("Usage: python ChatServer.py -sp {}".format(host_address[1]))
        sys.exit(2)

    parser = argparse.ArgumentParser()
    parser.add_argument("-sp", "--serverport",
                        type=long,
                        help="Specify the port number that server runs upon")
    args = parser.parse_args()
    host = host_address[0]
    if args.serverport:
        if args.serverport == 0:
            port = host_address[1]
        else:
            port = args.serverport
    else:
        port = host_address[1]

    ####################################################################################################################
    # load config file
    # config = ConfigHandler()
    # SECRET = config.load_secret()
    # SECRET = os.urandom(16)
    # print("Secret: " + str(SECRET))

    settings = ServerSettings()
    rsa_pri_key = read_private_key("serverSettings/server_private_key.der")
    rsa_pub_key = read_public_key("serverSettings/server_public_key.der")
    user_table = UserTable()

    # load saved user name and password from file to server settings
    with open("serverSettings/user_table.json", 'r') as f:
        user_password_dict = json.load(f)

    for k, v in user_password_dict.items():
        new_client = ClientItem()
        new_client.username = k
        new_client.password_hash = v

        user_table.add_client(new_client)

    # run the server
    try:
        server = ChatServer((host, port), ChatServerHandler)
        # server.rsa = AsyncKeyPair()
        server.settings = settings
        server.login_table = {}
        server.user_table = user_table
        server.settings.rsa_pri_key = rsa_pri_key
        server.settings.rsa_pub_key = rsa_pub_key

        server.secret = os.urandom(16)
        server.encryptor = HaoEncryptor(None, settings.rsa_pri_key)
        server.decryptor = HaoDecryptor(settings.rsa_pri_key, None)

        print("Server Initialized... ")
        print("chat server running on host: {}, port: {}".format(host, port))
        server.serve_forever(0.1)
    except socket.error as errMsg:
        print("Server Error: " + str(errMsg))
        print("Try address: {}, port: {}".format(host_address[0], host_address[1]))
    except KeyboardInterrupt as err:
        print("server stopped")
        sys.exit()

if __name__ == '__main__':
    main()
