from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import serialization


# Contract: read_public_key : str -> _RSAPublicKey
# Purpose: load the public key file with given file name
# Return: RSA public key object
def read_public_key(key_fn):
    try:
        key_file = open(key_fn, "rb")
        pub_key = serialization.load_der_public_key(key_file.read(), backend=default_backend())
        # print("Pub key size: {}".format(pub_key.key_size))
        return pub_key
    except IOError as err_msg:
        print("Open key file failed. Please check the key file name. " + str(err_msg))
        raise IOError(err_msg)


# Contract: read_private_key : str -> _RSAPrivateKey
# Purpose: load the private key file with given file name
# Return: RSA private key object
def read_private_key(key_fn):
    try:
        key_file = open(key_fn, "rb")
        pri_key = serialization.load_der_private_key(key_file.read(), password=None, backend=default_backend())
        # print("Pri key size: {}".format(pri_key.key_size))
        return pri_key
    except IOError as err_msg:
        print("Open key file failed. Please check the key file name. " + str(err_msg))
        raise IOError(err_msg)


# Contract: open_input_file : str -> file
# Purpose: load input file with given file name
# Return: the opened file object
def open_input_file(filename):
    try:
        in_file = open(filename, "rb")
        return in_file
    except IOError as err_msg:
        print("Open input file failed. Please check the input file name. " + str(err_msg))
        raise IOError(err_msg)


# Contract: open_output_file : str -> file
# Purpose: load output file with given file name
# Return: the opened file object
def open_output_file(filename):
    try:
        out_file = open(filename, "wb")
        return out_file
    except IOError as err_msg:
        print("Open output file failed. Please check the output file name. " + str(err_msg))
        raise IOError(err_msg)
