import ConfigParser
import pickle
import os

class ConfigHandler(object):
    """docstring for ConfigHandler"""
    def __init__(self, path="server.ini"):
        super(ConfigHandler, self).__init__()
        self.path = path
        self.config = ConfigParser.ConfigParser()
        try:
            self.config.read(self.path)
        except Exception as err:
            open("server.ini", 'w')
            self.config.read(self.path)

    def save_secret(self, secret):
        if "Secret" not in self.config.sections():
            self.config.add_section("Secret")

        if secret:
            self.config.set("Secret", "Value", secret)
        else:
            self.config.set("Secret", "Value", os.urandom(16))

    def load_secret(self):
        try:
            return self.config["Secret"].get("Value")
        except ConfigParser.MissingSectionHeaderError as err:
            print("no previous secret, generating a new one.")
            return os.urandom(16)

    def load_user_table(self):
        try:
            ut_file = open("server.ini", "rb")
            my_users = pickle.load(ut_file)
            return my_users
        except Exception as err:
            print("load user table error: " + str(err))

    def save_user_table(self):
        # 1. remove the hard coded name & passwords
        # 2. save hashes and encrypted passwords & username
        my_users = {"alice": "alice", "bob": "bob", "charlie": "charlie", "david": "david", "ellen": "ellen",
        "frank": "frank", "gary": "gary", "howard": "howard", "ian": "ian", "jason":"jason", "kevin":"kevin"}

        with open("server.ini", "wb") as ut:
            pickle.dump(my_users, ut)

if __name__ == '__main__':
    configer = ConfigHandler("server.ini")
    configer.save_secret()
    configer.save_user_table()