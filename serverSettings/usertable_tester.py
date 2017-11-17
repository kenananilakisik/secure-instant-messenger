import hashlib
import json
from cryptography.hazmat.backends import default_backend
from cryptography.hazmat.primitives import hashes
import base64

class ClientTableItem(object):
    def __init__(self):
        self.ip = '127.0.0.1'
        self.port = '50001'
        self.pub_key = None
        self.username = ''
        self.password_hash = None
        self.last_nounce = -1


my_users = {"alice": "alice", "bob": "bob", "charlie": "charlie", "david": "david", "ellen": "ellen",
"frank": "frank", "gary": "gary", "howard": "howard", "ian": "ian", "jason":"jason", "kevin":"kevin"}

for un in my_users.keys():
    hl_hex = hashlib.sha256(un).hexdigest()
    # i = ClientTableItem()
    # i.password_hash = hl_hex
    # i.ip = '10.0.0.47'
    # i.port = 8080
    my_users[un] = hl_hex

print(my_users)

with open('user_table.json', 'w+') as f:
    json.dump(my_users, f)

another_table = None
with open('user_table.json', 'r+') as f:
    another_table = json.load(f)

print another_table

for k, v in another_table.items():
    print(k)
    print(v)