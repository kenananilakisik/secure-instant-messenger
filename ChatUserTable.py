

# ClientTableItem is a group of information that is unique to the client.
# this item is being used on the server side to communicate and authenticate the client
class ClientItem(object):
    def __init__(self):
        self.username = ''
        self.password_hash = ''
        self.ip = ''
        self.port_listen = -1
        self.port_send = -1
        self.pub_key_pem = None
        self.last_nounce = -1
        # TODO: a default session key
        self.session_key = None
        self.is_online = False
        self.dh_pub = None


class UserTable(object):
    """docstring for UserTable"""
    def __init__(self):
        super(UserTable, self).__init__()
        self.client_list = []

    def get_client_by_name(self, name):
        if name:
            for c in self.client_list:
                if c.username == name:
                    return c
        return None

    def get_client_by_ip_send_port(self, ip, send_port):
        if ip and send_port:
            for c in self.client_list:
                if c.ip == ip and c.port_send == send_port:
                    return c
        return None

    def get_client_by_ip_listen_port(self, ip, listen_port):
        if ip and listen_port:
            for c in self.client_list:
                if c.ip == ip and c.port_send == listen_port:
                    return c
        return None

    def add_client(self, client_obj):
        self.client_list.append(client_obj)

    def remove_client_by_name(self, name):
        if name:
            for c in self.client_list:
                if c.username == name:
                    self.client_list.remove(c)
                    return
        return None

    def is_client_online(self, name):
        if name:
            for c in self.client_list:
                if c.username == name:
                    return c.is_online
        return False

    def set_nounce(self, name, val):
        if name:
            for c in self.client_list:
                if c.username == name:
                    c.last_nounce = val

    def get_client_pub_key(self, name):
        c = self.get_client_by_name(name)
        if c:
            return c.rsa_pub_key

        return None

    def get_client_listening_address(self, name):
        c = self.get_client_by_name(name)
        if c:
            if c.ip and c.port_listen:
                return c.ip, c.port_listen
            else:
                print("Missing IP or PORT LISTEN")

        return None

    def get_client_session_key(self, name):
        c = self.get_client_by_name(name)
        if c:
            if c.session_key:
                return c.session_key

        return None

    def get_client_session_key(self, ip, port_sent):
        for c in self.client_list:
            if c.ip == ip and c.port_send == port_sent:
                return c.session_key

    def get_online_clients_name(self):
        ret = []
        for c in self.client_list:
            if c.is_online:
                ret.append(c.username)

        return ret
