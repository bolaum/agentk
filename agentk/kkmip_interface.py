import base64
from paramiko.message import Message


class KkmipKey(object):
    def __init__(self, pubKeyData, comment):
        # self._pub_key_bytes = pubKeyData
        self._rsa_exp, self._rsa_mod = pubKeyData
        self._pub_key_bytes = None
        self._comment = comment

        self._gen_pem()

    def get_comment(self):
        return self._comment

    def get_pem_bytes(self):
        return self._pub_key_bytes

    def sign_data(self, data):
        pass

    def _gen_pem(self):
        msg = Message()
        msg.add_string('ssh-rsa')
        msg.add_string(self._rsa_exp)
        msg.add_string(self._rsa_mod)
        self._pub_key_bytes = msg.asbytes()

    def get_openssh_pubkey_format(self):
        return '%s %s %s' % (
            'ssh-rsa',
            base64.b64encode(self._pub_key_bytes).decode('ascii'),
            self.get_comment()
        )


class KkmipInterface(object):
    def __init__(self):
        self._keys = []

    def get_keys(self):
        return self._keys

    def close(self):
        pass
