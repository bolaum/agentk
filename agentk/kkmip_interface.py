class KkmipKey(object):
    def __init__(self, pubKeyData, comment):
        self._pub_key_bytes = pubKeyData
        self._comment = comment

    def get_comment(self):
        return self._comment

    def get_pem_bytes(self):
        return self._pub_key_bytes

    def sign_data(self, data):
        pass


class KkmipInterface(object):
    def __init__(self):
        self._keys = []

    def get_keys(self):
        return self._keys

    def close(self):
        pass
