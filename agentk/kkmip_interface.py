import base64
import logging
import socket
from kkmip import client, types, enums
from paramiko.message import Message

from agentk.utils import bigint_to_bytes

logger = logging.getLogger(__name__)


class KkmipKey(object):
    def __init__(self, exponent, modulus, comment):
        self._rsa_exp = exponent
        self._rsa_mod = modulus
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
        msg.add_string(bigint_to_bytes(self._rsa_exp))
        msg.add_string(bigint_to_bytes(self._rsa_mod, extra_bytes=1))
        self._pub_key_bytes = msg.asbytes()

    def get_openssh_pubkey_format(self):
        return '%s %s %s' % (
            'ssh-rsa',
            base64.b64encode(self._pub_key_bytes).decode('ascii'),
            self.get_comment()
        )


class KkmipInterface(object):
    def __init__(self, host, port, cert):
        self._host = host
        self._port = port
        self._cert = cert
        self._keys = []

        self._c = client.Client(
            host=self._host,
            port=self._port,
            protocol=client.Protocol.TTLV,
            verify=False,
            cert=self._cert)

    def ping_hsm(self):
        payload = types.QueryRequestPayload(
            query_function_list=[
                enums.QueryFunction.QueryServerInformation
            ]
        )
        r = self._send_payload(payload)
        logger.debug('Vendor ID: %s', r.vendor_identification)

    def get_keys(self):
        self._keys = []
        for id in self._fetch_all_key_ids():
            exp, mod = self._fetch_key_material(id)
            self._keys.append(KkmipKey(exp, mod, id))

        return self._keys

    def close(self):
        pass

    def _send_payload(self, payload):
        try:
            # logger.debug('Sending payload: %s', payload)
            r = self._c.post(payload)
            # logger.debug('Response payload: %s', r)
        except socket.gaierror as e:
            logger.error(e)
            raise

        return r

    def _fetch_all_key_ids(self):
        payload = types.LocateRequestPayload(
            attribute_list=[
                types.Attribute(
                    attribute_name=enums.Tag.ObjectType,
                    attribute_value=enums.ObjectType.PublicKey,
                ),
                types.Attribute(
                    attribute_name=enums.Tag.CryptographicAlgorithm,
                    attribute_value=enums.CryptographicAlgorithm.RSA,
                ),
            ],
        )
        r = self._send_payload(payload)
        return r.unique_identifier_list

    def _fetch_key_material(self, id):
        payload = types.GetRequestPayload(
            unique_identifier=id,
        )
        r = self._send_payload(payload)
        exp = r.object.key_block.key_value.key_material.public_exponent
        mod = r.object.key_block.key_value.key_material.modulus
        return exp, mod
