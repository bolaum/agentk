import base64
import hexdump
import logging
from binascii import hexlify
from hashlib import md5
from kkmip import types, enums
from kkmip.error import KmipError
from paramiko.message import Message

from agentk.utils import bigint_to_bytes
from agentk.kkmip_payloads import *

logger = logging.getLogger(__name__)


class KkmipKey(object):
    def __init__(self, kkmip_interface, uid):
        self._kkmip = kkmip_interface
        self._uid = uid

        attrs = self._fetch_attributes()

        self._name = attrs['name']
        self._link = attrs['link']
        self._state = attrs['state']

        self._pub_key_bytes = None
        self._gen_pem()

        self._fp = hexlify(self.get_fingerprint()).decode('ascii')

    def get_comment(self):
        return self._name

    def get_pem_bytes(self):
        return self._pub_key_bytes

    def get_fingerprint(self):
        return md5(self.get_pem_bytes()).digest()

    def activate(self):
        logger.info('Activating public key %s...', self._uid)
        self._kkmip.send_payload(types.ActivateRequestPayload(self._uid))

        if self._link:
            logger.info('Activating private key %s...', self._link)
            self._kkmip.send_payload(types.ActivateRequestPayload(self._link))

    def revoke(self):
        logger.info('Revoking public key %s...', self._uid)
        self._kkmip.send_payload(RevokeKey(self._uid))

        if self._link:
            logger.info('Revoking private key %s...', self._link)
            self._kkmip.send_payload(RevokeKey(self._link))

    def destroy(self):
        self.revoke()

        logger.info('Destroying public key %s...', self._uid)
        self._kkmip.send_payload(types.DestroyRequestPayload(self._uid))

        if self._link:
            logger.info('Destroying private key %s...', self._link)
            self._kkmip.send_payload(types.DestroyRequestPayload(self._link))

    def sign(self, data):
        logger.info('Signing data...')
        logger.debug('Data to sign:')
        for l in hexdump.hexdump(data, result='generator'):
            logger.debug(l)

        # make sure key is activated before signing
        if self._state != enums.State.Active:
            self.activate()

        payload = SignSHA1PKCS1(self._link, data)
        try:
            r = self._kkmip.send_payload(payload)
        except KmipError as e:
            logger.error('Kmip: %s', e.result_message)
            return None

        data = r.signature_data
        logger.debug('Signed data (%d bytes):', len(data ))
        for l in hexdump.hexdump(data, result='generator'):
            logger.debug(l)

        return data

    def get_openssh_pubkey_format(self):
        return '%s %s %s' % (
            'ssh-rsa',
            base64.b64encode(self._pub_key_bytes).decode('ascii'),
            self.get_comment()
        )

    def _gen_pem(self):
        msg = Message()
        msg.add_string('ssh-rsa')
        exp, mod = self._fetch_material()
        msg.add_string(bigint_to_bytes(exp))
        msg.add_string(bigint_to_bytes(mod, extra_bytes=1))
        self._pub_key_bytes = msg.asbytes()

    def _fetch_attributes(self):
        attrs = {
            'name': None,
            'link': None,
            'state': None
        }

        payload = GetAttributes(self._uid, ['Name', 'Link', 'State'])
        r = self._kkmip.send_payload(payload)

        if r.attribute_list:
            logger.debug('Name: %s', r.attribute_list[0].attribute_value.name_value)
            attrs['name'] = r.attribute_list[0].attribute_value.name_value

            if len(r.attribute_list) > 1:
                logger.debug('Link: %s', r.attribute_list[1].attribute_value.linked_object_identifier)
                attrs['link'] = r.attribute_list[1].attribute_value.linked_object_identifier

            if len(r.attribute_list) > 2:
                logger.debug('State: %s', r.attribute_list[2].attribute_value)
                attrs['state'] = r.attribute_list[2].attribute_value

        return attrs

    def _fetch_material(self):
        payload = types.GetRequestPayload(
            unique_identifier=self._uid,
        )
        r = self._kkmip.send_payload(payload)
        # logger.debug(r)
        exp = r.object.key_block.key_value.key_material.public_exponent
        mod = r.object.key_block.key_value.key_material.modulus
        return exp, mod
