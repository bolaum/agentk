import base64
import hexdump
import logging
from hashlib import md5
from kkmip import types, enums
from paramiko.message import Message

from agentk.utils import bigint_to_bytes

logger = logging.getLogger(__name__)


class KkmipKey(object):
    def __init__(self, kkmip_interface, uid):
        self._kkmip = kkmip_interface
        self._uid = uid

        attrs = self._fetch_attributes()

        self._name = attrs['name']
        self._link = attrs['link']

        self._pub_key_bytes = None
        self._gen_pem()

    def get_comment(self):
        return self._name

    def get_pem_bytes(self):
        return self._pub_key_bytes

    def get_fingerprint(self):
        return md5(self.get_pem_bytes()).digest()

    def activate(self):
        # TODO: this!
        self.send_payload(types.ActivateRequestPayload(r.unique_identifier))

    def revoke(self):
        # revoke public and private keys
        uids = [self._uid]

        if self._link:
            uids.append(self._link)

        for uid in uids:
            payload = types.RevokeRequestPayload(
                unique_identifier=uid,
                revocation_reason=types.RevocationReason(
                    revocation_reason_code=enums.RevocationReasonCode.CessationOfOperation
                ),
            )
            r = self._kkmip.send_payload(payload)
            logger.debug('Revoke result: %s', r)

    def destroy(self):
        self.revoke()

        # revoke public and private keys
        uids = [self._uid]

        if self._link:
            uids.append(self._link)

        for uid in uids:
            payload = types.DestroyRequestPayload(uid)
            r = self._kkmip.send_payload(payload)
            logger.debug('Destroy result: %s', r)

    def sign(self, data):
        logger.debug('Data to sign:')
        for l in hexdump.hexdump(data, result='generator'):
            logger.debug(l)

        # make sure key is activated before signing
        self.

        payload = types.SignRequestPayload(
            unique_identifier=self._link,
            data=data,
            cryptographic_parameters=types.CryptographicParameters(
                hashing_algorithm=enums.HashingAlgorithm.SHA_1,
                padding_method=enums.PaddingMethod.PKCS1V1_5,
            )
        )
        r = self._kkmip.send_payload(payload)

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
            'link': None
        }

        payload = types.GetAttributesRequestPayload(
            unique_identifier=self._uid,
            attribute_name_list=['Name', 'Link']
        )
        r = self._kkmip.send_payload(payload)

        if r.attribute_list:
            logger.debug('Name: %s', r.attribute_list[0].attribute_value.name_value)
            attrs['name'] = r.attribute_list[0].attribute_value.name_value

            if len(r.attribute_list) > 1:
                logger.debug('Link: %s', r.attribute_list[1].attribute_value.linked_object_identifier)
                attrs['link'] = r.attribute_list[1].attribute_value.linked_object_identifier

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
