import base64
import codecs
import hexdump
import logging
import socket
from kkmip import client, types, enums, ttv
from paramiko.message import Message
from sarge import Capture, run
from io import TextIOWrapper
from hashlib import md5
from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1_modules.rfc2437 import RSAPrivateKey, RSAPublicKey
from pyasn1_modules.rfc2459 import SubjectPublicKeyInfo

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
        r = self.send_payload(payload)
        logger.debug('Vendor ID: %s', r.vendor_identification)

    def get_keys(self):
        self._keys = []
        for id in self._fetch_all_key_ids():
            self._keys.append(KkmipKey(self, id))

        return self._keys

    def get_key(self, uid):
        return KkmipKey(self, uid)

    def get_cached_key_by_fingerprint(self, fingerprint):
        for k in self._keys:
            if k.get_fingerprint() == fingerprint:
                return k
        return None

    def import_key_from_file(self, privkey_fn, name):
        logger.debug('Privkey file name: %s', privkey_fn)

        pubkey_der, privkey_der = self._get_keys_der(privkey_fn)

        # pubkey_id = None
        privkey_id = self.import_privkey(privkey_der, name)
        pubkey_id = self.import_pubkey(pubkey_der, name, privkey_id)

        return pubkey_id, privkey_id

    def import_pubkey(self, pubkey_der, name, privkey_id):
        subject_public_key, rest_of_input = der_decoder(pubkey_der, asn1Spec=SubjectPublicKeyInfo())
        bin = subject_public_key['subjectPublicKey'].asOctets()
        public_key, rest_of_input = der_decoder(bin, asn1Spec=RSAPublicKey())
        length = int(public_key['modulus']).bit_length()
        logger.debug('Detected length: %d', length)

        payload = types.RegisterRequestPayload(
            object_type=enums.ObjectType.PublicKey,
            template_attribute=types.TemplateAttribute(
                attribute_list=[
                    types.Attribute(
                        attribute_name=enums.Tag.Name,
                        attribute_value=types.Name(
                            name,
                            enums.NameType.UninterpretedTextString
                        ),
                    ),
                    types.Attribute(
                        attribute_name=enums.Tag.CryptographicUsageMask,
                        attribute_value=enums.CryptographicUsageMask.Verify |
                                        enums.CryptographicUsageMask.Encrypt
                    ),
                    types.Attribute(
                        attribute_name=enums.Tag.Link,
                        attribute_value=types.Link(
                            link_type=enums.LinkType.PrivateKeyLink,
                            linked_object_identifier=privkey_id
                        )
                    )
                ],
            ),
            object=types.PublicKey(
                key_block=types.KeyBlock(
                    key_format_type=enums.KeyFormatType.TransparentRSAPublicKey,
                    key_value=types.KeyValue(
                        key_material=types.TransparentRSAPublicKey(
                            modulus=ttv.BigInteger(int(public_key['modulus'])),
                            public_exponent=ttv.BigInteger(int(public_key['publicExponent'])),
                        )
                    ),
                    cryptographic_algorithm=enums.CryptographicAlgorithm.RSA,
                    cryptographic_length=length,
                )
            )
        )
        r = self.send_payload(payload)

        self.send_payload(types.ActivateRequestPayload(r.unique_identifier))

        logger.debug('Imported public key id: %s', r.unique_identifier)
        return r.unique_identifier

    def import_privkey(self, privkey_der, name):
        private_key, rest_of_input = der_decoder(privkey_der, asn1Spec=RSAPrivateKey())
        length = int(private_key['modulus']).bit_length()
        logger.debug('Detected length: %d', length)

        payload = types.RegisterRequestPayload(
            object_type=enums.ObjectType.PrivateKey,
            template_attribute=types.TemplateAttribute(
                attribute_list=[
                    types.Attribute(
                        attribute_name=enums.Tag.Name,
                        attribute_value=types.Name(
                            name + '_priv',
                            enums.NameType.UninterpretedTextString
                        ),
                    ),
                    types.Attribute(
                        attribute_name=enums.Tag.CryptographicUsageMask,
                        attribute_value=enums.CryptographicUsageMask.Sign |
                                        enums.CryptographicUsageMask.Decrypt
                    ),
                    # types.Attribute(
                    #     attribute_name=enums.Tag.Link,
                    #     attribute_value=types.Link(
                    #         link_type=enums.LinkType.PublicKeyLink,
                    #         linked_object_identifier=pubkey_id
                    #     )
                    # )
                ],
            ),
            object=types.PrivateKey(
                key_block=types.KeyBlock(
                    key_format_type=enums.KeyFormatType.PKCS_1,
                    key_value=types.KeyValue(
                        key_material=privkey_der,
                    ),
                    cryptographic_algorithm=enums.CryptographicAlgorithm.RSA,
                    cryptographic_length=length,
                )
            )
        )
        r = self.send_payload(payload)

        self.send_payload(types.ActivateRequestPayload(r.unique_identifier))

        logger.debug('Imported private key id: %s', r.unique_identifier)
        return r.unique_identifier

    def destroy_keys(self):
        for k in self.get_keys():
            k.destroy()

    def close(self):
        pass

    def send_payload(self, payload):
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
        r = self.send_payload(payload)
        logger.debug('Fetch result: %s', r)

        if not r.unique_identifier_list:
            return []

        return r.unique_identifier_list

    def _get_keys_der(self, privkey_fn):
        # generate public key in pkcs1 format
        with Capture() as out:
            run('openssl rsa -in %s -outform PEM -pubout' % privkey_fn, stdout=out, stderr=Capture())
            pubkey_text = [n for n in TextIOWrapper(out).readlines() if not n.startswith('---')]
        pubkey_text = ''.join(pubkey_text)

        # convert to bytes
        pubkey_der = codecs.decode(pubkey_text.encode('ascii'), 'base64')

        subject_public_key, rest_of_input = der_decoder(pubkey_der, asn1Spec=SubjectPublicKeyInfo())
        bin = subject_public_key['subjectPublicKey'].asOctets()
        public_key, rest_of_input = der_decoder(bin, asn1Spec=RSAPublicKey())
        # logger.debug('Pubkey loaded: \n%s', public_key.prettyPrint())

        # load private key contents
        with open(privkey_fn, 'r') as f:
            privkey_text = [n for n in f.readlines() if not n.startswith('---')]
        privkey_text = ''.join(privkey_text)

        # convert to bytes
        privkey_der = codecs.decode(privkey_text.encode('ascii'), 'base64')

        private_key, rest_of_input = der_decoder(privkey_der, asn1Spec=RSAPrivateKey())
        # logger.debug('Privkey loaded: \n%s', private_key.prettyPrint())

        return pubkey_der, privkey_der
