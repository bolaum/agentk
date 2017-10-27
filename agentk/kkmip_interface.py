import codecs
import logging
import socket
from io import TextIOWrapper
from kkmip import client
from kkmip.error import KmipError
from pyasn1.codec.der.decoder import decode as der_decoder
from pyasn1_modules.rfc2437 import RSAPrivateKey, RSAPublicKey
from pyasn1_modules.rfc2459 import SubjectPublicKeyInfo
from sarge import Capture, run

from agentk.kkmip_key import KkmipKey
from agentk.kkmip_payloads import *

logger = logging.getLogger(__name__)


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
        logger.info('Trying to ping HSM...')
        payload = QueryServerInformation()
        r = self.send_payload(payload)
        logger.debug('Vendor ID: %s', r.vendor_identification)

    def get_keys(self):
        logger.info('Getting HSM keys...')
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

    def import_key(self, n, e, d, p, q, comment):
        logger.info('Importing keys to HSM...')
        payload = RegisterRSAPrivateKey(n, e, d, p, q, comment)

        try:
            r = self.send_payload(payload)
            privkey_uid = r.unique_identifier
            logger.debug('New private key uid: %s', privkey_uid)
        except KmipError as e:
            logger.error('Kmip: %s', e.result_message)
            raise

        payload = RegisterRSAPublicKey(n, e, privkey_uid, comment)

        try:
            r = self.send_payload(payload)
            pubkey_uid = r.unique_identifier
            logger.debug('New public key uid: %s', pubkey_uid)
        except KmipError as e:
            r = self.send_payload(types.DestroyRequestPayload(privkey_uid))
            logger.debug('Destroy result: %s', r)
            logger.error('Kmip: %s', e.result_message)
            raise

        self.get_key(pubkey_uid).activate()

    # Leaving this for future reference
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

    # Leaving this for future reference
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

    def destroy_key(self, k):
        if k in self._keys:
            self._keys.remove(k)
        k.destroy()

    def close(self):
        pass

    def send_payload(self, payload):
        try:
            # logger.debug('Sending payload: %s', payload)
            r = self._c.post(payload)
            # logger.debug('Response payload: %s', r)
        except socket.gaierror as e:
            raise

        return r

    def _fetch_all_key_ids(self):
        payload = LocateRSAPublicKeys()
        r = self.send_payload(payload)
        logger.debug('Fetch result: %s', r)

        if not r.unique_identifier_list:
            return []

        return r.unique_identifier_list

    # Leaving this for future reference
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
