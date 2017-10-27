import logging
from kkmip import types, enums, ttv

logger = logging.getLogger(__name__)


def RegisterRSAPrivateKey(n, e, d, p, q, name):
    length = int(n).bit_length()
    logger.debug('Detected length: %d', length)

    return types.RegisterRequestPayload(
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
            ],
        ),
        object=types.PrivateKey(
            key_block=types.KeyBlock(
                key_format_type=enums.KeyFormatType.TransparentRSAPrivateKey,
                key_value=types.KeyValue(
                    key_material=types.TransparentRSAPrivateKey(
                        modulus=ttv.BigInteger(n),
                        public_exponent=ttv.BigInteger(e),
                        private_exponent=ttv.BigInteger(d),
                        p=ttv.BigInteger(p),
                        q=ttv.BigInteger(q)
                    ),
                ),
                cryptographic_algorithm=enums.CryptographicAlgorithm.RSA,
                cryptographic_length=length,
            )
        )
    )


def RegisterRSAPublicKey(n, e, privkey_uid, name):
    length = int(n).bit_length()
    logger.debug('Detected length: %d', length)

    return types.RegisterRequestPayload(
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
                        linked_object_identifier=privkey_uid
                    )
                )
            ],
        ),
        object=types.PublicKey(
            key_block=types.KeyBlock(
                key_format_type=enums.KeyFormatType.TransparentRSAPublicKey,
                key_value=types.KeyValue(
                    key_material=types.TransparentRSAPublicKey(
                        modulus=ttv.BigInteger(n),
                        public_exponent=ttv.BigInteger(e),
                    )
                ),
                cryptographic_algorithm=enums.CryptographicAlgorithm.RSA,
                cryptographic_length=length,
            )
        )
    )
