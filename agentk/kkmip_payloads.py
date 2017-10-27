import logging
from kkmip import types, enums, ttv

logger = logging.getLogger(__name__)


def RegisterRSAPrivateKey(n, e, d, p, q, name):
    length = int(n).bit_length()
    logger.debug('RegisterRSAPrivateKey: Detected length: %d', length)

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
    logger.debug('RegisterRSAPublicKey: Detected length: %d', length)

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


def QueryServerInformation():
    return types.QueryRequestPayload(
        query_function_list=[
            enums.QueryFunction.QueryServerInformation
        ]
    )


def LocateRSAPublicKeys():
    return types.LocateRequestPayload(
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


def RevokeKey(uid):
    return types.RevokeRequestPayload(
        unique_identifier=uid,
        revocation_reason=types.RevocationReason(
            revocation_reason_code=enums.RevocationReasonCode.CessationOfOperation
        ),
    )


def SignSHA1PKCS1(uid, data):
    return types.SignRequestPayload(
        unique_identifier=uid,
        data=data,
        cryptographic_parameters=types.CryptographicParameters(
            hashing_algorithm=enums.HashingAlgorithm.SHA_1,
            padding_method=enums.PaddingMethod.PKCS1V1_5,
        )
    )


def GetAttributes(uid, attributes):
    return types.GetAttributesRequestPayload(
        unique_identifier=uid,
        attribute_name_list=attributes
    )
