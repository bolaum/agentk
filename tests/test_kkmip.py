from kkmip import client, types, enums
from agentk.kkmip_interface import KkmipInterface


def test_hsm_connection():
    kkmip = KkmipInterface('kryptus.dyndns.biz', 49252,
                           cert=('/home/bolaum/projs/desafiok/vhsm_12/user1.crt',
                                 '/home/bolaum/projs/desafiok/vhsm_12/user1.key'))

    kkmip.ping_hsm()

def test_get_hsm_keys():
    kkmip = KkmipInterface('kryptus.dyndns.biz', 49252,
                           cert=('/home/bolaum/projs/desafiok/vhsm_12/user1.crt',
                                 '/home/bolaum/projs/desafiok/vhsm_12/user1.key'))

    keys = kkmip.get_keys()
    assert len(keys) > 0



if __name__ == 'blabla':

    proto = client.Protocol.HTTPS_JSON
    c = client.Client(host='kryptus.dyndns.biz', port=49252, protocol=client.Protocol.TTLV,
                      verify=False,
                      cert=('/home/bolaum/projs/desafiok/vhsm_12/user1.crt',
                            '/home/bolaum/projs/desafiok/vhsm_12/user1.key'))

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

    r = c.post(payload)
    print(r.unique_identifier_list)
    print()

    for u in r.unique_identifier_list:
        payload = types.GetAttributeListRequestPayload(
            unique_identifier=u
        )
        r = c.post(payload)
        print(r)
        print()

        payload = types.GetAttributesRequestPayload(
            unique_identifier=u,
            attribute_name_list=['Object Type', 'Cryptographic Algorithm', 'Digest', 'State']
        )
        r = c.post(payload)
        print(r)
        print()

        payload = types.GetRequestPayload(
            unique_identifier=u,
        )
        r = c.post(payload)
        print(r.object.key_block.key_value.key_material.modulus)
        print(r.object.key_block.key_value.key_material.public_exponent)
        print()
