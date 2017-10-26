from kkmip import client, types, enums
from agentk.kkmip_interface import KkmipInterface


def test_hsm_connection(kkmip):
    kkmip.ping_hsm()


def test_import_to_and_get_hsm_key(kkmip, privkey_fn):
    pubkey_id, privkey_id = kkmip.import_key_from_file(privkey_fn, 'testkey')

    keys = kkmip.get_keys()
    assert len(keys) > 0

    kkmip.get_key(pubkey_id).destroy()

