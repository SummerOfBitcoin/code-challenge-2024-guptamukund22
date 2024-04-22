import json
import os
import hashlib
import binascii
import bech32
from Crypto.Hash import RIPEMD160
from ecdsa import VerifyingKey, SECP256k1, util
import struct
from typing import List
import time 

def double_sha256(s):
    return hashlib.sha256(hashlib.sha256(s).digest()).digest()

def serialize_varint(value):
    """Serialize an integer as a VarInt."""
    if value < 0xfd:
        return value.to_bytes(1, byteorder='little')
    elif value <= 0xffff:
        return b'\xfd' + value.to_bytes(2, byteorder='little')
    elif value <= 0xffffffff:
        return b'\xfe' + value.to_bytes(4, byteorder='little')
    else:
        return b'\xff' + value.to_bytes(8, byteorder='little')

def serialize_tx(tx):
    serialized_tx = bytearray()
    
    # Version
    serialized_tx.extend(int(tx['version']).to_bytes(4, byteorder='little'))
    
    # Number of inputs, using VarInt
    serialized_tx.extend(serialize_varint(len(tx['vin'])))
    
    # Inputs
    for vin in tx['vin']:
        # TXID
        serialized_tx.extend(bytes.fromhex(vin['txid'])[::-1])
        # VOUT
        serialized_tx.extend(int(vin['vout']).to_bytes(4, byteorder='little'))
        # ScriptSig (not present for SegWit inputs in txid calculation, but demonstrating VarInt usage)
        serialized_tx.extend(serialize_varint(len(bytes.fromhex(vin.get('scriptsig', '')))))
        if 'scriptsig' in vin:
            serialized_tx.extend(bytes.fromhex(vin['scriptsig']))
        # Sequence
        serialized_tx.extend(int(vin['sequence']).to_bytes(4, byteorder='little'))
    
    # Number of outputs, using VarInt
    serialized_tx.extend(serialize_varint(len(tx['vout'])))
    
    # Outputs
    for vout in tx['vout']:
        # Value
        serialized_tx.extend(int(vout['value']).to_bytes(8, byteorder='little'))
        # ScriptPubKey length and ScriptPubKey, using VarInt for the length
        scriptpubkey_bytes = bytes.fromhex(vout['scriptpubkey'])
        serialized_tx.extend(serialize_varint(len(scriptpubkey_bytes)))
        serialized_tx.extend(scriptpubkey_bytes)
    
    # Locktime
    serialized_tx.extend(int(tx['locktime']).to_bytes(4, byteorder='little'))
    
    return bytes(serialized_tx)

def wid_id(tx):
    serialized_tx = bytearray()

    # Version
    serialized_tx.extend(int(tx['version']).to_bytes(4, byteorder='little'))

    # Marker and Flag (only if there is at least one witness)
    if any('witness' in vin for vin in tx['vin']):
        serialized_tx.extend(b'\x00\x01')

    # Number of inputs, using VarInt
    serialized_tx.extend(serialize_varint(len(tx['vin'])))

    # Inputs
    for vin in tx['vin']:
        # TXID
        serialized_tx.extend(bytes.fromhex(vin['txid'])[::-1])
        # VOUT
        serialized_tx.extend(int(vin['vout']).to_bytes(4, byteorder='little'))
        # ScriptSig (empty for segwit inputs initially)
        serialized_tx.extend(serialize_varint(0))
        # Sequence
        serialized_tx.extend(int(vin['sequence']).to_bytes(4, byteorder='little'))
    
    # Outputs
    serialized_tx.extend(serialize_varint(len(tx['vout'])))
    for vout in tx['vout']:
        # Value
        serialized_tx.extend(int(vout['value']).to_bytes(8, byteorder='little'))
        # ScriptPubKey
        scriptpubkey_bytes = bytes.fromhex(vout['scriptpubkey'])
        serialized_tx.extend(serialize_varint(len(scriptpubkey_bytes)))
        serialized_tx.extend(scriptpubkey_bytes)

    # Witness data
    if any('witness' in vin for vin in tx['vin']):
        for vin in tx['vin']:
            if 'witness' in vin:
                # Number of witness elements
                serialized_tx.extend(serialize_varint(len(vin['witness'])))
                for witness in vin['witness']:
                    witness_bytes = bytes.fromhex(witness)
                    serialized_tx.extend(serialize_varint(len(witness_bytes)))
                    serialized_tx.extend(witness_bytes)

    # Locktime
    serialized_tx.extend(struct.pack('<I', tx['locktime']))
    # Compute wTxID
    wtxid = double_sha256(serialized_tx)
    return wtxid.hex()

def get_txid(tx):
    serialized_tx = serialize_tx(tx)
    txid = double_sha256(serialized_tx)
    return txid[::-1].hex()  # Reverse txid to match usual big-endian hex display

t = {
  "version": 2,
  "locktime": 0,
  "vin": [
    {
      "txid": "acc3ba00869acb582a3f2904ce3a11dd3779350ce234063fc7d0959246213364",
      "vout": 133,
      "prevout": {
        "scriptpubkey": "5120a8f86aae4e80a5235a830a92edab346ab46a86e87421e694992eccd7406db98e",
        "scriptpubkey_asm": "OP_PUSHNUM_1 OP_PUSHBYTES_32 a8f86aae4e80a5235a830a92edab346ab46a86e87421e694992eccd7406db98e",
        "scriptpubkey_type": "v1_p2tr",
        "scriptpubkey_address": "bc1p4rux4tjwszjjxk5rp2fwm2e5d26x4phgwss7d9ye9mxdwsrdhx8qylt8qz",
        "value": 1806
      },
      "scriptsig": "",
      "scriptsig_asm": "",
      "witness": [
        "1cebdc60e3772e982d83fda9b07d3e684efbfb57e56236c1b951518a4824ff7cc438d3c7bb415d3abf4036c6a537b37cbd83a50e715810488bf4525b4d7d921d",
        "20f1835aa33781318112236f890ee427a9cea0c03b4e215900fd774c45dbc37111ac0063036f726401010a746578742f706c61696e00357b2270223a226272632d3230222c226f70223a226d696e74222c227469636b223a22646f6765222c22616d74223a2234323030227d68",
        "c0f1835aa33781318112236f890ee427a9cea0c03b4e215900fd774c45dbc37111"
      ],
      "is_coinbase": False,
      "sequence": 4261412863
    }
  ],
  "vout": [
    {
      "scriptpubkey": "00147a665de7a370f4c9b372ab1fae587500a5bcbdb4",
      "scriptpubkey_asm": "OP_0 OP_PUSHBYTES_20 7a665de7a370f4c9b372ab1fae587500a5bcbdb4",
      "scriptpubkey_type": "v0_p2wpkh",
      "scriptpubkey_address": "bc1q0fn9mearwr6vnvmj4v06ukr4qzjme0d565dzcx",
      "value": 294
    }
  ]
}
print(get_txid(t))
print(wid_id(t))