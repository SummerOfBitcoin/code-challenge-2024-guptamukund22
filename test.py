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

def merkle_root(txids: List[str]) -> str:
    # Convert each hex-encoded transaction ID into bytes and reverse to little-endian
    hashes = [bytes.fromhex(txid)[::-1] for txid in txids]

    while len(hashes) > 1:
        if len(hashes) % 2 == 1:
            hashes.append(hashes[-1])  # Duplicate the last hash if the number of hashes is odd
        # Pair and hash each consecutive pair of transaction hashes
        hashes = [double_sha256(hashes[i] + hashes[i + 1]) for i in range(0, len(hashes), 2)]

    # Return the Merkle root in hex format, reversing back to big-endian for display
    return hashes[0][::-1].hex() if hashes else ''

def convert_big_to_little_endian(hex_str):
    # Convert hex string to bytes
    hex_bytes = bytes.fromhex(hex_str)
    # Reverse the byte order
    hex_bytes_reversed = hex_bytes[::-1]
    # Convert bytes back to hex
    little_endian_hex = hex_bytes_reversed.hex()
    return little_endian_hex

def witness_commitment(txs):
    root = merkle_root(txs)
    root = convert_big_to_little_endian(root)
    reserved = '00' * 32  # 32 bytes of zero
    print(root + reserved)
    return double_sha256(bytes.fromhex(root + reserved)).hex()

def coinbase(txs,amount):
    tx = bytearray()
    tx.extend(b'\x01\x00\x00\x00') # Version
    tx.extend(b'\x00') # Marker
    tx.extend(b'\x01') # Flag
    tx.extend(b'\x01') # Num Inputs
    tx.extend(b'\x00' * 32) # Prev Tx Hash
    tx.extend(b'\xff\xff\xff\xff') # Prev Txout Index
    scriptsig_bytes = bytes.fromhex('03233708184d696e656420627920416e74506f6f6c373946205b8160a4256c0000946e0100')
    tx.extend(struct.pack('<B', len(scriptsig_bytes))) # Txin Script Len (1 byte, VarInt)
    tx.extend(scriptsig_bytes) # ScriptSig
    tx.extend(b'\xff\xff\xff\xff') # Sequence
    tx.extend(b'\x02') # Num Outputs

    # First Output
    tx.extend(bytes.fromhex(amount)) # Amount 1
    tx.extend(b'\x19') # Txout Script Len
    tx.extend(bytes.fromhex('76a914edf10a7fac6b32e24daa5305c723f3ee58db1bc888ac')) # ScriptPubKey
    txs.insert(0,"0000000000000000000000000000000000000000000000000000000000000000")
    # Second Output
    tx.extend(bytes.fromhex('0000000000000000')) # Amount 2
    print(witness_commitment(txs))
    script = bytes.fromhex('6a24aa21a9ed') + bytes.fromhex(witness_commitment(txs))
    tx.extend(len(script).to_bytes(1, 'big')) # Txout Script Len
    tx.extend(script) # Script

    # Locktime
    tx.extend(b'\x01\x20') # Stack Items Len
    tx.extend(b'\x00' * 32)
    tx.extend(b'\x00\x00\x00\x00') # Locktime
    txid = double_sha256(tx)
    return tx.hex(), txid[::-1].hex()

wid = ["6440ffe0a58cbec4692d075bc74877cdf7554a25eee5a02fa6ff3bb55dbb0802" ,
       "9e4fa066c9587e65845065a6b5ad02cbec6cfdad8b0158953dcee086ff420ffd" , 
        " 57661a181f4762861fc2bc5c6001c27b54e26992e845b4742a6f0f867609b2c2"]
t,h= coinbase(wid,"f595814a00000000")