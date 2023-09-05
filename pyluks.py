#!/usr/bin/env python3

import argparse
import hashlib
import cryptography

def createByteString(string, length):
    result = string.encode('ascii')
    result += b'\0' * (length - len(string))
    return result

def createByteInt(value):
    return value.to_bytes(4, 'big')


def getUUID():
    return "3dbc5803-20e4-4d8a-ace3-a034fa0d4a64"


def getmasterkey():
    iterations = 128754
    salt = bytes.fromhex("1924e8299633c0e0f2eb700d046f4836e3d644f7ad8836e7c5a73f05f88960b1")
    key = bytes.fromhex(
            "22 2c 75 52 fa 1c 58 07 25 85 ca 62 5b ef ca bb"
            "53 06 06 33 6d c9 40 75 50 a4 3e 98 d5 03 d5 8f"
            "23 20 b8 6f 7e e4 7d 1f 74 79 e6 4a 45 7e 14 98"
            "5d d3 3d 3b 05 3e 32 e0 c8 44 3b 38 5c d1 86 28"
            )
    key = bytes.fromhex(
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
            "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
            )
    keyhash = hashlib.pbkdf2_hmac("sha256", key, salt, iterations, 20)

    return (key, keyhash, salt, iterations)

def xorbytes(var, key):
    return bytes(a ^ b for a, b in zip(var, key))

def hashval(val):
    width = 32
    rounds = math.ceil((len(val)/width))

    result = bytes()
    for i in range(rounds):
        data = val[i*width:(i+1)*width]
        iterator = i.to_bytes(8, "little")
        #data = iterator + data
    #    print(len(data))
        hashedData = bytes.fromhex(hashlib.sha256(data).hexdigest())
        print(hashlib.sha256(data).digest_size)
        hashedData = hashedData[0:len(data)]
        result += hashedData

    return result

import random, math

def afSplitter(unsplitMaterial, stripes):
    length = len(unsplitMaterial)

    d = b'\0' * length
    s = b''

    for stripe in range(stripes-1):
        s_k = b'\0' * length #random.randbytes(length)
        d = xorbytes(d, s_k)
        d = hashval(d)
        assert len(d) == 64
        s += s_k

    s += xorbytes(d, unsplitMaterial)

    return s

from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os

def getSlotKey(mk, stripes, iterations, salt):
    split = afSplitter(mk, stripes)
    key = ""
    keyhash = hashlib.pbkdf2_hmac("sha256", key.encode("utf-8"), salt, iterations, 64)
    iv = (8).to_bytes(8, 'little') + b'\0'* 8

    print(iv)

   
    blocks = len(split)
    print(len(mk))
    print(len(mk))
    print(blocks)
    cipher = Cipher(algorithms.AES(keyhash), modes.XTS(iv))
    encryptor = cipher.encryptor()
    ct = encryptor.update(split) + encryptor.finalize()
    return ct

def createHeader():
    magic = b"LUKS" + bytes.fromhex("BABE")
    version = bytes.fromhex("0001")
    chipher_name = createByteString("aes", 32)
    #chipher_name = createByteString("cipher_null", 32)
    chipher_mode = createByteString("xts-plain64", 32)
    #chipher_mode = createByteString("ecb", 32)
    hash_spec = createByteString("sha256", 32)
    payload_offset = createByteInt(4096)
    key_bytes = createByteInt(64)
    #key_bytes = createByteInt(32)
    mk, mk_digest, mk_digest_salt, mk_iterations = getmasterkey()
    mk_digest_iter = createByteInt(mk_iterations)
    uuid = createByteString(getUUID(), 40)

    header = magic + version + chipher_name + chipher_mode + hash_spec + payload_offset + key_bytes + mk_digest + mk_digest_salt + mk_digest_iter + uuid

    disabled = bytes.fromhex("0000DEAD")
    enabled = bytes.fromhex("00AC71F3")
    status = enabled

    size_of_phdr = 592
    luks_sector_size = 512

    offset =  size_of_phdr // luks_sector_size + 1
    offset =  8
    #stripes = 4000
    stripes = 1
    keyMaterialSectors = (stripes * 64) // luks_sector_size + 1
    keyMaterialSectors = 504


    for key_id in range(8):
        iterations = 2056030
        salt = bytes.fromhex("e98b34cc2157547c10c4e31d1bdf985555c2bf561488116f38dbd344a47a828f")
        header += status
        if status == disabled:
            header += b'\0' * 4
            header += b'\0' * 32
            header += createByteInt(offset)
            header += createByteInt(stripes)
            offset +=  keyMaterialSectors
            continue

        header += createByteInt(iterations)
        header += salt
        header += createByteInt(offset)
        header += createByteInt(stripes)
        status = disabled
        offset +=  keyMaterialSectors

    header += b'\0' * (4096 - len(header))

    slot1 = getSlotKey(mk, stripes, iterations, salt)
    header += slot1
    header += b'\0' * (16777216 - len(header))
    return header

parser = argparse.ArgumentParser(
    prog = 'PyLuks',
    description = 'Create a Luks filesystem image from python')
parser.add_argument('file', type = argparse.FileType('wb'))

args = parser.parse_args()

header = createHeader()
f = args.file
f.write(header)
f.close()

