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
    return "abcdabcd-abcd-abcd-abcd-abcdabcdabcd"

def getmasterkey():
    iterations = 1000
    salt = bytes.fromhex("0101010101010101010101010101010101010101010101010101010101010101")
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
        #print(hashlib.sha256(data).digest_size)
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

    #print(iv)

   
    blocks = len(split)
    #print(len(mk))
    #print(len(mk))
    #print(blocks)
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
    #offset =  8
    stripes = 4000
    #stripes = 1
    keyMaterialSectors = (stripes * 64) // luks_sector_size + 1
    #keyMaterialSectors = 504


    for key_id in range(8):
        iterations = 2056030
        salt = bytes.fromhex("0101010101010101010101010101010101010101010101010101010101010101")
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

