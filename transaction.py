#!/usr/bin/env python3
# -*- coding: utf-8 -*-
import logging
from collections import namedtuple

from crypto import double_sha256, sha256

from crypto import address_to_public_key_hash

from utils import (
    bytes_to_hex,  hex_to_bytes, int_to_varint
)

import math
from bsv_mini import bsv
from meta import Unspent
#import cryptos
#from kivy.network.urlrequest import UrlRequest
from network import get_tx_by_txid, get_utxo_by_address, broadcast_tx
#from urllib.request import urlopen
#from urllib.request import Request
#import json
#import certifi
#import os
#os.environ['SSL_CERT_FILE'] = certifi.where()
#import requests
#from bitsv.wallet import Key, PrivateKey, wif_to_key


VERSION_1 = 0x01.to_bytes(4, byteorder='little')
SEQUENCE = 0xffffffff.to_bytes(4, byteorder='little')
LOCK_TIME = 0x00.to_bytes(4, byteorder='little')

# The dust is described in bitcoin-sv/src/primitives/transaction.h
DUST = 546

##
# Python 3 doesn't allow bitwise operators on byte objects...
HASH_TYPE = 0x01.to_bytes(4, byteorder='little')
# BitcoinSV fork ID.
SIGHASH_FORKID = 0x40.to_bytes(4, byteorder='little')
# So we just do this for now. FIXME
HASH_TYPE = 0x41.to_bytes(4, byteorder='little')
##

OP_0 = b'\x00'
OP_FALSE = b'\00'
OP_CHECKLOCKTIMEVERIFY = b'\xb1'
OP_CHECKSIG = b'\xac'
OP_DUP = b'v'
OP_EQUALVERIFY = b'\x88'
OP_HASH160 = b'\xa9'
OP_PUSH_20 = b'\x14'
OP_RETURN = b'\x6a'
OP_PUSHDATA1 = b'\x4c'
OP_PUSHDATA2 = b'\x4d'
OP_PUSHDATA4 = b'\x4e'

MESSAGE_LIMIT = 100000  # The real limiting factor seems to be total transaction size


class TxIn:
    __slots__ = ('script', 'script_len', 'txid', 'txindex', 'amount')

    def __init__(self, script, script_len, txid, txindex, amount):
        self.script = script
        self.script_len = script_len
        self.txid = txid
        self.txindex = txindex
        self.amount = amount

    def __eq__(self, other):
        return (self.script == other.script and
                self.script_len == other.script_len and
                self.txid == other.txid and
                self.txindex == other.txindex and
                self.amount == other.amount)

    def __repr__(self):
        return 'TxIn({}, {}, {}, {}, {})'.format(
            repr(self.script),
            repr(self.script_len),
            repr(self.txid),
            repr(self.txindex),
            repr(self.amount)
        )


Output = namedtuple('Output', ('address', 'amount', 'currency'))


def calc_txid(tx_hex):
    return bytes_to_hex(double_sha256(hex_to_bytes(tx_hex))[::-1])


def estimate_tx_fee(n_in, n_out, satoshis, compressed, op_return_size=0):

    if not satoshis:
        return 0

    estimated_size = (
        4 +  # version
        n_in * (148 if compressed else 180)
        + len(int_to_varint(n_in))
        + n_out * 34  # excluding op_return outputs, dealt with separately
        + len(int_to_varint(n_out))
        + op_return_size  # grand total size of op_return outputs(s) and related field(s)
        + 4  # time lock
    )

    estimated_fee = math.ceil(estimated_size * satoshis)

    logging.debug('Estimated fee: {} satoshis for {} bytes'.format(estimated_fee, estimated_size))

    return estimated_fee


def get_op_return_size(message, custom_pushdata=False):
    # calculate op_return size for each individual message
    if custom_pushdata is False:
        op_return_size = (
            8  # int64_t amount 0x00000000
            + len(OP_FALSE + OP_RETURN)  # 2 bytes
            + len(get_op_pushdata_code(message))  # 1 byte if <75 bytes, 2 bytes if OP_PUSHDATA1...
            + len(message)  # Max 220 bytes at present
        )

    if custom_pushdata is True:
        op_return_size = (
            8  # int64_t amount 0x00000000
            + len(OP_FALSE + OP_RETURN)  # 2 bytes
            + len(message)  # Unsure if Max size will be >220 bytes due to extra OP_PUSHDATA codes...
        )

    # "Var_Int" that preceeds OP_RETURN - 0xdf is max value with current 220 byte limit (so only adds 1 byte)
    op_return_size += len(int_to_varint(op_return_size))
    return op_return_size


def get_op_pushdata_code(dest):
    length_data = len(dest)
    if length_data <= 0x4c:  # (https://en.bitcoin.it/wiki/Script)
        return length_data.to_bytes(1, byteorder='little')
    elif length_data <= 0xff:
        return OP_PUSHDATA1 + length_data.to_bytes(1, byteorder='little')  # OP_PUSHDATA1 format
    elif length_data <= 0xffff:
        return OP_PUSHDATA2 + length_data.to_bytes(2, byteorder='little')  # OP_PUSHDATA2 format
    else:
        return OP_PUSHDATA4 + length_data.to_bytes(4, byteorder='little')  # OP_PUSHDATA4 format




def construct_output_block(outputs, custom_pushdata=False):

    output_block = b''

    for data in outputs:
        dest, amount = data

        # Real recipient
        if amount:
            script = (OP_DUP + OP_HASH160 + OP_PUSH_20 +
                      address_to_public_key_hash(dest) +
                      OP_EQUALVERIFY + OP_CHECKSIG)

            output_block += amount.to_bytes(8, byteorder='little')

        # Blockchain storage
        else:
            if custom_pushdata is False:
                script = OP_FALSE + OP_RETURN + get_op_pushdata_code(dest) + dest

                output_block += b'\x00\x00\x00\x00\x00\x00\x00\x00'

            elif custom_pushdata is True:
                # manual control over number of bytes in each batch of pushdata
                if type(dest) != bytes:
                    raise TypeError("custom pushdata must be of type: bytes")
                else:
                    script = (OP_FALSE + OP_RETURN + dest)

                output_block += b'\x00\x00\x00\x00\x00\x00\x00\x00'

        # Script length in wiki is "Var_int" but there's a note of "modern BitcoinQT" using a more compact "CVarInt"
        output_block += int_to_varint(len(script))
        output_block += script

    return output_block

def construct_input_block(inputs):

    input_block = b''
    sequence = SEQUENCE

    for txin in inputs:
        input_block += (
            txin.txid +
            txin.txindex +
            txin.script_len +
            txin.script +
            sequence
        )

    return input_block


def create_p2pkh_transaction(utxosets, outputs, custom_pushdata=False):

    version = VERSION_1
    lock_time = LOCK_TIME
    # sequence = SEQUENCE
    hash_type = HASH_TYPE
    unspents = [Unspent.from_dict(utxo) for utxo in utxosets]
    input_count = int_to_varint(len(unspents))
    output_count = int_to_varint(len(outputs))
    

    output_block = construct_output_block(outputs, custom_pushdata=custom_pushdata)

    # Optimize for speed, not memory, by pre-computing values.
    inputs = []
    for unspent in unspents:
        txid = hex_to_bytes(unspent.txid)[::-1]
        txindex = unspent.txindex.to_bytes(4, byteorder='little')
        amount = unspent.amount.to_bytes(8, byteorder='little')

        inputs.append(TxIn('', 0, txid, txindex, amount))

    hashPrevouts = double_sha256(b''.join([i.txid+i.txindex for i in inputs]))
    hashSequence = double_sha256(b''.join([SEQUENCE for i in inputs]))
    hashOutputs = double_sha256(output_block)

    # scriptCode_len is part of the script.
    for i, txin in enumerate(inputs):
        private_key = bsv(wif=utxosets[i]['PrivateKey'])
        public_key = bytes.fromhex(private_key.public_key)
        public_key_len = len(public_key).to_bytes(1, byteorder='little')

        scriptCode = (OP_DUP + OP_HASH160 + OP_PUSH_20 + address_to_public_key_hash(private_key.address) + OP_EQUALVERIFY + OP_CHECKSIG)
        scriptCode_len = int_to_varint(len(scriptCode))
        to_be_hashed = (
            version +
            hashPrevouts +
            hashSequence +
            txin.txid +
            txin.txindex +
            scriptCode_len +
            scriptCode +
            txin.amount +
            SEQUENCE +
            hashOutputs +
            lock_time +
            hash_type
        )
        hashed = sha256(to_be_hashed)  # BIP-143: Used for Bitcoin SV

        # signature = private_key.sign(hashed) + b'\x01'
        signature = private_key.sign(hashed) + b'\x41'
        
        script_sig = (
            len(signature).to_bytes(1, byteorder='little') +
            signature +
            public_key_len +
            public_key
        )

        inputs[i].script = script_sig
        inputs[i].script_len = int_to_varint(len(script_sig))

    return bytes_to_hex(
        version +
        input_count +
        construct_input_block(inputs) +
        output_count +
        output_block +
        lock_time
    )


def create_transaction(utxosets,output,exchange_address):
    fee = estimate_tx_fee(len(utxosets),2,0.5,True,0)
    input_amount = 0
    for item in utxosets:
        input_amount += item['amount']
    output_amount = output[1]
    leftamount = input_amount - output_amount - fee
    if leftamount > 546:
        outputs = [output,(exchange_address,leftamount)]   #output is tuple
        rawtx = create_p2pkh_transaction(utxosets, outputs)
        utxoset = {}
        utxoset['txid'] = calc_txid(rawtx)
        utxoset['txindex'] = 1
        utxoset['amount'] = leftamount
        utxoset['confirmations'] = 0
        return {'rawtx':rawtx,'utxoset':utxoset,'txid': calc_txid(rawtx),'amount': input_amount-leftamount}.copy()
    else:
        outputs = [output]
        rawtx = create_p2pkh_transaction(utxosets, outputs)
        return {'rawtx':rawtx,'utxoset': None,'txid': calc_txid(rawtx),'amount': input_amount}.copy()
    

    

def sweep(utxosets,address):
    fee = estimate_tx_fee(len(utxosets),1,0.5,True,0)
    input_amount = 0
    for item in utxosets:
        input_amount += item['amount']
    leftamount = input_amount - fee
    outputs = [(address,leftamount)]
    rawtx = create_p2pkh_transaction(utxosets, outputs)
    return {'rawtx':rawtx,'utxoset': None,'txid': calc_txid(rawtx),'amount': input_amount}.copy()




def deserialize_input(rawinput):
    input_count = int(rawinput[:2],16)
    input_list = []
    remain_input = rawinput[2:]
    key_list = ['txid','txindex','script_len','script','sequence']
    for i in range(input_count):
        input_list.append({})
        for key in key_list:
            if key == 'txid':
                input_list[-1][key] = bytes.fromhex(remain_input[:64])[::-1].hex()
                remain_input = remain_input[64:]
            elif key == 'txindex':
                input_list[-1][key] = int.from_bytes(bytes.fromhex(remain_input[:8]), 'little')
                remain_input = remain_input[8:]
            elif key == 'script_len':
                input_list[-1][key] = int(remain_input[:2],16)
                remain_input = remain_input[2:]
            elif key == 'script':
                input_list[-1][key] = remain_input[:input_list[-1]['script_len']*2]
                remain_input = remain_input[input_list[-1]['script_len']*2:]
            elif key == 'sequence':
                input_list[-1][key] = int(remain_input[:8],16)
                remain_input = remain_input[8:]
    return input_list


def get_rawtx_to_pay(sighash_single_rawtx,pay_to_address):
    est_size_of_rawHex = len(sighash_single_rawtx['version']) +\
                         len(sighash_single_rawtx['input']) + \
                        len(int_to_varint(2).hex()) + \
                        len(sighash_single_rawtx["output"]) + \
                        len(sighash_single_rawtx['lock_time']) + \
                        16 + 2 + 50   # amount: 8 bytes  script_len： 1 byte  script: 25bytes
    rawtx_single_json = deserialize_input(sighash_single_rawtx['input'])
    
    input_amount = 0
    for item in rawtx_single_json:
        result = get_tx_by_txid(item['txid'])
        input_amount += int(result['vout'][item['txindex']]['value']*100000000)
    output_amount = int.from_bytes(bytes.fromhex(sighash_single_rawtx['output'][:8]),'little')
    
    amount = int(input_amount - output_amount - est_size_of_rawHex/4)   #fee rate: 0.5sat/B

    output_count = int_to_varint(2)
    output_block = bytes.fromhex(sighash_single_rawtx["output"])
    output_script = (OP_DUP +OP_HASH160 + OP_PUSH_20 + address_to_public_key_hash(pay_to_address)+ OP_EQUALVERIFY + OP_CHECKSIG)
    output_block += (amount).to_bytes(8, byteorder='little')   #satoshi
    output_block += int_to_varint(len(output_script))
    output_block += output_script
    rawtx = ''
    rawtx += sighash_single_rawtx['version']
    rawtx += sighash_single_rawtx['input']
    rawtx += output_count.hex()
    rawtx += output_block.hex()
    rawtx += sighash_single_rawtx['lock_time']

    utxoset = {}
    utxoset['txid'] = calc_txid(rawtx)
    utxoset['txindex'] = 1
    utxoset['amount'] = amount
    utxoset['confirmations'] = 0

    return {'rawtx':rawtx,'utxoset':utxoset,'txid': calc_txid(rawtx),'amount':amount}.copy()

def generate_sighash_single_rawtx(utxosets, changeaddress,authrized_amount):
    unspents = [Unspent.from_dict(utxo) for utxo in utxosets]
    version = VERSION_1
    lock_time = LOCK_TIME
    #sequence = SEQUENCE
    
    
    input_count = int_to_varint(len(unspents))
    
    inputs = []
    total_input_amount = 0
    for unspent in unspents:
        txid = hex_to_bytes(unspent.txid)[::-1]
        txindex = unspent.txindex.to_bytes(4, byteorder='little')
        amount = unspent.amount.to_bytes(8, byteorder='little')
        inputs.append(TxIn('', 0, txid, txindex, amount))
        total_input_amount += unspent.amount  #satoshi
    
    
    
    output_count = int_to_varint(1)
    output_block = b''
    output_script = (OP_DUP +OP_HASH160 + OP_PUSH_20 + address_to_public_key_hash(changeaddress)+ OP_EQUALVERIFY + OP_CHECKSIG)
    output_block += (total_input_amount-authrized_amount).to_bytes(8, byteorder='little')   #satoshi
    output_block += int_to_varint(len(output_script))
    output_block += output_script

    

    hashPrevouts = double_sha256(b''.join([i.txid+i.txindex for i in inputs]))
    hashSequence = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
    # scriptCode_len is part of the script.
    for i, txin in enumerate(inputs):
        if i==0:
            hashOutputs = double_sha256(output_block)
            hash_type = 0x43.to_bytes(4, byteorder='little')  #sighash single
        else:
            hashOutputs = bytes.fromhex('0000000000000000000000000000000000000000000000000000000000000000')
            hash_type = 0x42.to_bytes(4, byteorder='little')  #sighash none

        private_key = bsv(utxosets[i]['PrivateKey'])
        public_key = bytes.fromhex(private_key.public_key)
        public_key_len = len(public_key).to_bytes(1, byteorder='little')
        scriptCode = (OP_DUP + OP_HASH160 + OP_PUSH_20 + address_to_public_key_hash(private_key.address) + OP_EQUALVERIFY + OP_CHECKSIG)
        scriptCode_len = int_to_varint(len(scriptCode))
        to_be_hashed = (
            version +
            hashPrevouts +
            hashSequence +
            txin.txid +
            txin.txindex +
            scriptCode_len +
            scriptCode +
            txin.amount +
            SEQUENCE +
            hashOutputs +
            lock_time +
            hash_type
        )
        hashed = sha256(to_be_hashed)  # BIP-143: Used for Bitcoin SV

        # signature = private_key.sign(hashed) + b'\x01'   sighash ALL  ; single b'\x03' ,NONE b'\x02'
        if i==0:
            signature = private_key.sign(hashed) + b'\x43'
        else:
            signature = private_key.sign(hashed) + b'\x42'

        script_sig = (
            len(signature).to_bytes(1, byteorder='little') +
            signature +
            public_key_len +
            public_key
        )

        inputs[i].script = script_sig
        inputs[i].script_len = int_to_varint(len(script_sig))
        
            
    return {"version": bytes_to_hex(version),
            "input" : bytes_to_hex(input_count + construct_input_block(inputs) ),
            "output" : bytes_to_hex(output_block),
            "lock_time" : bytes_to_hex(lock_time) }

def convert_utxo_format(utxo_from_woc):
    utxo = {}
    utxo['txid'] = utxo_from_woc['tx_hash']
    utxo['txindex'] = utxo_from_woc['tx_pos']
    utxo['amount'] = utxo_from_woc['value']
    utxo['confirmations'] = 0
    return utxo


def confirm_deposit(address):
    result = get_utxo_by_address(address)
    utxosets = [convert_utxo_format(item) for item in result]
    return utxosets
        
