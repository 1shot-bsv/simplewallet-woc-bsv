from urllib.request import urlopen
from urllib.request import Request
import json
import certifi
import os

os.environ['SSL_CERT_FILE'] = certifi.where()

def post_data(url,obj):
    method = "POST"
    headers = {"Content-Type" : "application/json"}

    json_data = json.dumps(obj).encode("utf-8")

    request = Request(url, data=json_data, method=method, headers=headers)
    with urlopen(request) as response:
        response_body = json.loads(response.read())
    return response_body

def get_data(url):
    with urlopen(url) as response:
        result = json.loads(response.read())
    return result

def get_tx_by_txid(txid):
    result = get_data('https://api.whatsonchain.com/v1/bsv/main/tx/hash/' + txid)
    return result

def broadcast_tx(rawtx):
    #result = post_data('https://api.whatsonchain.com/v1/bsv/main/mapi/ab398390/tx',{"rawtx":rawtx})
    result = post_data('https://api.metasv.com/v1/merchants/tx/broadcast',{'rawHex':rawtx})
    return result

def get_utxo_by_address(address):
    result = get_data('https://api.whatsonchain.com/v1/bsv/main/address/'+address+'/unspent')
    return result

