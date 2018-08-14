#! /usr/bin/env python
import uuid
from uuid import UUID
import requests
import json
import sys
import os
import asyncio
import logging

from eth_account.messages import defunct_hash_message
from web3.auto import w3 as web3
from web3 import Web3,HTTPProvider
from web3.middleware import geth_poa_middleware

logging.basicConfig(level=logging.INFO)
w3=Web3(HTTPProvider(os.environ.get('GETH_ADDR','http://geth:8545')))
w3.middleware_stack.inject(geth_poa_middleware,layer=0)

KEYFILE = os.environ.get('KEYFILE','keyfile')
HOST = os.environ.get('POLYSWARMD_ADDR','polyswarmd:31337')
PASSWORD = os.environ.get('PASSWORD','password')
ACCOUNT = '0x' + json.loads(open(KEYFILE,'r').read())['address']
ARTIFACT_DIRECTORY = os.environ.get('ARTIFACT_DIRECTORY','./bounties/')
BOUNTY_DURATION = os.environ.get('BOUNTY_DURATION',25)

logging.debug('using account ' + ACCOUNT + "...")

EXPERT='0x05328f171b8c1463eafdacca478d9ee6a1d923f8'

# Description: File class to hold sufficient data for bounty creation
# TODO: 
class File:
        def __init__(self, name, path):
                self.name = name
                self.path = path+name

class Artifact:
        def __init__(self, file, bid):
                #file object
                self.file = file
                self.uri = ''
                self.bid = bid

        # Description: POST current artifact and store uri
        # Params: self object
        # return: uri string to access artifact
        def postArtifact(self):

                logging.debug("Attempting to post "+ self.file.name)
                response = ''

                params = (('account', ACCOUNT))
                file = {'file': (self.file.name, open(self.file.path, 'rb'))}
                url = 'http://'+HOST+'/artifacts'

                #send post to polyswarmd
                try:
                        response = requests.post(url, files=file)
                except:
                        logging.debug("Error in artifact.postArtifact: ", sys.exc_info())
                        logging.debug(self.file.name +" not posted")
                        sys.exit()

                response = jsonify(response)
                #check response is ok
                if 'status' not in response or 'result' not in response:
                                logging.debug('Missing key in response. Following error received:')
                                logging.debug(response['message'])
                                sys.exit()


                if response['status'] is 'FAIL':
                        logging.debug(response['message'])
                        sys.exit()

                #hold response URI
                logging.debug("Posted to IPFS successfully \n")
                self.uri = response['result']

	#Description: POST self as artifact
        # Params:       Duration - how long to keep bounty active for test
        #                       Amount - 
        # return: artifact file contents
        def postBounty(self, duration,basenonce):
                #create data for post
                headers = {'Content-Type': 'application/json'}
                postnonce = ''
                postnonce = str(basenonce)
                logging.debug('base nonce is ' + postnonce)
                data = dict()
                data['amount']=self.bid
                data['uri']=self.uri
                data['duration']=duration
                
                url = 'http://'+HOST+'/bounties?account='+ACCOUNT+'&base_nonce='+postnonce
                response = ''
                logging.debug('attempting to post bounty: ' + self.uri + ' to: ' + url + '\n*****************************')  
                try:
                        response = requests.post(url, headers=headers, data=json.dumps(data))
                except:
                        logging.debug("Error in artifact.postBounty: ", sys.exc_info())
                        logging.debug(self.file.name +" bounty not posted.")


                logging.debug(response)
                #parse result
                transactions = response.json()['result']['transactions']
                #sign transactions 
                signed = []
                key = web3.eth.account.decrypt(open(KEYFILE,'r').read(), PASSWORD)
                cnt = 0
                for tx in transactions:
                    cnt+=1
                    logging.debug('tx:to= ' +tx['to'].upper())
                    logging.debug('account: ' +ACCOUNT.upper()) 
                    logging.debug('\n\n*****************************\n' + 'TRANSACTION RESPONSE\n')
                    logging.info(tx)
                    logging.debug('******************************\n')


                    s = web3.eth.account.signTransaction(tx, key)
                    raw = bytes(s['rawTransaction']).hex()
                    signed.append(raw)
                logging.debug('***********************\nPOSTING SIGNED TXNs, count #= ' + str(cnt) + '\n***********************\n')
                r = requests.post('http://' + HOST + '/transactions', json={'transactions': signed})
                logging.debug(r.json())
                if r.json()['status'] == 'OK':
                    logging.info("\n\nBounty "+self.file.name+" sent to polyswarmd.\n\n")
                else:
                    logging.warning("BOUNTY NOT POSTED!!!!!!!!!!! CHECK TX")

def jsonify(encoded):
        decoded = '';
        try:
                decoded = encoded.json()
        except ValueError:
                logging.debug('account: ' +ACCOUNT.upper()) 

                sys.exit("Error in jsonify: ", sys.exc_info()[0])
        return decoded


# Description: Posts # of bounties equal to or less than num files we have
# Params: # to post 
# return: array of bounty objects
def postBounties(numToPost, files):
        #hold all artifacts and bounties
        artifactArr = []
        bountyArr = [];
        logging.debug("trying to get nonce")
        nonce=json.loads(requests.get('http://'+HOST + '/nonce?account='+ACCOUNT).text)['result']
        logging.debug("nonce received: "+str(nonce))
        #create and post artifacts 
        for i in range(0, numToPost):
                #stop early if bounties to post is greater than the number of files
                if numToPost > len(files):
                        break;
                tempArtifact = Artifact(files[i], '625000000000000000')
                tempArtifact.postArtifact()
                artifactArr.append(tempArtifact)

        #post bounties
        #artifactList iterator
        numArtifacts = len(artifactArr)
        curArtifact = 0
        for i in range(0, numToPost):
                #loop over artifacts when creating many bounties
                if curArtifact > numArtifacts:
                        curArtifact = 0

                tempBounty = artifactArr[curArtifact]
                #will need to change time to account for 
                tempBounty.postBounty(BOUNTY_DURATION,nonce)
                logging.debug('posted bounty with nonce '+ str(nonce))
                nonce +=2
                bountyArr.append(tempBounty)
                curArtifact+=1
        return bountyArr

# Description: Retrieve files from directories to use as artifacts
# Params:
# return: array of file objects
def getFiles():
        files = []

        for file in os.listdir(ARTIFACT_DIRECTORY):
                tmp = File(file, ARTIFACT_DIRECTORY)
                files.append(tmp)

        return files

def post_transaction(transactions, key):
    signed = []

    for tx in transactions:
        s = web3.eth.account.signTransaction(tx, key)
        raw = bytes(s['rawTransaction']).hex()
        signed.append(raw)

    r = requests.post('http://' + HOST + '/transactions', json={'transactions': signed})

    return r

def sign_state(state, private_key):
    state_hash = defunct_hash_message(text=state)
    signed_state = w3.eth.account.signHash(state_hash, private_key=private_key)

    return signed_state

def gen_state(**kwargs):

    print(kwargs)

    r = requests.post('http://' + HOST + '/offers/state', json=kwargs)
    return (r.json())

def open_offer_channel():
    key = web3.eth.account.decrypt(open(KEYFILE,'r').read(), PASSWORD)

    # create offer channgel
    r = requests.post('http://' + HOST + '/offers?account=' + ACCOUNT, json={'ambassador': ACCOUNT, 'expert': EXPERT, 'settlementPeriodLength': 100})
    transactions = (r.json()['result']['transactions'])
    offer_info = post_transaction(transactions, key).json()['result']['offers_initialized'][0] # TODO fix 0??
    logging.debug(offer_info)

    guid = str(UUID(int=offer_info['guid'], version=4))

    msig = offer_info['msig']
    
    # set communication uri
    r = requests.post('http://' + HOST + '/offers/' + str(uuid.uuid4()) + '/uri?account=' + ACCOUNT, json={'websocketUri': 'ws//:' + HOST + '/messages'})
    transactions = (r.json()['result']['transactions'])
    logging.debug(transactions)
    logging.debug(post_transaction(transactions, key).json())

    # TODO fix guid int issue
    state = gen_state(close_flag=1, nonce=0, ambassador=ACCOUNT, expert=EXPERT, msig_address=msig, ambassador_balance=30, expert_balance=0, guid=str(offer_info['guid']), offer_amount=1)['result']['state']

    sig = sign_state(state, key)

    # open channel to be joined
    r = requests.post('http://' + HOST + '/offers/' + str(uuid.uuid4()) + '/open?account=' + ACCOUNT, json={'r':web3.toHex(sig.r), 'v':sig.v, 's':web3.toHex(sig.s), 'state': state})
    transactions = (r.json()['result']['transactions'])
    post_transaction(transactions, key)


if __name__ == "__main__":
        # TODO: Create cli option to select offers or bounties        
        open_offer_channel()

        #default bounties to post
        numBountiesToPost = 2

        #if an int is used in cmd arg then use that as # bounties to post
        if (len(sys.argv) is 2):
                if isinstance(sys.argv[1], int):
                        numBountiesToPost = sys.argv[1]


        logging.debug("\n\n********************************")
        logging.debug("OBTAINING FILES")
        logging.debug("********************************")
        fileList = getFiles()
        if numBountiesToPost<10:
            logging.debug(os.listdir(ARTIFACT_DIRECTORY))
        logging.debug("\n\n******************************************************")
        logging.debug("CREATING "+ str(numBountiesToPost) + "BOUNTIES")
        logging.debug("********************************************************")
        bountyList = postBounties(numBountiesToPost, fileList)
        logging.debug( str(bountyList) )
        logging.debug("\n\n********************************")
        logging.debug("FINISHED BOUNTY CREATION, EXITING AMBASSADOR")
        logging.debug("********************************\n\n")
        sys.exit(0)

