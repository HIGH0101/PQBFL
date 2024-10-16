from web3 import Web3
from eth_account import Account
from eth_account.messages import *
from eth_keys import keys
from eth_utils import decode_hex

from eth_account._utils.legacy_transactions import serializable_unsigned_transaction_from_dict
from eth_account._utils.signing import to_standard_v
from eth_account.datastructures import SignedMessage

from pqcrypto.kem import kyber768 

from Crypto.Protocol.DH import key_agreement
from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import ECC
from Crypto.Hash import SHAKE128, SHA384
from Crypto.Cipher import AES
from Crypto.Util.number import *


import socket, pickle

import json
import tarfile, io ,gzip
import os, sys,time, ast
import hashlib

import os 
import train_model


def kdf(x):
        return SHAKE128.new(x).read(32)


def wrapfiles(eth_address, *files):
    tar_buffer = io.BytesIO()  # Create an in-memory TAR archive
    with tarfile.open(fileobj=tar_buffer, mode='w') as tar:  # Create a tarfile object
        for file_name, file_data in files:
            file_info = tarfile.TarInfo(name=file_name) # Add the file to the archive
            file_info.size = len(file_data)
            tar.addfile(file_info, io.BytesIO(file_data))   
    tar_data = tar_buffer.getvalue()  # Get the TAR archive content as bytes
    return tar_data


def unwrap_files(tar_data):
    extracted_files = {}    # dictionary to hold the extracted files
    tar_buffer = io.BytesIO(tar_data)
    with tarfile.open(fileobj=tar_buffer, mode='r') as tar:
        for item in tar.getmembers(): # Iterate through the file items of the tarfile
            file = tar.extractfile(item)
            if file is not None:
                extracted_files[item.name] = file.read()
    return extracted_files


def unzip(gzip_data):
    with gzip.GzipFile(fileobj=io.BytesIO(gzip_data)) as gz_file:
        tar_data = gz_file.read()
    return tar_data


def encrypt_data(key,msg):
    nonce = os.urandom(8)
    crypto = AES.new(key, AES.MODE_CTR, nonce=nonce)
    model_ct = crypto.encrypt(msg)
    encrypted= nonce + model_ct
    return encrypted

def decrypt_data(key,cipher):
    nonce = cipher[:8]
    crypto = AES.new(key, AES.MODE_CTR, nonce=nonce)
    dec = crypto.decrypt(cipher[8:])
    return dec

def hash_data(data):
    hashed_data=hashlib.sha256(data).hexdigest()
    return hashed_data

def pubKey_from_tx(tx_hash):
    tx = w3.eth.get_transaction(tx_hash)
    v = tx['v']
    r = int(tx['r'].hex(), 16)
    s = int(tx['s'].hex(), 16)
    unsigned_tx = serializable_unsigned_transaction_from_dict({     # Reconstruct the unsigned transaction
        'nonce': tx['nonce'],
        'gasPrice': tx['gasPrice'],
        'gas': tx['gas'],
        'to': tx['to'],
        'value': tx['value'],
        'data': tx['input']
    })
    tx_hash = unsigned_tx.hash()    
    standard_v = to_standard_v(v) # Convert v value to standard
    signature = keys.Signature(vrs=(standard_v, r, s))
    public_key = signature.recover_public_key_from_msg_hash(tx_hash)     # Recover the public key from the signature
    return public_key

def sign_data(msg, Eth_private_key):
    encoded_ct = encode_defunct(msg)
    signed_ct = w3.eth.account.sign_message(encoded_ct, private_key=Eth_private_key)
    message_hash =signed_ct.messageHash
    r_bytes = long_to_bytes(signed_ct.r)
    s_bytes  = long_to_bytes(signed_ct.s)
    v_bytes  = long_to_bytes(signed_ct.v)
    sign_bytes = signed_ct.signature
    signed_msg = message_hash + r_bytes + s_bytes  + v_bytes  + sign_bytes
    return signed_msg

def verify_sign(signed_data,msg,pubkey):
    # recover signature from signature data recieved
    msg_hash = signed_data[:32]
    r_sign = bytes_to_long(signed_data[32:64])
    s_sign = bytes_to_long(signed_data[64:96])
    v_sign = bytes_to_long(signed_data[96:97])
    sign_bytes = signed_data[97:]
    signature = SignedMessage( messageHash=msg_hash,r=r_sign,s=s_sign,v=v_sign,signature=sign_bytes)
    '''
    # Signature verification  
    key = ECC.import_key(pubkey)
    verifier = DSS.new(key, 'fips-186-3')
    try:                # verify signature of client's public Keys
        verifier.verify(msg, signature)
    except ValueError:
        print("The message is not authentic.")
    '''

# Register the client
def register_client(hash_epk,Project_id):   
    try:
        Call_reg = contract.functions.registerClient(hash_epk,int(Project_id)).transact({'from': ETH_address}) # Send a registration transaction
        receipt = w3.eth.wait_for_transaction_receipt(Call_reg)
        gas_used=receipt['gasUsed']
        tx_registration=receipt['transactionHash'].hex()
        logs = receipt['logs']
        log_data_bytes=logs[0]['data']

        project_id_bytes = log_data_bytes[32:64]  # Extract the segment where the initial score is stored with padding
        project_id = int.from_bytes(project_id_bytes[-1:], byteorder='big', signed=True)
        initial_score_bytes = log_data_bytes[64:96]  # Extract the segment where the initial score is stored with padding
        initial_score = int.from_bytes(initial_score_bytes[-1:], byteorder='big', signed=True)

        # The offset is a 32-byte integer, but the actual content starts after this 32-byte length indicator.
        offset = int.from_bytes(log_data_bytes[96:128], byteorder='big')
        epk_len = int.from_bytes(log_data_bytes[offset:offset+32], byteorder='big')  # Length of the publicKey
        epk_bytes = log_data_bytes[offset+32:offset+32+epk_len]  # Extract publicKey using its length
        onchain_epk = epk_bytes.decode('utf-8')  # Assuming the public key is ASCII/UTF-8 encoded
        assert onchain_epk==hash_epk, 'epk placed on the chain is not same as generated epk !!'
        print('registertion on contract completed successfully')
        print(f'    Tx: {tx_registration}')
        print(f'    Your Address: {ETH_address}')
        print(f'    Project ID: {project_id}')
        print(f'    Gas: {gas_used} Wei')
        print(f'    Initial Score: {initial_score}')
        print(f'    PublicKey: {onchain_epk}')
        print('-'*75)
    except Exception as e:   
        if "Registration completed" in str(e):  # Check if the error is due to the registration being completed
            print("The project has reached its limit for client registrations. No more registrations are accepted.")
            sys.exit()
        else:
            print(f"An unexpected error occurred: {e}")
            sys.exit()
    return initial_score, tx_registration, project_id


def task_terminated(Task_Id):
    contract = w3.eth.contract(address=contract_address, abi=contract_abi)
    return contract.functions.isProjectTerminated(Task_Id).call()


def listen_for_projcet():
    print("Listen for project...")
    while True:
        try:
            task_event_filter = contract.events.ProjectRegistered.create_filter(fromBlock="latest")
            events = task_event_filter.get_all_entries()
            if events:
                    project_id = events[0]['args']['project_id']
                    cnt_clients = events[0]['args']['cnt_clients']
                    server_address = events[0]['args']['serverAddress']
                    creation_time = time.gmtime(int(events[0]['args']['transactionTime']))
                    initial_model_hash= events[0]['args']['hash_init_model']
                    server_hash_pubkeys = events[0]['args']['hash_keys']
                    tx_hash = events[0]['transactionHash']
                    print('Received a project:')
                    print(f'    Poject ID: {project_id}')
                    print(f'    Server address: {server_address}')
                    print(f'    required client count: {cnt_clients}')
                    print(f'    Time: {time.strftime("%Y-%m-%d %H:%M:%S (UTC)", creation_time)}')
                    print(f'    Hash_pubkeys: {server_hash_pubkeys}')
                    print('-'*75)
                    break
        except Exception as e:
            print(f"Error occurred while fetching events: {e}")
            break
    return tx_hash, project_id,server_address, cnt_clients, initial_model_hash, server_hash_pubkeys        


def listen_for_task(timeout): # Wait for a task to be published
    print("Listen for task...")
    start_time = time.time()
    Task_id = Hashed_model = round = hash_keys=project_id =server_address=D_t=0  # Initialize with default value

    while True:
        try:
            '''
            # Fetch historical events (adjust the block range as needed)
            from_block = 0  # Start from block 0 (or any other appropriate block number)
            to_block = 'latest'  # Fetch events up to the latest block
            task_event_filter = contract.events.TaskPublished.create_filter(fromBlock=from_block, toBlock=to_block)
            events = task_event_filter.get_all_entries()

            # Check for new events if no historical events found
            if not events:
                task_event_filter = contract.events.TaskPublished.create_filter(fromBlock="latest")
                events = task_event_filter.get_all_entries()
            '''
            task_event_filter = contract.events.TaskPublished.create_filter(fromBlock="latest")
            events = task_event_filter.get_all_entries()
            if events:
                round = events[0]['args']['round']
                Task_id = events[0]['args']['taskId']
                server_address = events[0]['args']['serverAddress']
                Hashed_model = events[0]['args']['HashModel']
                hash_keys = events[0]['args']['hash_keys']
                project_id=events[0]['args']['project_id'] 
                #ipfs_address = events[0]['args']['ipfsAddress']
                creation_time = time.gmtime(int(events[0]['args']['creationTime']))
                D_t=events[0]['args']['DeadlineTask']            
                if registered_id_p==project_id:
                    print('Received a published task:')
                    print(f'    Task ID: {Task_id}')
                    print(f'    Project ID: {project_id}')
                    print(f'    Server address: {server_address}')
                    print(f'    Time: {time.strftime("%Y-%m-%d %H:%M:%S (UTC)", creation_time)}')
                    print(f'    Deadline task: {time.strftime("%Y-%m-%d %H:%M:%S (UTC)", D_t )}')
                    print('-'*75)
                    break
            elapsed_time = time.time() - start_time
            if elapsed_time >= timeout:   
                break
            time.sleep(1)  # Sleep for 1 second and check again
        except Exception as e:
            print(f"Error occurred while fetching events: {e}")
            break
    return round,Task_id, Hashed_model,hash_keys,project_id , server_address,D_t


def update_model_Tx(r, Hash_model,hash_ct_epk,Task_id,project_id):
    tx_hash = contract.functions.updateModel(r, Hash_model,hash_ct_epk,Task_id,project_id).transact({'from': ETH_address})
    tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    gas_used=tx_receipt['gasUsed']
    tx_update=tx_receipt['transactionHash'].hex()
    print('-'*75)
    print('Local model updated successfully')
    print(f'    Tx: {tx_update}')
    print(f'    Gas: {gas_used} Wei')
    print('-'*75)
    return tx_update


def listen_for_feedback(client_address): 
    print("Waiting for feedback...")
    while True:
        filter = contract.events.FeedbackProvided.create_filter(fromBlock="latest")      # Create a filter for the feedback event
        feedback_events = filter.get_all_entries()
        #feedback=filter.get_all_entries()
        #print("feed=", feedback_events)
        for feedback in feedback_events: # Iterate through the events and filter by client address
            event_client_address = feedback['args']['clientAddress']  # Assuming the event contains `clientAddress`

            if event_client_address == client_address: # Only process feedback intended for this specific client
                accepted = feedback['args']['accepted']
                task_id = feedback['args']['taskId']
                round = feedback['args']['round']
                tx_hash = feedback['transactionHash'].hex()  # Get transaction hash
                project_id = feedback['args']['project_id']
                T = feedback['args']['terminate']
                score_change = feedback['args']['scoreChange']
                server_addr = feedback['args']['serverId']
                print('Feedback model received:')
                print(f'    Tx: {tx_hash}')
                print(f'    Status: {accepted}')
                print(f'    Score: {score_change}')
                print(f'    Time: {time.strftime("%Y-%m-%d %H:%M:%S (UTC)", time.gmtime())}')
                print(f'    Server address: {server_addr}')
                print('-'*75)
                return project_id, T, score_change
        time.sleep(1) # Small sleep to avoid overwhelming the blockchain with event polling



if __name__ == "__main__":

    try:      # Connect to the local Ganache blockchain
        ganache_url = "http://127.0.0.1:7545"  
        w3 = Web3(Web3.HTTPProvider(ganache_url))
        print(f"Client connected to blockchain (Ganache) successfully\n")
    except Exception as e:
        print("An exception occurred in connecting to blockchain (Ganache) or offchain:", e)
        exit()

    Eth_private_key=sys.argv[1]
    #Eth_private_key = "0xf69cf2ef85af57a8e559885de18d0fb830fbd282098fc708a8505dbdbc1111e3"  			# Replace with the client's private key
    contract_address = sys.argv[2] 
    #contract_address = "0xc37eE4E9E44d89099C87d4272fa7f574b0C9CDe7"   # Replace with the deployed contract address
    num_epochs=int(sys.argv[3])
    #num_epochs=4

    account = Account.from_key(Eth_private_key)
    ETH_address = account.address

    script_dir = os.path.dirname(os.path.abspath(__file__))
    main_dir = os.path.dirname(script_dir)     # Get the path to the parent directory of the script

    with open(main_dir+"/contract/contract-abi.json", "r") as abi_file:
        contract_abi = json.load(abi_file)      # Load ABI from file
    contract = w3.eth.contract(address=contract_address, abi=contract_abi)  # Create a contract instance

    Tx_r, Project_id,server_address,cnt_clients, initial_model_hash, hash_pubkeys=listen_for_projcet()

    esk_a = ECC.generate(curve='p256')      # client's (Alice) private key ECDH 
    epk_a = bytes(esk_a.public_key().export_key(format='PEM'), 'utf-8')

    time.sleep(0.5)
    ini_score, Tx_r , registered_id_p = register_client(hash_data(epk_a), Project_id)         # Register to model training

    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 65432))

    hello_msg='Hello!, my ETH address: ' + ETH_address
    client_socket.send(hello_msg.encode('utf-8'))
    data= client_socket.recv(4096)
    session_id= str(data)[2:-1].split(':')[1]

# recive public keys of server
    msg={}
    msg['Session ID']=session_id
    msg["pubkey_req"]='pubkeys please'
    msg_json=json.dumps(msg)
    client_socket.send(msg_json.encode('utf-8'))  # send request for public keys
    data = client_socket.recv(4096)      
    received_data = json.loads(data.decode('utf-8'))
    epk_b_pem = bytes.fromhex(received_data['epk_b_pem'])
    kpk_b= bytes.fromhex(received_data['kpk_b'])
    assert hash_data(kpk_b+epk_b_pem) == hash_pubkeys, "on-chain and off-chain pub keys are not match :("     
    #verify_sign(signature, kpk_b+epk_b_pem, pubKey_from_tx(Tx_r))  # verify recieved kpk_b and epk_b signature
    epk_b = ECC.import_key(epk_b_pem) 
    ct, ss_k = kyber768.encrypt(kpk_b)  

    msg['epk_a_pem']=epk_a.hex()
    msg['ciphertext']=ct.hex()
    msg["pubkey_req"]='none'
    msg_json = json.dumps(msg)
    client_socket.send(msg_json.encode('utf-8'))     # send ct and public key
    client_socket.close()  

    ss_e = key_agreement(eph_priv=esk_a, eph_pub=epk_b, kdf=kdf)    # ECDH shared secret 
    SS = ss_k + ss_e     # (ss_k||ss_e) 
    salt_a=b'\0'*32  # asymmetric salt
    salt_s = b'\0'*32    # symmetric salt
    Root_key= HKDF(SS, 32, salt_a, SHA384, 1)     # assymmetric ratcheting 
    chain_key=Root_key
    chain_key, Model_key = HKDF(Root_key, 32, salt_s, SHA384, 2)   # first symmetric ratcheting

    timeout=120
    Local_model_info={}
    while True:              # several times contributions (round)
        hash_ct_epk_a='None'
        r, Task_id, Hash_model,hash_pubkeys,project_id, server_eth_addr, D_t= listen_for_task(timeout)          # Wait to Task publish 

        if task_terminated(Task_id):   # check contract that task has not finished 
            print(f"Server has already terminated Task id: {Task_id} ")
            break
        if Task_id==0:
            print(f"No new task received within the timeout period ({timeout} seconds). Exit")
            break     
        print('=============')      
        print(f"Round {r}")
        print('=============')
        if hash_pubkeys !='None':    # recieve a assymmetric ratcheting trigger
            esk_a = ECC.generate(curve='p256')      # client's (Alice) private key ECDH 
            epk_a = bytes(esk_a.public_key().export_key(format='PEM'), 'utf-8')

            client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            client_socket.connect(('127.0.0.1', 65432))
            msg={}
            msg["pubkey_req"]='pubkeys please'
            msg['Session ID']=session_id
            msg_json=json.dumps(msg)

            client_socket.send(msg_json.encode('utf-8'))
            data = client_socket.recv(4096)
            received_data = json.loads(data.decode('utf-8'))
            epk_b_pem = bytes.fromhex(received_data['epk_b_pem'])
            kpk_b= bytes.fromhex(received_data['kpk_b'])
            epk_b = ECC.import_key(epk_b_pem) 
            assert hash_data(kpk_b+epk_b_pem) == hash_pubkeys, "on-chain and off-chain pub keys are not match :("  
            ct, ss_k = kyber768.encrypt(kpk_b)
            hash_ct_epk_a=hash_data(ct+epk_a)    

            msg['epk_a_pem']=epk_a.hex()
            msg['ciphertext']=ct.hex()
            msg_json = json.dumps(msg)
            client_socket.send(msg_json.encode('utf-8')) # send ct and public key
            ss_e = key_agreement(eph_priv=esk_a, eph_pub=epk_b, kdf=kdf)    # ECDH shared secret 
            SS = ss_k + ss_e     # (ss_k||ss_e) 
            Root_key= HKDF(SS, 32, salt_a, SHA384, 1)      # assymmetric ratcheting  
            chain_key=Root_key
            client_socket.close()
  
        # load model info (recieved:)
        time.sleep(0.8)
        Recieved_msg=open(main_dir + f"/server/files/wrapped_data_{ETH_address}.tar.gz",'rb').read()  
        unwrapped_msg=unwrap_files(unzip(Recieved_msg))
        signature=unwrapped_msg['signature.bin']
        global_model_ct=unwrapped_msg['global_model.enc']
        verify_sign(signature, global_model_ct, pubKey_from_tx(Tx_r))
        dec_wrapfile=decrypt_data(Model_key,global_model_ct)
        unwraped=unwrap_files(dec_wrapfile)
        task_info=unwraped['task_info.json']
        global_model=unwraped['Model.pth']
        assert Hash_model==hash_data(global_model), "Hash recieved on-chain and off-chain models are not match :("    

        
    # Train_local_model
        print("Start training...")
        train_model.train(num_epochs,ETH_address)   # train and save the model in files folder
        Local_model= open(main_dir + f"/participant/files/local_model_{ETH_address}.pth",'rb').read()     
        Hash_model = hash_data(Local_model)

        #build local model information
        Local_model_info['Round number'] = r
        Local_model_info['Model hash'] = Hash_model
        Local_model_info['Project id'] = project_id
        Local_model_info['Task id'] = Task_id

        Tx_u = update_model_Tx(r, Hash_model,hash_ct_epk_a,Task_id, project_id)

        Local_model_info['Update Tx'] = Tx_u
        json_info = json.dumps(Local_model_info, indent=4)
        wraped_model_info=wrapfiles(ETH_address, ('Local_model_info.json',json_info.encode()), (f'local_model_{ETH_address}.pth',Local_model))  # Wrap Model and info files 
        model_ct=encrypt_data(Model_key, wraped_model_info)
        signed_ct=sign_data(model_ct, Eth_private_key)

        # save (send:) wrapped files in zip to server 
        wraped_msg=wrapfiles(ETH_address, ('signature.bin',signed_ct), ('Local_model.enc', model_ct))
        with gzip.open(main_dir + f"/server/files/wrapped_data_{ETH_address}.tar.gz", 'wb') as gzip_file:
            gzip_file.write(wraped_msg)
        project_id_fb, T, score=listen_for_feedback(ETH_address)
        if T:
            if project_id_fb==project_id:
                print(f'server terminated the project id {project_id_fb}')
                break
        chain_key, Model_key = HKDF(chain_key, 32, salt_s, SHA384, 2)    # symmetric ratcheting
        salt_s= (bytes_to_long(salt_s)+1).to_bytes(32, byteorder='big')        #  salt_s  increment 
        salt_a= (bytes_to_long(salt_a)+1).to_bytes(32, byteorder='big')        #  salt_a  increment 