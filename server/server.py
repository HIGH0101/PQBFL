from web3 import Web3
from web3.middleware import geth_poa_middleware
from eth_account import Account
from eth_keys import keys
#from eth_utils import decode_hex
from eth_account.messages import encode_defunct
from eth_account.datastructures import SignedMessage

from eth_account._utils.legacy_transactions import serializable_unsigned_transaction_from_dict
from eth_account._utils.signing import to_standard_v

#import ipfs_api
import tarfile, io ,gzip
#from pqcrypto.sign  import dilithium2 ,sphincs_sha256_128f_simple   #.dilithium2 import generate_keypair,sign,verify
from pqcrypto.kem import kyber768 

import socket, pickle

from Crypto.Protocol.DH import key_agreement
from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import ECC
from Crypto.Hash import SHAKE128, SHA384
from Crypto.Cipher import AES
from Crypto.Util.number import *
#from Crypto.Signature import DSS

import tenseal as ts
import json
import hashlib
import os, sys, time
#import tempfile
import aggregate
from threading import *
from queue import Queue
import torch


#from utils import wrapfiles
#from Utils import utils
#import utils


def kdf(x):
        return SHAKE128.new(x).read(32)

def wrapfiles( *files):   # input sample: ('A.bin', A), ('B.enc',B)
    tar_buffer = io.BytesIO()  # Create an in-memory TAR archive
    # Create a tarfile object
    with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
        for file_name, file_data in files:
            # Add the file to the archive
            file_info = tarfile.TarInfo(name=file_name)
            file_info.size = len(file_data)
            tar.addfile(file_info, io.BytesIO(file_data))
    
    tar_data = tar_buffer.getvalue()  # Get the TAR archive content as bytes
    return tar_data

def unwrap_files(tar_data):
    extracted_files = {}
    # Create an in-memory byte stream from the tar_data
    tar_buffer = io.BytesIO(tar_data)
    with tarfile.open(fileobj=tar_buffer, mode='r') as tar:
        # Iterate through the members of the tarfile
        for member in tar.getmembers():
            file = tar.extractfile(member)
            if file is not None:
                extracted_files[member.name] = file.read()
    return extracted_files

def unzip(gzip_data):
    with gzip.GzipFile(fileobj=io.BytesIO(gzip_data)) as gz_file:
        tar_data = gz_file.read()
    return tar_data

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
    # Signature verification  
    #key = ECC.import_key(pubسkey)
    #verifier = DSS.new(key, 'fips-186-3')
    #try:                # verify signature of client's public Keys
    #    verifier.verify(msg, signature)
    #except ValueError:
    #    print("The message is not authentic.")


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

def scale_HE_encrypted(aggregated_weights, num_clients,HE_algorithm,scaling_factor=1000000):

    if HE_algorithm=='BFV':
        for name in aggregated_weights:
            aggregated_weights[name] *= scaling_factor  # Integer scaling (multiplying by large factorto make division integer-friendly)
            aggregated_weights[name] *= int(scaling_factor / num_clients)  # Integer-safe division (approximate)
    elif HE_algorithm=='CKKS':
        scaling_factor = 1 / num_clients
        for name in aggregated_weights:
            aggregated_weights[name] *= num_clients  
            #aggregated_weights[name] = aggregated_weights[name].rescale() # Rescale to manage the scale growth in CKKS
    return aggregated_weights


def serialize_data(encrypted_model):
    # Serialize each encrypted weight
    serialized_weights = {}
    for name, enc_weight in encrypted_model.items():
        serialized_weights[name] = enc_weight.serialize()  # serialize only the weights, not context
    # Convert to bytes using pickle
    buffer = io.BytesIO()
    pickle.dump(serialized_weights, buffer)
    return buffer.getvalue()


def register_project(project_id,cnt_clients_req, hash_init_model, hash_keys):
    contract = w3.eth.contract(address=contract_address, abi=contract_abi)
    if not contract.functions.isProjectTerminated(project_id).call():
        nonce = w3.eth.get_transaction_count(Eth_address)

        #Initial_model_hash=hash_data(Initial_model)
        transaction = contract.functions.registerProject(project_id,cnt_clients_req,hash_init_model,hash_keys).build_transaction({
            'from': Eth_address,
            'gas': 2000000,
            'gasPrice': w3.to_wei('50', 'gwei'),
            'nonce': nonce,
        })
        signed_transaction = w3.eth.account.sign_transaction(transaction, Eth_private_key)
        tx_sent = w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
        receipt = w3.eth.wait_for_transaction_receipt(tx_sent)
        gas_used=receipt['gasUsed']
        deployment_block = receipt.blockNumber
        tx_registration = receipt['transactionHash'].hex()
        print(f'Project Registeration on contract:')
        print(f'    Tx_hash: {tx_registration}')
        print(f'    Gas: {gas_used} Wei')
        print(f'    Project ID: {project_id}')
        print(f'    required client count: {cnt_clients_req}') 
        print(f'    Initial model hash: {hash_init_model}')
        print(f'    Pubic keys hash: {hash_keys}')
        print('-'*75)
        return tx_registration
    else:
        print(f"Project {project_id} is already completed on the contract. Please Change the Project ID. Exit...")
        sys.exit()  # Exit the code if the task is already terminated
    

def wait_for_clients(event_filter, event_queue):
    print('waiting for clients...')
    # Add PoA middleware for Ganache (if needed)
    if geth_poa_middleware not in w3.middleware_onion:
        w3.middleware_onion.inject(geth_poa_middleware, layer=0)

    # Create an instance of the contract with the ABI and address
    contract = w3.eth.contract(address=contract_address, abi=contract_abi)
    event_filter = contract.events.ClientRegistered.create_filter(fromBlock="latest")          # Get events since the last checked block
    
    # Loop to listen for events
    while True:
        events = event_filter.get_new_entries()
        if events:
            for event in events:
                event_queue.put(event)


def finish_tash(task_id, project_id):
    contract = w3.eth.contract(address=contract_address, abi=contract_abi)
    nonce = w3.eth.get_transaction_count(Eth_address)
    
    # Build the transaction with task_id and project_id
    transaction = contract.functions.finishTask(task_id, project_id).build_transaction({
        'from': Eth_address,
        'gas': 2000000,  # Adjust the gas limit based on your contract's needs
        'gasPrice': w3.to_wei('50', 'gwei'),
        'nonce': nonce,
    })
    # Sign and send the transaction
    signed_transaction = w3.eth.account.sign_transaction(transaction, Eth_private_key)
    tx_hash = w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
    # Wait for the receipt
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    gas_used = receipt['gasUsed']
    tx_publish = receipt['transactionHash'].hex()

    print(f'Task terminated:')
    print(f'    Tx_hash: {tx_publish}')
    print(f'    Gas: {gas_used} Wei')
    print(f'    Task ID: {task_id}')
    print(f'    Project ID: {project_id}')
    print('-' * 75)

def finish_project(project_id):
    contract = w3.eth.contract(address=contract_address, abi=contract_abi)
    nonce = w3.eth.get_transaction_count(Eth_address)
    # Build the transaction with project_id
    transaction = contract.functions.finishProject(project_id).build_transaction({
        'from': Eth_address,
        'gas': 2000000,  # Adjust the gas limit based on your contract's needs
        'gasPrice': w3.to_wei('50', 'gwei'),
        'nonce': nonce,
    })
    # Sign and send the transaction
    signed_transaction = w3.eth.account.sign_transaction(transaction, Eth_private_key)
    tx_hash = w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
    # Wait for the receipt
    receipt = w3.eth.wait_for_transaction_receipt(tx_hash)
    gas_used = receipt['gasUsed']
    tx_publish = receipt['transactionHash'].hex()
    print(f'Project terminated:')
    print(f'    Tx_hash: {tx_publish}')
    print(f'    Gas: {gas_used} Wei')
    print(f'    Project ID: {project_id}')
    print('-' * 75)



def publish_task(r, Hash_model, hash_keys, Task_id, project_id, D_t):
    contract = w3.eth.contract(address=contract_address, abi=contract_abi)
    nonce = w3.eth.get_transaction_count(Eth_address)
    transaction = contract.functions.publishTask(r,Hash_model, hash_keys, Task_id, project_id, D_t).build_transaction({
        'from': Eth_address,
        'gas': 2000000,
        'gasPrice': w3.to_wei('50', 'gwei'),
        'nonce': nonce,
    })
    signed_tx = w3.eth.account.sign_transaction(transaction, Eth_private_key)
    tx_sent = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_sent)
    gas_used=receipt['gasUsed']
    tx_publish = receipt['transactionHash'].hex()
    print('')
    print(f'Task published round {r}:')
    print(f'    Tx_hash: {tx_publish}')
    print(f'    Gas: {gas_used} Wei')
    print(f'    Task ID: {Task_id}')
    print('-'*75)
    return tx_publish


def listen_for_updates(event_filter, event_queue):
    # Add PoA middleware for Ganache (if needed)
    if geth_poa_middleware not in w3.middleware_onion:
        w3.middleware_onion.inject(geth_poa_middleware, layer=0)

    # Create an instance of the contract with the ABI and address
    contract = w3.eth.contract(address=contract_address, abi=contract_abi)
    event_filter = contract.events.ModelUpdated.create_filter(fromBlock="latest")           # Get events since the last checked block
    # Loop to listen for events
    while True:
        events = event_filter.get_new_entries()
        if events:
            for event in events:
                event_queue.put(event)


def feedback_TX (r, task_id, project_id, client_address, feedback_score,T):
    contract = w3.eth.contract(address = contract_address, abi=contract_abi)
    nonce = w3.eth.get_transaction_count(Eth_address)
    transaction = contract.functions.provideFeedback(r, task_id, project_id, client_address, feedback_score,T).build_transaction({
        'from': Eth_address,
        'gas': 2000000,
        'gasPrice': w3.to_wei('50', 'gwei'),
        'nonce': nonce,
    })
    signed_transaction = w3.eth.account.sign_transaction(transaction, Eth_private_key)
    tx_sent = w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
    receipt = w3.eth.wait_for_transaction_receipt(tx_sent)
    gas_used=receipt['gasUsed']
    tx_feedback = receipt['transactionHash'].hex()
    print(f'Feedback:')
    print(f'      Client address: {client_address}')
    print(f'      Tx_hash: {tx_feedback}')
    print(f'      Gas: {gas_used} Wei')
    print(f'      Task ID: {task_id}')
    print(f'      Score: {task_id}')
    print('-'*75)
    return tx_feedback


def analyze_model (Local_model,Task_id,project_id_update):
    res=True
    Feedback_score=1
    return res, Feedback_score


def aggregate_HE_encrypted(list_of_encrypted_weights):
    aggregated_weights = {}
    # Initialize the aggregated weights dictionary using the first client's encrypted weights
    for name in list_of_encrypted_weights[0]:
        aggregated_weights[name] = list_of_encrypted_weights[0][name].copy()  # Copy the first client's weights
    
    # Iterate over the remaining clients and add their encrypted weights
    for client_weights in list_of_encrypted_weights[1:]:
        for name in client_weights:
            aggregated_weights[name] += client_weights[name]  # Homomorphic addition
    return aggregated_weights




if __name__ == "__main__":

    try:  # Connect to the local Ganache blockchain
        onchain_addr = "http://127.0.0.1:7545"   # (on-chain) address anache_url
        w3 = Web3(Web3.HTTPProvider(onchain_addr))
        print("Server connected to blockchain (Ganache) successfully\n")
    except Exception as e:
        print("An exception occurred in connecting to blockchain (Ganache) or offchain:", e)
        exit()
    offcahin_addr = ('localhost', 65432)          # server (off-chain) address
    server_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    server_socket.setsockopt(socket.SOL_SOCKET, socket.SO_KEEPALIVE, 1)
    server_socket.bind(offcahin_addr)
    server_socket.listen()

    
    Eth_private_key=sys.argv[1]    
    #Eth_private_key = "0x1a4c2d1907441763f50f0a9906a858e369c76395b0f93a640661cbd9437b84d3"  			# Replace with the client's private key
    contract_address = sys.argv[2]
    #contract_address = "0xFAa6d8Bfc6A5c1D96858f179Cc40B49C7Dae52d9"   # Replace with the deployed contract address
    project_id=int(sys.argv[3])   #int(input("Enter a Task ID for registration: "))
    #project_id=1
    round=int(sys.argv[4]) 
    #round=4
    client_req=int(sys.argv[5])     # client requirement count 
    #client_req=2
    HE_algorithm=sys.argv[6]    # Homomorphic encryption activation
    #HE_algorithm='CKKS'

    account = Account.from_key(Eth_private_key)
    Eth_address = account.address   # load the Ethereum account

    script_dir = os.path.dirname(os.path.abspath(__file__))
    main_dir = os.path.dirname(script_dir)  # Get the path to the parent directory of the script
    with open(main_dir+"/contract/contract-abi.json", "r") as abi_file:
        contract_abi = json.load(abi_file)     # Load ABI from file
    contract = w3.eth.contract(address=contract_address, abi=contract_abi)  # Create a contract instance

    if HE_algorithm=='CKKS':
        with open(main_dir + f'/server/keys/CKKS_without_priv_key.pkl', "rb") as f:
            serialized_without_key = pickle.load(f)
        HE_config_without_key = ts.context_from(serialized_without_key)
    elif HE_algorithm=='BFV':
        with open(main_dir + f'/server/keys/BFV_without_priv_key.pkl', "rb") as f:
            serialized_without_key = pickle.load(f)
        HE_config_without_key = ts.context_from(serialized_without_key)
    
# generate and wrap the public keys
    esk_b = ECC.generate(curve='p256')      # Server's (Bob) private key ECDH 
    epk_b = bytes(esk_b.public_key().export_key(format='PEM'), 'utf-8')
    kpk_b,ksk_b=kyber768.generate_keypair()          # Server's (Bob) KEM key pair
    hash_pubkeys = hash_data(kpk_b+epk_b)    # hash of concatinate keys

    msg_keys={}
    msg_keys['epk_b_pem']=epk_b.hex()
    msg_keys['kpk_b']=kpk_b.hex()
    msg_keys_json = json.dumps(msg_keys)
#-------------------------------------------------
    Init_model = b'ipfs://Qm...'
    Hash_model = hash_data(Init_model)
    
    Tx_r =register_project(project_id, client_req, Hash_model, hash_pubkeys)

    registration_queue = Queue()
    block_filter =  w3.eth.filter('latest')
    worker = Thread(target=wait_for_clients, args=(block_filter,registration_queue), daemon=True)
    worker.start()
    clients_dict={}
    registered_cnt=0

# Wait for enough number participants and put their information clients_dict.
    while  registered_cnt < client_req: #True:         
        if not registration_queue.empty():  # onchain registration of clients
            event = registration_queue.get() 
            eth_address = event['args']['clientAddress']
            Tx_r = event['transactionHash'].hex()
            initialScore= event['args']['initialScore']
            project_id= event['args']['project_id']
            h_Key= event['args']['hash_PubKeys']

            clients_dict[eth_address] = {'Session ID':registered_cnt+1,
                                    'score': initialScore, 
                                    'hash_epk': h_Key, 
                                    'registeration Tx': Tx_r}   # For each client             
            
            # Accept a client connection
            client_socket, client_address = server_socket.accept()
            print(f"New connection from {client_address}")            
            recv_hello_msg = client_socket.recv(4096).decode('utf-8')
            if eth_address==recv_hello_msg[24:]:  # bind a session id to each connected client and send
                client_socket.send(('Session ID:' + str(clients_dict[eth_address]['Session ID'] )).encode('utf-8'))

            # Send epk_b and kpk_b to client via off-chain
            recv_msg = json.loads(client_socket.recv(4096).decode('utf-8'))
            if recv_msg["pubkey_req"] == "pubkeys please":
                client_socket.sendall(msg_keys_json.encode('utf-8'))
                data = client_socket.recv(4096)  # Receive epk_a_pem and ct from client via off-chain
                if data is None:
                    print(f"Failed to receive data from client {eth_address}")
                    client_socket.close()
                    continue

            # Process the received Json data construct root, chain and model keys
            received_data = json.loads(data.decode('utf-8'))
            epk_a_pem = bytes.fromhex(received_data['epk_a_pem'])
            ct = bytes.fromhex(received_data['ciphertext']) 
            epk_a = ECC.import_key(epk_a_pem)
            ss_e = key_agreement(eph_priv=esk_b, eph_pub=epk_a, kdf=kdf)    # ECDH shared secret 
            ss_k = kyber768.decrypt(ksk_b, ct)
            SS = ss_k + ss_e        # (ss_k||ss_e) construnct general shared secret 
            salt_a=b'\0'*32    # asymmetric salt
            salt_s = b'\0'*32    # symmetric salt
            Root_key= HKDF(SS, 32, salt_a, SHA384, 1)     #  RK_1 <-- SS + Salt_a  
            chain_key, Model_key = HKDF(Root_key, 32, salt_s, SHA384, 2)
            # Save keys info for each client address
            clients_dict[eth_address]['Hash_ct_epk_a']=hash_data(ct +epk_a_pem) 
            clients_dict[eth_address]['Root key']  = Root_key.hex()
            clients_dict[eth_address]['Model key'] = Model_key.hex()
            clients_dict[eth_address]['Chain key'] = chain_key.hex()
            registered_cnt+=1
            print(f"{registered_cnt}/{client_req} clients connected")
    print('-'*75)

    clients_info = json.loads(json.dumps(clients_dict, indent=4))
    Global_Model=Init_model
    Models=[]
    task_info= {}
    ratchet_renge=2
    for r in range(1,round+1):    

        Task_id=int(str(project_id)+str(r))
        task_info['Round number'] = r
        task_info['Model hash'] = Hash_model
        task_info['Project id'] = project_id
        task_info['Task id'] = Task_id
        task_info['Deadline Task'] = int(time.time()) + 100000

    # Publish Task
        hash_pubkeys='None'
        if r%ratchet_renge==0: # Assymmetric ratcheting condition
            esk_b = ECC.generate(curve='p256')      # Server's (Bob) private key ECDH 
            epk_b = bytes(esk_b.public_key().export_key(format='PEM'), 'utf-8')
            kpk_b,ksk_b=kyber768.generate_keypair()          # Server's (Bob) KEM key pair
            hash_pubkeys = hash_data(kpk_b+epk_b)
            msg_keys['epk_b_pem']=epk_b.hex()
            msg_keys['kpk_b']=kpk_b.hex()
            msg_keys_json = json.dumps(msg_keys)

            Tx_p = publish_task(r, Hash_model, hash_pubkeys, Task_id, project_id, task_info['Deadline Task'])       
            task_info['Publish Tx'] = Tx_p
        else: 
            Tx_p = publish_task(r, Hash_model, hash_pubkeys, Task_id, project_id, task_info['Deadline Task'])    
            task_info['Publish Tx'] = Tx_p

        json_task_info = json.dumps(task_info, indent=4)
        if r!=1 and HE_algorithm!='None':
            wraped_model_info=wrapfiles(('task_info.json',json_task_info.encode()), ('global_HE_model.bin',global_HE_model))  # Wrap  Model and info files 
        else:
            wraped_model_info=wrapfiles(('task_info.json',json_task_info.encode()), ('global_model.pth',Global_Model))  # Wrap  Model and info files 
    # encrypt and sign model for each client     
        for addr in clients_dict:  
            Client_Model_key=bytes.fromhex(clients_dict[addr]['Model key'])
            model_ct=encrypt_data(Client_Model_key, wraped_model_info)
            signed_ct=sign_data(model_ct, Eth_private_key)
            wraped_msg=wrapfiles(('signature.bin',signed_ct), ('global_model.enc',model_ct))
            #save (send:) wrapped files in zip
            with gzip.open(main_dir + f"/server/files/wrapped_data_{addr}.tar.gz", 'wb') as gzip_file:
               gzip_file.write(wraped_msg)
        # update keys in assymetric ratchet       
            if r%ratchet_renge==0:    
                client_socket, client_address = server_socket.accept()
                print(f"New connection for ratcheting from {client_address}")
                recv_msg = json.loads(client_socket.recv(4096).decode('utf-8'))
                if recv_msg["pubkey_req"] == "pubkeys please" and r%ratchet_renge==0:
                    session_id=int(recv_msg["Session ID"])
                    client_socket.sendall(msg_keys_json.encode('utf-8'))
                    data = client_socket.recv(4096)
                    if data is None:
                        print(f"Failed to receive data from client")
                        client_socket.close()
                        continue
                    # Process the received data (assuming it's JSON encoded for simplicity)
                    received_data = json.loads(data.decode('utf-8'))
                    epk_a_pem = bytes.fromhex(received_data['epk_a_pem'])
                    ct = bytes.fromhex(received_data['ciphertext'])
                    matching_addr = [address for address, details in clients_dict.items() if details.get("Session ID") == session_id] #find eth addr based Session ID w
                    clients_dict[matching_addr[0]]['Hash_ct_epk_a']=hash_data(ct + epk_a_pem) 
                    epk_a = ECC.import_key(epk_a_pem)
                    ss_e = key_agreement(eph_priv=esk_b, eph_pub=epk_a, kdf=kdf)    # ECDH shared secret 
                    ss_k = kyber768.decrypt(ksk_b, ct)
                    SS = ss_k + ss_e              # (ss_k||ss_e) construnct general shared secret  
                    Root_key= HKDF(SS, 32, salt_a, SHA384, 1)     #  RK_1 <-- SS + Salt_a
                    clients_dict[matching_addr[0]]['Root key']  = Root_key.hex()

        print(f"Start Round {r}: Waiting for local model updates...") 
        print('='*20)       
        event_queue = Queue()
        block_filter =  w3 .eth.filter('latest')
        worker = Thread(target=listen_for_updates, args=(block_filter,event_queue), daemon=True)
        worker.start()
        client_addrs=[]
        update_dict={}
        cnt_models=0
        T= False
        while True:  # Wait for update model
            if not event_queue.empty():
                print(f'Received {cnt_models+1} Local model update Tx:')
                event = event_queue.get()
                r_update = event['args']['round']
                Task_id_update = event['args']['taskId']
                tx_u = event['transactionHash'].hex()
                project_id_update= event['args']['project_id']
                Client_eth_addr = event['args']['clientAddress']
                Hash_local_model = event['args']['HashModel']
                Hash_ct_epk_a = event['args']['hash_ct_epk']

                if r_update==r and Task_id_update==Task_id and project_id_update==project_id:
                    update_dict[Client_eth_addr]= {'round': r_update, 'Task id':Task_id_update , 
                                                   'Tx_u': tx_u, 'Project id':project_id_update, 
                                                   'Local model hash':Hash_local_model} 
                else:
                    print('information of model is not related to this round or project')  
                print(json.dumps(update_dict[Client_eth_addr], indent=4))

                client_addrs.append(Client_eth_addr)
                
            # Load model info (recieved:) and verification
                time.sleep(0.8)
                if HE_algorithm!='None':
                    time.sleep(3)
                Recieved_msg=open(main_dir + f"/server/files/wrapped_data_{Client_eth_addr}.tar.gz",'rb').read()  
                unwrapped_msg=unwrap_files(unzip(Recieved_msg))
                signature=unwrapped_msg['signature.bin']
                local_model_ct=unwrapped_msg['Local_model.enc']
                verify_sign(signature, local_model_ct, pubKey_from_tx(tx_u))
                client_Model_key=bytes.fromhex(clients_dict[Client_eth_addr]['Model key'])
                dec_wrapfile=decrypt_data(client_Model_key,local_model_ct)
                unwraped=unwrap_files(dec_wrapfile)
                Local_model_info =unwraped['Local_model_info.json']

                if Hash_ct_epk_a!='None':  # Check on-chain and off-chain hash(ct||epk)
                    assert clients_dict[Client_eth_addr]['Hash_ct_epk_a'] == Hash_ct_epk_a  , " off- and on-chain keys  not match :("   

                if HE_algorithm!='None':
                    local_HE_model=unwraped[f'local_HE_model_{Client_eth_addr}.bin']
                    assert Hash_local_model==hash_data(local_HE_model), f" on-chain and off-chain Hash of local model {Client_eth_addr} are not match :("    # این قسمت شاید اضافه باشه چون صحت مدل با امضا هم میشه فهمید
                    cnt_models+=1  # save local model for using in aggregation
                    open(main_dir + f"/server/files/models/local_HE_model_{Client_eth_addr}.bin",'wb').write(local_HE_model)
                    Feedback_score=0  
                    Tx_f=feedback_TX (r,Task_id, project_id, Client_eth_addr, Feedback_score, T)    
                else:
                    Local_model=unwraped[f'local_model_{Client_eth_addr}.pth']
                    assert Hash_local_model==hash_data(Local_model), f" on-chain and off-chain Hash of local model {Client_eth_addr} are not match :("    # این قسمت شاید اضافه باشه چون صحت مدل با امضا هم میشه فهمید
                    Res, Feedback_score = analyze_model(Local_model,Task_id_update,project_id_update)
                    if Res:
                        cnt_models+=1  # save local model for using in aggregation
                        open(main_dir + f"/server/files/models/local_model_{Client_eth_addr}.pth",'wb').write(Local_model)  
                        Tx_f=feedback_TX (r,Task_id, project_id, Client_eth_addr, Feedback_score, T)    

                if cnt_models==registered_cnt:
                    if HE_algorithm!='None':
                        HE_aggregated=aggregate.aggregate_models(client_addrs,HE_algorithm) 
                        Scaled_model=scale_HE_encrypted(HE_aggregated,cnt_models,HE_algorithm)
                        global_HE_model=serialize_data(Scaled_model)
                        Hash_model = hash_data(global_HE_model)
                        open(main_dir + f"/server/files/global_HE_model.bin",'wb').write(global_HE_model) 
                    else:    
                        normal_aggregated,accuracy=aggregate.aggregate_models(client_addrs,HE_algorithm) 
                        #Hash_model = hash_data(normal_aggregated)
                        torch.save(normal_aggregated.state_dict(), main_dir+'/server/files/global_model.pth')
                        print('*'*40+f'\nTest Accuracy on global model: {accuracy:.4f}\n'+'*'*40)
                    break
            else:
                time.sleep(1)

        # Symmetric ratcheting of model-key for each client
        for addr in clients_dict:   
            chain_key=bytes.fromhex(clients_dict[addr]['Chain key'])  # get previous chain key
            if Hash_ct_epk_a=='None':
                chain_key, Model_key = HKDF(chain_key, 32, salt_s, SHA384, 2)
            else:
                Root_key=bytes.fromhex(clients_dict[addr]['Root key'])
                chain_key, Model_key = HKDF(Root_key, 32, salt_s, SHA384, 2)
            clients_dict[addr]['Model key'] = Model_key.hex()
            clients_dict[addr]['Chain key'] = chain_key.hex()  # update keys of dict of clients
        salt_s=(bytes_to_long(salt_s)+1).to_bytes(32, byteorder='big')        #  salt_s  increment 
        salt_a=(bytes_to_long(salt_a)+1).to_bytes(32, byteorder='big')        #  salt_a  increment            

finish_tash(Task_id,project_id) # transaction termination for recording on blockchain
finish_project(project_id)

