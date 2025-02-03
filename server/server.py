"""
Created on Tue Jan  2 14:18:41 2024

@author: HIGHer
""" 
from web3 import Web3
from web3.middleware import geth_poa_middleware
from eth_account import Account

from collections import namedtuple
from pqcrypto.kem import kyber768 

from Crypto.Protocol.DH import key_agreement
from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA384
from Crypto.Util.number import *

import socket, pickle
import tenseal as ts
import os, sys, time,json

import aggregate
from threading import *
from queue import Queue
import torch


from simple_cnn_config import SimpleCNN
sys.path.append(os.path.dirname(os.path.dirname(os.path.abspath(__file__))))
from utils import *




def generate_keys():
    KeyPair = namedtuple('KeyPair', ['pk', 'sk'])
    ecdh_priv = ECC.generate(curve='p256')  # ECDH private key
    ecdh_pub = bytes(ecdh_priv.public_key().export_key(format='PEM'), 'utf-8')  # ECDH public key
    kyber_pub, kyebr_priv = kyber768.generate_keypair()  # Kyber key pair
    ecdh_keys = KeyPair(pk =ecdh_pub, sk =ecdh_priv)
    kyber_keys = KeyPair(pk=kyber_pub, sk=kyebr_priv)
    return ecdh_keys, kyber_keys

def register_project(project_id, cnt_clients_req, hash_init_model, hash_keys):
    contract = w3.eth.contract(address=contract_address, abi=contract_abi)
    if not contract.functions.isProjectTerminated(project_id).call():
        for attempt in range(3):  # Retry logic
            try:
                nonce = w3.eth.get_transaction_count(Eth_address, 'pending')
                transaction = contract.functions.registerProject(
                    project_id, cnt_clients_req, hash_init_model, hash_keys
                ).build_transaction({
                    'from': Eth_address,
                    'gas': 2000000,
                    'gasPrice': w3.to_wei('50', 'gwei'),
                    'nonce': nonce,
                })
                signed_transaction = w3.eth.account.sign_transaction(transaction, Eth_private_key)
                tx_sent = w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
                receipt = w3.eth.wait_for_transaction_receipt(tx_sent)
                gas_used=receipt['gasUsed']
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
            except ValueError as e:
                print(f"Error: {e}. Retrying transaction...")
                time.sleep(2)
        raise Exception("Transaction failed after retries.")
    else:
        print(f"Project {project_id} is already completed.")
        sys.exit()


def wait_for_clients(event_queue, stop_event, poll_interval=2):
    print('waiting for clients...')
    if geth_poa_middleware not in w3.middleware_onion: 
        # Add PoA middleware for Ganache (if needed)
        w3.middleware_onion.inject(geth_poa_middleware, layer=0)
    # Create an instance of the contract
    contract = w3.eth.contract(address=contract_address, abi=contract_abi)
    last_processed_block = w3.eth.block_number  # Keep track of the last processed block
    while not stop_event.is_set():  # Check the stop_event to terminate the loop
        try:
            current_block = w3.eth.block_number  # Get current block number
            if current_block > last_processed_block:
                # Create filter for the specific block range
                event_filter = contract.events.ClientRegistered.create_filter(
                    fromBlock=last_processed_block + 1,
                    toBlock=current_block
                )
                events = event_filter.get_all_entries()  # Get events 
                for event in events:  # Process events
                    event_queue.put(event)
                    print(f"Event caught at block {event['blockNumber']}: {event['args']['clientAddress']}")
                last_processed_block = current_block  # Update last processed block
                w3.eth.uninstall_filter(event_filter.filter_id)  # Clean up filter

            time.sleep(poll_interval)  # Wait before next poll
        except Exception as e:
            print(f"Error in event listener: {str(e)}")
            time.sleep(poll_interval)  # Wait before retrying


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


def feedback_TX(r, task_id, project_id, client_address, feedback_score, T):
    contract = w3.eth.contract(address=contract_address, abi=contract_abi)
    for attempt in range(3):  # Retry mechanism
        try:
            nonce = w3.eth.get_transaction_count(Eth_address, 'pending') # Fetch the current pending nonce
            transaction = contract.functions.provideFeedback(r, task_id, project_id, client_address, feedback_score, T   # Add the feedback score
            ).build_transaction({
                'from': Eth_address,
                'gas': 2000000,
                'gasPrice': w3.to_wei('50', 'gwei'),
                'nonce': nonce,
            })
            # Sign the transaction
            signed_transaction = w3.eth.account.sign_transaction(transaction, Eth_private_key)
            tx_sent = w3.eth.send_raw_transaction(signed_transaction.rawTransaction)
            receipt = w3.eth.wait_for_transaction_receipt(tx_sent)
            gas_used = receipt['gasUsed']
            tx_feedback = receipt['transactionHash'].hex()
            # Print transaction details
            print(f'Feedback:')
            print(f'      Client address: {client_address}')
            print(f'      Tx_hash: {tx_feedback}')
            print(f'      Gas: {gas_used} Wei')
            print(f'      Task ID: {task_id}')
            print(f'      Score: {feedback_score}')
            print('-'*75)
            return tx_feedback
        except ValueError as e:
            print(f"Transaction failed: {e}. Retrying...")
            time.sleep(2)  # Wait before retrying
    raise Exception("Feedback transaction failed after retries.")

def analyze_model (Local_model,Task_id,project_id_update):
    res=True
    Feedback_score=1
    return res, Feedback_score


def establish_root_key(client_socket,clients_dict,ecdh,kyber,salt_a,session_id):
            matching_addr = [address for address, details in clients_dict.items() if details.get("Session ID") == session_id] # find eth addr based Session ID
            if not matching_addr:
                print('you did not registered for project')
                client_socket.close()
            else:
                msg_keys['epk_b_pem']=(ecdh.pk).hex()
                msg_keys['kpk_b']=(kyber.pk).hex()
                msg_keys_json = json.dumps(msg_keys)
                client_socket.sendall(msg_keys_json.encode('utf-8'))
                data = client_socket.recv(4096).decode('utf-8')  # Receive epk_a_pem and ct from client via off-chain
                if data is None:
                    print(f"Failed to receive data from client {eth_address}")
                    client_socket.close()
                received_data= json.loads(data) # Process the received Json data construct root, chain and model keys
                epk_a_pem = bytes.fromhex(received_data['epk_a_pem'])
                ct = bytes.fromhex(received_data['ciphertext']) 
                epk_a = ECC.import_key(epk_a_pem)
                ss_e = key_agreement(eph_priv=ecdh.sk, eph_pub=epk_a, kdf=kdf)    # ECDH shared secret 
                ss_k = kyber768.decrypt(kyber.sk, ct)
                SS = ss_k + ss_e           # (ss_k||ss_e) construnct general shared secret 
                Root_key= HKDF(SS, 32, salt_a, SHA384, 1)     #  RK_1 <-- SS + Salt_a  
                clients_dict[matching_addr[0]]['Hash_ct_epk_a']=hash_data(ct +epk_a_pem) 
                clients_dict[matching_addr[0]]['Root key']  = Root_key.hex()
            return Root_key


def offchain_listener(server_socket): #Listen for incoming off-chain client connections.
    while True:
        client_socket, client_address = server_socket.accept()
        print(f"New off-chain connection from {client_address}")
        client_thread = Thread(
            target=handle_offchain_client,
            args=(client_socket,),
            daemon=True
        )
        client_thread.start()

    
def handle_offchain_client(client_socket):    # Handle individual client communication on off-chain.
    global salt_a, salt_s, ecdh, kyber, wraped_global_model , model_info
    model_info={}
    while True: 
        try:
            data = client_socket.recv(4096).decode('utf-8')
            recv_msg= json.loads(data)
            if recv_msg["msg_type"] == 'Hello!':
                eth_address = recv_msg["Data"]
                if eth_address in clients_dict:
                    session_id = clients_dict[eth_address]['Session ID']
                    client_socket.send(('Session ID:' + str(session_id)).encode('utf-8'))
                    data=client_socket.recv(4096).decode('utf-8')
                    recv_msg= json.loads(data)
                    if recv_msg["msg_type"] == "pubkeys please":
                        session_id = int(recv_msg["Data"])
                        establish_root_key(client_socket, clients_dict, ecdh, kyber, salt_a, session_id)
                        eth_address = [addr for addr, details in clients_dict.items() if details["Session ID"] == session_id][0]
                        root_key = bytes.fromhex(clients_dict[eth_address]['Root key'])
                        chain_key, model_key = HKDF(root_key, 32, salt_s, SHA384, 2)
                        clients_dict[eth_address]['Model key'] = model_key.hex()
                        clients_dict[eth_address]['Chain key'] = chain_key.hex()
                else:
                    client_socket.send("You haven't registered for the project on blockchain.".encode('utf-8'))
            elif recv_msg["msg_type"] == 'update pubkeys':
                session_id = int(recv_msg["Data"])
                try:
                    establish_root_key(client_socket, clients_dict, ecdh, kyber, salt_a, session_id)
                except Exception as e:
                    print(f"Error handling client here: {e}")
            elif recv_msg["msg_type"] == 'Global model please':
                session_id = int(recv_msg["Data"])
                eth_addr = [addr for addr, details in clients_dict.items() if details["Session ID"] == session_id][0]
                Client_Model_key=bytes.fromhex(clients_dict[eth_addr]['Model key'])
                model_ct=AES_encrypt_data(Client_Model_key, wraped_global_model)
                signed_ct=sign_data(model_ct, Eth_private_key, w3)
                global_model_msg=wrapfiles(('signature.bin',signed_ct), ('global_model.enc',model_ct))
                send_model(client_socket, global_model_msg)
            elif recv_msg["msg_type"] == 'local model update':
                session_id = int(recv_msg["Data"])
                Recieved_model=receive_Model(client_socket)
                eth_addr = [addr for addr, details in clients_dict.items() if details["Session ID"] == session_id][0]
                model_info[eth_addr]={'model_data': Recieved_model}
            else:
                print("Invalid message type received from client.")
        except Exception as e:
            print(f"Error handling client: {e}")
            print(recv_msg)
            break



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
    #Eth_private_key = "0xb524f75accb35465dc297adb4864be59aaed6b7960ce2e4162c8dda611218f0e"  			# Replace with the client's private key
    contract_address = sys.argv[2]
    #contract_address = "0xD656A5c4Ab375df60244561710B98D5b570A4D95"   # Replace with the deployed contract address
    project_id=int(sys.argv[3])   #int(input("Enter a Task ID for registration: "))
    #project_id=3
    round=int(sys.argv[4])
    #round=4
    client_req=int(sys.argv[5])     # client requirement count 
    #client_req=2
    Dataset_type=sys.argv[6]    # Dataset type
    #Dataset_type='UCI_HAR' #    UCI_HAR
    HE_algorithm=sys.argv[7]    # Homomorphic encryption activation
    #HE_algorithm='None'


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
    ecdh, kyber = generate_keys()    # remember the ecdh public key is in pem format
    hash_pubkeys=hash_data(kyber.pk+ecdh.pk)
#-------------------------------------------------
    Init_Global_model = SimpleCNN(Dataset_type)
    Init_Global_model = pickle.dumps(Init_Global_model.state_dict())
    Hash_model = hash_data(Init_Global_model)
    Tx_r =register_project(project_id, client_req, Hash_model, hash_pubkeys)

    msg_keys={}
    clients_dict={}
    registered_cnt=0
    salt_a = salt_s = b'\0'*32    # asymmetric and symmetric salt
    registration_queue = Queue()
    stop_event = Event()

    Thread(target=wait_for_clients, args=(registration_queue, stop_event), daemon=True).start()
    Thread(target=offchain_listener, args=(server_socket,), daemon=True).start()

    while registered_cnt < client_req:
        try:
            event = registration_queue.get(timeout=30)  # 30 second timeout
            eth_address = event['args']['clientAddress']                
            session_id = registered_cnt + 1
            clients_dict[eth_address] = {
                'Session ID': session_id,
                'score': event['args']['initialScore'],
                'hash_epk': event['args']['hash_PubKeys'],
                'registration_tx': event['transactionHash'].hex(),
                'block_number': event['blockNumber']
            }
            registered_cnt += 1
            print(f"Client {registered_cnt}/{client_req} registered: {eth_address}")
        except Exception as e:
            print(f"Error processing registration: {str(e)}")

    print("All clients registered.")
    stop_event.set()   # Signal the thread to stop after registration is complete
    print('-'*75)
    clients_info = json.loads(json.dumps(clients_dict, indent=4))
    Global_Model=Init_Global_model
    Models=[]
    task_info= {}
    ratchet_renge=2
    accuracy_list=[]
   
    for r in range(1,round+1):    
        Task_id=int(str(project_id)+str(r))
        task_info['Round number'] = r
        task_info['Model hash'] = Hash_model
        task_info['Project id'] = project_id
        task_info['Task id'] = Task_id
        task_info['Deadline Task'] = int(time.time()) + 100000

    # Publish Task
        hash_pubkeys='None'
        if r%ratchet_renge==0:     # Assymmetric ratcheting condition
            ecdh, kyber = generate_keys() 
            hash_pubkeys=hash_data(kyber.pk+ecdh.pk)
            Tx_p = publish_task(r, Hash_model, hash_pubkeys, Task_id, project_id, task_info['Deadline Task'])       
            task_info['Publish Tx'] = Tx_p
        else: 
            Tx_p = publish_task(r, Hash_model, hash_pubkeys, Task_id, project_id, task_info['Deadline Task'])    
            task_info['Publish Tx'] = Tx_p 

        json_task_info = json.dumps(task_info, indent=4)
        if r!=1 and HE_algorithm!='None':
            wraped_global_model=wrapfiles(('task_info.json',json_task_info.encode()), ('global_HE_model.bin',aggregated_HE_model))  # Wrap  Model and info files 
        else:
            wraped_global_model=wrapfiles(('task_info.json',json_task_info.encode()), ('global_model.pth',Global_Model))  # Wrap  Model and info files 

        print(f"Start Round {r}: Waiting for local model updates...\n"+'='*20)        
        event_queue = Queue()
        block_filter =  w3 .eth.filter('latest')
        worker = Thread(target=listen_for_updates, args=(block_filter,event_queue), daemon=True)
        worker.start()
        client_addrs=[]
        update_dict={}
        cnt_models=0
        T= False  # Termination flag
        while True:  # Wait for update model
            if not event_queue.empty():
                print(f'Received {cnt_models+1} Local model update Tx:')
                event = event_queue.get()
                r_update = event['args']['round']
                Task_id_update = event['args']['taskId']
                tx_u = event['transactionHash'].hex()
                project_id_update= event['args']['project_id']
                client_addr = event['args']['clientAddress']
                Hash_local_model = event['args']['HashModel']
                Hash_ct_epk_a = event['args']['hash_ct_epk']

                if r_update==r and Task_id_update==Task_id and project_id_update==project_id:
                    update_dict[client_addr]= {'round': r_update, 'Task id':Task_id_update , 
                                                   'Tx_u': tx_u, 'Project id':project_id_update, 
                                                   'Local model hash':Hash_local_model} 
                else:
                    print('information of model is not related to this round or project')  
                print(json.dumps(update_dict[client_addr], indent=4))
                client_addrs.append(client_addr)
                
            # recieved model info and verification
                time.sleep(1)
                if HE_algorithm!='None':
                    time.sleep(9)
                Recieved_model=model_info[client_addr]['model_data']
                unwrapped_msg=unwrap_files(Recieved_model)
                signature=unwrapped_msg['signature.bin']
                local_model_ct=unwrapped_msg['Local_model.enc']
                verify_sign(signature, local_model_ct, pubKey_from_tx(tx_u,w3))
                Model_key=bytes.fromhex(clients_dict[client_addr]['Model key'])
                dec_wrapfile=AES_decrypt_data(Model_key,local_model_ct)
                unwraped=unwrap_files(dec_wrapfile)
                Local_model_info =unwraped['Local_model_info.json']

                if Hash_ct_epk_a!='None':  # Check on-chain and off-chain hash(ct||epk)
                    assert clients_dict[client_addr]['Hash_ct_epk_a'] == Hash_ct_epk_a  , " off- and on-chain keys not match :("   

                if HE_algorithm!='None':
                    local_HE_model=unwraped[f'local_HE_model_{client_addr}.bin']
                    assert Hash_local_model==hash_data(local_HE_model), f" on-chain and off-chain Hash of local model {client_addr} are not match :("    # این قسمت شاید اضافه باشه چون صحت مدل با امضا هم میشه فهمید
                    cnt_models+=1  # save local model for using in aggregation
                    open(main_dir + f"/server/files/models/local_HE_model_{client_addr}.bin",'wb').write(local_HE_model)
                    Feedback_score=0  
                    Tx_f=feedback_TX (r,Task_id, project_id, client_addr, Feedback_score, T)    
                else:
                    Local_model=unwraped[f'local_model_{client_addr}.pth']
                    assert Hash_local_model==hash_data(Local_model), f" on-chain and off-chain Hash of local model {client_addr} are not match :("    # این قسمت شاید اضافه باشه چون صحت مدل با امضا هم میشه فهمید
                    Res, Feedback_score = analyze_model(Local_model,Task_id_update,project_id_update)
                    if Res:
                        cnt_models+=1  # save local model for using in aggregation
                        open(main_dir + f"/server/files/models/local_model_{client_addr}.pth",'wb').write(Local_model)  
                        Tx_f=feedback_TX (r,Task_id, project_id,client_addr, Feedback_score, T)    

                if cnt_models==registered_cnt:
                    if HE_algorithm!='None':
                        aggregated_HE_model = aggregate.aggregate_models(client_addrs,HE_algorithm,Dataset_type) 
                        Hash_model = hash_data(aggregated_HE_model)
                        open(main_dir + f"/server/files/global_HE_model.bin",'wb').write(aggregated_HE_model) 

                    else:
                        normal_aggregated,accuracy=aggregate.aggregate_models(client_addrs,HE_algorithm,Dataset_type)
                        Global_Model=pickle.dumps(normal_aggregated.state_dict())
                        Hash_model = hash_data(Global_Model)
                        torch.save(normal_aggregated.state_dict(), main_dir+'/server/files/global_model.pth')
                        print('*'*40+f'\nAccuracy global model in round {r}: {accuracy:.5f}\n'+'*'*40)
                    break
            else:
                time.sleep(1)

        # Symmetric ratcheting of model-key for each client at the of round
        for addr in clients_dict:   
            chain_key=bytes.fromhex(clients_dict[addr]['Chain key'])  # get previous chain key
            if  r%ratchet_renge==0: #Hash_ct_epk_a!='None':
                Root_key=bytes.fromhex(clients_dict[addr]['Root key'])
                chain_key, Model_key = HKDF(Root_key, 32, salt_s, SHA384, 2)
            else:
                chain_key, Model_key = HKDF(chain_key, 32, salt_s, SHA384, 2)

            clients_dict[addr]['Model key'] = Model_key.hex()
            clients_dict[addr]['Chain key'] = chain_key.hex()  # update keys of dict of clients
        salt_s=(bytes_to_long(salt_s)+1).to_bytes(32, byteorder='big')        #  salt_s  increment(update salt) 
        salt_a=(bytes_to_long(salt_a)+1).to_bytes(32, byteorder='big')        #  salt_a  increment(update salt)           
finish_tash(Task_id,project_id) # transaction termination for recording on blockchain
finish_project(project_id)

