from web3 import Web3
from eth_account import Account
from eth_account.messages import *
from eth_keys import keys

from pqcrypto.kem import kyber768 

from Crypto.Protocol.DH import key_agreement
from Crypto.Protocol.KDF import HKDF
from Crypto.PublicKey import ECC
from Crypto.Hash import SHA384
from Crypto.Util.number import *

import tenseal as ts
import socket, pickle
import json
import os, sys,time
import train_model


pqbfl_path = os.path.join(os.path.dirname(os.path.abspath(__file__)), '..')
sys.path.append(os.path.abspath(pqbfl_path))  # to import function in utility (utils.py)
from utils import *  



    
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
        print('registration in Project : successfully')
        print(f'    Project ID: {project_id}')
        print(f'    Tx: {tx_registration}')
        print(f'    Your Address: {ETH_address}')
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


def task_completed(task_id, project_id):
    contract = w3.eth.contract(address=contract_address, abi=contract_abi)
    return contract.functions.isTaskDone(task_id, project_id).call()


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
                    print('Received Project Info:')
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
                event=events[0]
                round = event['args']['round']
                Task_id = event['args']['taskId']
                server_address = event['args']['serverAddress']
                Hashed_model = event['args']['HashModel']
                hash_keys = event['args']['hash_keys']
                project_id=event['args']['project_id'] 
                tx_hash = event['transactionHash'].hex()
                creation_time = time.gmtime(int(event['args']['creationTime']))
                D_t=time.gmtime(int(event['args']['DeadlineTask']))            
                if registered_id_p==project_id:
                    print('Published Task Info:')
                    print(f'    Task ID: {Task_id}')
                    print(f'    Project ID: {project_id}')
                    print(f'    Server address: {server_address}')
                    print(f'    Transaction Hash: {tx_hash}')
                    print(f'    Time: {time.strftime("%Y-%m-%d %H:%M:%S (UTC)", creation_time)}')
                    print(f'    Deadline: {time.strftime("%Y-%m-%d %H:%M:%S (UTC)", D_t )}')
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


def update_model_Tx(r, Hash_model, hash_ct_epk, Task_id, project_id):
    try:
        nonce = w3.eth.get_transaction_count(ETH_address) # Fetch the latest nonce for the account
        # Build the transaction
        transaction = contract.functions.updateModel(r, Hash_model, hash_ct_epk, Task_id, project_id).build_transaction({
            'from': ETH_address,
            'nonce': nonce,
            'gas': 2000000,  # Adjust gas limit if necessary
            'gasPrice': w3.to_wei('50', 'gwei')
        })
        # Sign and send the transaction
        signed_tx = w3.eth.account.sign_transaction(transaction, private_key=Eth_private_key)
        tx_hash = w3.eth.send_raw_transaction(signed_tx.rawTransaction)
        tx_receipt = w3.eth.wait_for_transaction_receipt(tx_hash) # Wait for transaction receipt
        gas_used = tx_receipt['gasUsed']
        tx_update = tx_receipt['transactionHash'].hex()
        print(' ')
        print('Train completed, model update Info:')
        print(f'    Tx: {tx_update}')
        print(f'    Gas: {gas_used} Wei')
        print('-' * 75)
        return tx_update
    except ValueError as e:
        print(f"Error occurred: {e}")
        if "nonce" in str(e):
            print("Retrying transaction with updated nonce...")
            return update_model_Tx(r, Hash_model, hash_ct_epk, Task_id, project_id)  # Recursive retry
        raise e


def listen_for_feedback(current_round,client_address, blocks_lookback=10):
    print("Waiting for feedback...")
    # Determine the block range
    latest_block = w3.eth.block_number
    start_block = max(0, latest_block - blocks_lookback)  # Avoid negative block numbers
    feedback_filter = contract.events.FeedbackProvided.create_filter(fromBlock=start_block)
    while True:
        feedback_events = feedback_filter.get_all_entries()  # Fetch events from the filter
        for feedback in feedback_events:
            event_client_address = feedback['args']['clientAddress']
            event_round = feedback['args']['round']  # Extract the round from the event
            if event_client_address == client_address and event_round == current_round:
                # Process the feedback event if it matches the current round
                accepted = feedback['args']['accepted']
                task_id = feedback['args']['taskId']
                tx_hash = feedback['transactionHash'].hex()
                project_id = feedback['args']['project_id']
                T = feedback['args']['terminate']
                score_change = feedback['args']['scoreChange']
                server_addr = feedback['args']['serverId']
                print('Feedback Info:')
                print(f'    Tx: {tx_hash}')
                print(f'    Status: {accepted}')
                print(f'    Round: {event_round}')
                print(f'    Score: {score_change}')
                print(f'    Time: {time.strftime("%Y-%m-%d %H:%M:%S (UTC)", time.gmtime())}')
                print(f'    Server address: {server_addr}')
                print('-' * 75)
                return project_id, T, score_change
        time.sleep(1)  # Adjust polling frequency as needed




if __name__ == "__main__":
    try:      # Connect to the local Ganache blockchain
        ganache_url = "http://127.0.0.1:7545"  
        w3 = Web3(Web3.HTTPProvider(ganache_url))
        print(f"Client connected to blockchain (Ganache) successfully\n")
    except Exception as e:
        print("An exception occurred in connecting to blockchain (Ganache) or offchain:", e)
        exit()
    Eth_private_key=sys.argv[1]
    #Eth_private_key = "0x72a284507a64d2ff8960d773c76d35190f2359c20636f4b2caaa7a24c4ef0cd9"  			# Replace with the client's private key
    contract_address = sys.argv[2] 
    #contract_address = "0xD897C0ff940599743a6c311b7822e7303eD9d713"   # Replace with the deployed contract address
    num_epochs=int(sys.argv[3])
    #num_epochs=2
    dataset_type=sys.argv[4]    # Dataset type
    #dataset_type='MNIST' #"MNIST"  UCI_HAR
    HE_algorithm=sys.argv[5]    # Homomorphic encryption activation
    #HE_algorithm='CKKS'


    account = Account.from_key(Eth_private_key)
    ETH_address = account.address

    script_dir = os.path.dirname(os.path.abspath(__file__))
    main_dir = os.path.dirname(script_dir)     # Get the path to the parent directory of the script

    with open(main_dir+"/contract/contract-abi.json", "r") as abi_file:
        contract_abi = json.load(abi_file)      # Load ABI from file
    contract = w3.eth.contract(address=contract_address, abi=contract_abi)  # Create a contract instance

    if HE_algorithm=='CKKS':
        with open(main_dir + f'/participant/keys/CKKS_with_priv_key.pkl', "rb") as f: # load already recieved HE key
            serialized_with_key = pickle.load(f)
        HE_config_with_key = ts.context_from(serialized_with_key)
    elif HE_algorithm=='BFV':
        with open(main_dir + f'/participant/keys/BFV_with_priv_key.pkl', "rb") as f: # load already recieved HE key
            serialized_with_key = pickle.load(f)
        HE_config_with_key = ts.context_from(serialized_with_key)
    
    Tx_r, project_id,server_address,cnt_clients, initial_model_hash, hash_pubkeys=listen_for_projcet()

    esk_a = ECC.generate(curve='p256')      # client's (Alice) private key ECDH 
    epk_a = bytes(esk_a.public_key().export_key(format='PEM'), 'utf-8')



    #time.sleep(random.random())  # avoid transaction collision with other clients
    ini_score, Tx_r , registered_id_p = register_client(hash_data(epk_a), project_id)         # Register to model training
    client_socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    client_socket.connect(('127.0.0.1', 65432))
    msg={}
    msg["msg_type"]='Hello!'
    msg["Data"]= ETH_address
    msg_json=json.dumps(msg)
    while True:
        client_socket.send(msg_json.encode('utf-8'))
        data= client_socket.recv(4096)
        if b"You haven't registered" not in data:
            break
        time.sleep(0.5)

    session_id= str(data)[2:-1].split(':')[1]
    msg["msg_type"]='pubkeys please'
    msg['Data']=session_id
    msg_json=json.dumps(msg)
    client_socket.send(msg_json.encode('utf-8'))  # send request for public keys
    data = client_socket.recv(4096)      
    received_data = json.loads(data.decode('utf-8'))
    epk_b_pem = bytes.fromhex(received_data['epk_b_pem'])
    kpk_b= bytes.fromhex(received_data['kpk_b'])    
    assert hash_data(kpk_b+epk_b_pem) == hash_pubkeys, "on-chain and off-chain pub keys are not match :("     
    epk_b = ECC.import_key(epk_b_pem) 
    ct, ss_k = kyber768.encrypt(kpk_b)  
    msg['epk_a_pem']=epk_a.hex()
    msg['ciphertext']=ct.hex()
    msg["msg_type"]='none'
    msg_json = json.dumps(msg)
    client_socket.send(msg_json.encode('utf-8'))     # send ct and public key
    ss_e = key_agreement(eph_priv=esk_a, eph_pub=epk_b, kdf=kdf)    # ECDH shared secret 
    SS = ss_k + ss_e     # (ss_k||ss_e) 
    salt_a=salt_s =b'\0'*32  # asymmetric and symmetric salt
    Root_key= HKDF(SS, 32, salt_a, SHA384, 1)     # assymmetric ratcheting 
    chain_key=Root_key
    chain_key, Model_key = HKDF(Root_key, 32, salt_s, SHA384, 2)   # first symmetric ratcheting
    timeout=240
    Local_model_info={}
    while True:              # several times contributions (round)
        hash_ct_epk_a='None'
        r, Task_id, Hash_model,hash_pubkeys,project_id, server_eth_addr, D_t= listen_for_task(timeout)          # Wait to Task publish 
        if task_completed(Task_id, project_id):   # check contract that task has not finished 
            print(f"Server has already terminated Task id: {Task_id}")
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
            msg={}
            msg["msg_type"]='update pubkeys'
            msg['Data']=session_id
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
            time.sleep(2)  # avoid conflict double sending in a single chunk 
        msg={}
        msg["msg_type"]='Global model please'
        msg['Data'] = session_id
        msg_json=json.dumps(msg)
        client_socket.send(msg_json.encode('utf-8'))
        x=receive_Model(client_socket)
        unwrapped_msg=unwrap_files(x)
        #unwrapped_msg=unwrap_files((receive_Model(client_socket)))
        signature=unwrapped_msg['signature.bin']
        global_model_ct=unwrapped_msg['global_model.enc']
        verify_sign(signature, global_model_ct, pubKey_from_tx(Tx_r,w3))
        dec_wrapfile=AES_decrypt_data(Model_key,global_model_ct)
        unwraped=unwrap_files(dec_wrapfile)
        task_info=unwraped['task_info.json']
        if r!=1 and HE_algorithm!='None':
            global_HE_model=unwraped['global_HE_model.bin']
            #assert Hash_model==hash_data(global_HE_model), "on-chain and off-chain models hash are not match :("
            encrypted_weights,metadata=deserialize_data(global_HE_model, HE_config_with_key)
            HE_dec_model = HE_decrypt_model(encrypted_weights, Local_model, HE_config_with_key,HE_algorithm,metadata)
        else:
            global_model=unwraped['global_model.pth']
            assert Hash_model==hash_data(global_model), "on-chain and off-chain models hash are not match :("    

    # Train_local_model
        print("Start training...")
        Local_model = train_model.train(global_model,num_epochs, dataset_type)
        #test_accuracy=train_model.evaluate_model_on_test_data(Local_model, dataset_type, device='cpu', batch_size=64)
        if HE_algorithm!='None':
            HE_enc_model, metadata=HE_encrypt_model(Local_model,HE_config_with_key,HE_algorithm)
            serialized_model=serialize_data(HE_enc_model,metadata,HE_algorithm)
            Hash_model = hash_data(serialized_model)
            Local_model_info['Model hash'] = Hash_model
        else:  
            Local_model = pickle.dumps(Local_model.state_dict())
            Hash_model = hash_data(Local_model)
            Local_model_info['Model hash'] = Hash_model

        #build local model information
        Local_model_info['Round number'] = r    
        Local_model_info['Project id'] = project_id
        Local_model_info['Task id'] = Task_id

        Tx_u = update_model_Tx(r, Hash_model,hash_ct_epk_a,Task_id, project_id)

        Local_model_info['Update Tx'] = Tx_u
        json_info = json.dumps(Local_model_info, indent=4)
        if HE_algorithm!='None':
            wraped_model_info=wrapfiles(('Local_model_info.json',json_info.encode()), (f'local_HE_model_{ETH_address}.bin',serialized_model)) 
        else:
            wraped_model_info=wrapfiles(('Local_model_info.json',json_info.encode()), (f'local_model_{ETH_address}.pth',Local_model))  # Wrap Model and info files 
        model_ct=AES_encrypt_data(Model_key, wraped_model_info)
        signed_ct=sign_data(model_ct, Eth_private_key,w3)
        wraped_msg = wrapfiles(('signature.bin',signed_ct), ('Local_model.enc', model_ct))
        
        msg={}
        msg["msg_type"]='local model update'
        msg['Data']=session_id
        msg_json=json.dumps(msg)
        client_socket.send(msg_json.encode('utf-8'))
        send_model(client_socket, wraped_msg)
        project_id_fb, T, score=listen_for_feedback(r,ETH_address)
        if T:
            if project_id_fb==project_id:
                print(f'server terminated the project id {project_id_fb}')
                break
        chain_key, Model_key = HKDF(chain_key, 32, salt_s, SHA384, 2)    # symmetric ratcheting
        salt_s= (bytes_to_long(salt_s)+1).to_bytes(32, byteorder='big')        #  salt_s  increment 
        salt_a= (bytes_to_long(salt_a)+1).to_bytes(32, byteorder='big')        #  salt_a  increment 

