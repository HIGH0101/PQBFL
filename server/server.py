from web3 import Web3
from web3.middleware import geth_poa_middleware
from eth_account import Account
import ipfs_api
import tarfile, io ,gzip
from pqcrypto.sign  import dilithium2 ,sphincs_sha256_128f_simple   #.dilithium2 import generate_keypair,sign,verify
import json
import hashlib
import os, sys, time, ast
import tempfile
import aggregate
from threading import Thread
from queue import Queue, Empty

'''
def wrapfiles(model_data, signature_data):
    
    tar_buffer = io.BytesIO() # Create an in-memory TAR archive
    # Create a tarfile object
    with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
        # Add the model data to the archive
        model_info = tarfile.TarInfo(name='model.bin')
        model_info.size = len(model_data)
        tar.addfile(model_info, io.BytesIO(model_data))

        # Add the signature data to the archive
        signature_info = tarfile.TarInfo(name='signature.bin')
        signature_info.size = len(signature_data)
        tar.addfile(signature_info, io.BytesIO(signature_data))

    tar_data = tar_buffer.getvalue() # Get the TAR archive content as bytes
    output_file = 'wrapped_data.tar.gz'
    # Create a gzip compressed file
    with gzip.open(output_file, 'wb') as gzip_file:
        gzip_file.write(tar_data)
'''
def wrapfiles(model_data, signature_data,ETH_address):
    
    tar_buffer = io.BytesIO() # Create an in-memory TAR archive
    # Create a tarfile object
    with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
        # Add the model data to the archive
        model_info = tarfile.TarInfo(name=f'model_{ETH_address}.pth')
        model_info.size = len(model_data)
        tar.addfile(model_info, io.BytesIO(model_data))

        # Add the signature data to the archive
        signature_info = tarfile.TarInfo(name=f'signature_{ETH_address}.bin')
        signature_info.size = len(signature_data)
        tar.addfile(signature_info, io.BytesIO(signature_data))
    tar_data = tar_buffer.getvalue() # Get the TAR archive content as bytes
    output_file = f'wrapped_data_{ETH_address}.tar.gz'
    # Create a gzip compressed file
    with gzip.open(output_file, 'wb') as gzip_file:
        gzip_file.write(tar_data)


def extract_files(file_path, file1_name, file2_name):
    result = {}
    with gzip.open(file_path, 'rb') as gz_file:
        with tarfile.open(fileobj=gz_file, mode='r') as tar:
            for member in tar.getmembers():
                if member.name == file1_name or member.name == file2_name:
                    content = tar.extractfile(member)
                    result[member.name] = content.read()
    return result


def hash_data(data):
    hashed_data=hashlib.sha256(data).hexdigest()
    return hashed_data


def register_project(project_id,cnt_clients,pq_PubKey):
    pq_PubKey=pq_PubKey.hex()
    #Task_id = int(input("Enter a Task ID for registration: ")) # generate a Task identifier 
    contract = web3.eth.contract(address=contract_address, abi=contract_abi)

    if not contract.functions.isProjectTerminated(project_id).call():
        nonce = web3.eth.get_transaction_count(Eth_address)

        #Initial_model_hash=hash_data(Initial_model)
        transaction = contract.functions.registerProject(project_id,cnt_clients,pq_PubKey).build_transaction({
            'from': Eth_address,
            'gas': 2000000,
            'gasPrice': web3.to_wei('50', 'gwei'),
            'nonce': nonce,
        })
        signed_transaction = web3.eth.account.sign_transaction(transaction, Eth_private_key)
        tx_sent = web3.eth.send_raw_transaction(signed_transaction.rawTransaction)
        receipt = web3.eth.wait_for_transaction_receipt(tx_sent)
        gas_used=receipt['gasUsed']
        deployment_block = receipt.blockNumber
        tx_registration = receipt['transactionHash'].hex()
        print(f'''Project Registered on contract:
              Tx_hash: {tx_registration}
              Gas: {gas_used} Wei
              Project ID: {project_id}
              required client count: {cnt_clients} 
              pq_pubKey: {pq_PubKey}''')
        print('-'*75)
        return project_id
    else:
        print(f"Project {project_id} is already terminated. Please Change the Project ID")
        return 'fail'
    
def wait_for_clients(event_filter, event_queue):
    print('waiting for clients...')
    # Add PoA middleware for Ganache (if needed)
    if geth_poa_middleware not in web3.middleware_onion:
        web3.middleware_onion.inject(geth_poa_middleware, layer=0)

    # Create an instance of the contract with the ABI and address
    contract = web3.eth.contract(address=contract_address, abi=contract_abi)
    event_filter = contract.events.ClientRegistered.create_filter(fromBlock="latest")           # Get events since the last checked block
    
    # Loop to listen for events
    #print("listening for client registration...")
    while True:
        events = event_filter.get_new_entries()
        if events:
            for event in events:
                event_queue.put(event)


def terminate_project(Task_id):
    contract = web3.eth.contract(address=contract_address, abi=contract_abi)
    nonce = web3.eth.get_transaction_count(Eth_address)
    transaction = contract.functions.finishProject(Task_id).build_transaction({
        'from': Eth_address,
        'gas': 2000000,  # Adjust the gas limit based on your contract's needs
        'gasPrice': web3.to_wei('50', 'gwei'),
        'nonce': nonce,
    })
    signed_transaction = web3.eth.account.sign_transaction(transaction, Eth_private_key)
    tx_hash = web3.eth.send_raw_transaction(signed_transaction.rawTransaction)
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    gas_used=receipt['gasUsed']
    tx_publish = receipt['transactionHash'].hex()
    print(f'''Task terminated:
          Tx_hash: {tx_publish}
          Gas: {gas_used} Wei
          Task ID: {Task_id}''')
    print('-'*75)

def publish_task(Task_id, Hash_model,Hash_Model_signature, Ipfs_id):
    contract = web3.eth.contract(address=contract_address, abi=contract_abi)
    nonce = web3.eth.get_transaction_count(Eth_address)
    transaction = contract.functions.publishTask(Task_id,Hash_model,Hash_Model_signature,Ipfs_id).build_transaction({
        'from': Eth_address,
        'gas': 2000000,
        'gasPrice': web3.to_wei('50', 'gwei'),
        'nonce': nonce,
    })
    signed_tx = web3.eth.account.sign_transaction(transaction, Eth_private_key)
    tx_sent = web3.eth.send_raw_transaction(signed_tx.rawTransaction)
    receipt = web3.eth.wait_for_transaction_receipt(tx_sent)
    gas_used=receipt['gasUsed']
    tx_publish = receipt['transactionHash'].hex()
    print(f'''Task published:
          Tx_hash: {tx_publish}
          Gas: {gas_used} Wei
          Task ID: {Task_id}
          IPFS ID: {Ipfs_id}''')
    print('-'*75)

def listen_for_updates(event_filter, event_queue):

    # Add PoA middleware for Ganache (if needed)
    if geth_poa_middleware not in web3.middleware_onion:
        web3.middleware_onion.inject(geth_poa_middleware, layer=0)

    # Create an instance of the contract with the ABI and address
    contract = web3.eth.contract(address=contract_address, abi=contract_abi)
    event_filter = contract.events.ModelUpdated.create_filter(fromBlock="latest")           # Get events since the last checked block
    
    # Loop to listen for events
    #print("listening for upadates...")
    while True:
        events = event_filter.get_new_entries()
        if events:
            for event in events:
                event_queue.put(event)


def fetch_model_from_Ipfs(Ipfs_id,client_address):
    Ipfs_data = ipfs_api.http_client.cat(Ipfs_id)
    with open(f"wrapped_data_{client_address}.tar.gz", "wb") as f:
        f.write(Ipfs_data)
    zipfile =f'wrapped_data_{client_address}.tar.gz' 
    model_file=f'local_model_{client_address}.pth'
    Signature_file=f'signature_{client_address}.bin'
    result=extract_files(zipfile,model_file,Signature_file)

    Model_data=result[model_file]
    open(main_dir +'/server/files/'+model_file,'wb').write(Model_data)
    Signature_data=result[Signature_file]
    open(main_dir +'/server/keys/'+Signature_file,'wb').write(Signature_data)
    return Model_data , Signature_data


def feedback_TX (task_id, client_address, feedback_score):

    contract = web3.eth.contract(address = contract_address, abi=contract_abi)
    nonce = web3.eth.get_transaction_count(Eth_address)
    transaction = contract.functions.provideFeedback(task_id, client_address, feedback_score).build_transaction({
        'from': Eth_address,
        'gas': 2000000,
        'gasPrice': web3.to_wei('50', 'gwei'),
        'nonce': nonce,
    })
    signed_transaction = web3.eth.account.sign_transaction(transaction, Eth_private_key)
    tx_sent = web3.eth.send_raw_transaction(signed_transaction.rawTransaction)
    receipt = web3.eth.wait_for_transaction_receipt(tx_sent)
    gas_used=receipt['gasUsed']
    tx_feedback = receipt['transactionHash'].hex()
    print(f'''Feedback provided:
          Client address:{client_address}
          Tx_hash: {tx_feedback}
          Gas: {gas_used} Wei
          Task ID: {Task_id}
          Score: {Task_id}''')
    print('-'*75)


def upload_model_to_Ipfs(Model,Signature,ETH_address):
    
    wrapfiles(Model, Signature,ETH_address) # Wrap the model and signature into a zip file  
    print('Model files are uploaded to IPFS\n')
    result = ipfs_api.http_client.add(f"wrapped_data_{ETH_address}.tar.gz", recursive=True)   # Upload the zip file to IPFS
    start_index = str(result).find('{')
    end_index = str(result).rfind('}')
    content_inside_braces = str(result)[start_index:end_index + 1]
    result_dict = ast.literal_eval(content_inside_braces)
    return result_dict['Hash']


def analyze_model (Local_model,Task_id):
    res=True
    Feedback_score=1
    return res, Feedback_score



if __name__ == "__main__":

# Connect to the local Ganache blockchain
    try:
        ganache_url = "http://127.0.0.1:7545"  
        web3 = Web3(Web3.HTTPProvider(ganache_url))
        print("Server connected to blockchain (Ganache) successfully\n")
    except:
        print("An exception occurred in connecting to blockchain (Ganache)")

# Load the smart contract ABI and address 
    Eth_private_key=sys.argv[1]    
    #Eth_private_key = "0x656e593363e2fe87db1fdf43cee17971874a2872f286b99efd6c24ae4e8612e1"  			# Replace with the client's private key

    contract_address = sys.argv[2]
    #contract_address = "0x71B1494d2084Db29c46F51b09D41B4f82C50Ef59"   # Replace with the deployed contract address

    project_id=int(sys.argv[3])   #int(input("Enter a Task ID for registration: "))
    
    #project_id=1

# Load the Ethereum account
    account = Account.from_key(Eth_private_key)
    Eth_address = account.address


    script_dir = os.path.dirname(os.path.abspath(__file__))
# Get the absolute path to the parent directory of the script directory
    main_dir = os.path.dirname(script_dir)


    with open(main_dir+"/contract/contract-abi.json", "r") as abi_file:
        contract_abi = json.load(abi_file)   # Load ABI from file
    contract = web3.eth.contract(address=contract_address, abi=contract_abi)  # Create a contract instance

    #pq_PubKey, pq_priKey = dilithium2.generate_keypair()    # Generate post-quantum signaure key pairs
    pq_PubKey, pq_priKey=sphincs_sha256_128f_simple.generate_keypair()
    open(main_dir + f"/server/keys/Qpri_key_{Eth_address}.txt",'wb').write(pq_priKey)
    open(main_dir + f"/server/keys/Qpub_key_{Eth_address}.txt",'wb').write(pq_PubKey)

    #pq_priKey=open(main_dir + f"/server/keys/pq_pri_key.txt",'rb').read()
    #pq_PubKey=open(main_dir + f"/server/keys/pq_pub_key.txt",'rb').read()
    Task_id=1
    Initial_dataset = b'ipfs://Qm...'
    Initial_model = b'ipfs://Qm...'
    Model_signature = sphincs_sha256_128f_simple.sign(pq_priKey,Initial_model)

    Hash_init_model = hash_data(Initial_model)
    Hash_init_dataset = hash_data(Initial_dataset)
    Hash_Model_signature = hash_data(Model_signature)

    # register FL project on blockchain
    cnt_require=2  #  requirement client count   
    
    registeration=register_project(project_id, cnt_require, pq_PubKey)
    if registeration=='fail':
        sys.exit()  # Exit the code if the task is already terminated

    registration_queue = Queue()
    block_filter =  web3.eth.filter('latest')
    worker = Thread(target=wait_for_clients, args=(block_filter,registration_queue), daemon=True)
    worker.start()
    clients_dict={}
    client_cnt=0
    while True:
        if not registration_queue.empty():
            event = registration_queue.get()
            address = event['args']['clientAddress']
            initialScore= event['args']['initialScore']
            project_id= event['args']['project_id']
            Key= event['args']['pq_publicKey']
            clients_dict[address] = {'score': initialScore, 'pq_key': Key}  
            client_cnt+=1
            print(f"{client_cnt}/{cnt_require} clients connected")
        if client_cnt==cnt_require:
            break
    clients_info = json.loads(json.dumps(clients_dict, indent=4))

    Model=Initial_model
    Hash_model=Hash_init_model 
    Models=[]
    round=1
    for i in range(round):  # More rounds may be needed later
        
        Uploaded_ipfs_id = upload_model_to_Ipfs(Model, Model_signature,Eth_address)
        publish_task(Task_id, Hash_model,Hash_Model_signature,Uploaded_ipfs_id)      # publishing in rounds
        print(f"Round {i+1}: Listening for local models...")
        
        event_queue = Queue()
        block_filter =  web3 .eth.filter('latest')
        worker = Thread(target=listen_for_updates, args=(block_filter,event_queue), daemon=True)
        worker.start()
        client_addrs=[]
        while True:
            if not event_queue.empty():
                event = event_queue.get()
                Task_id = event['args']['taskId']
                Client_eth_addr = event['args']['clientAddress']
                Hash_model = event['args']['modelHash']
                Ipfs_id = event['args']['ipfsId']
                print(f'''Local model update received:
                Task ID: {Task_id}
                Client address: {Client_eth_addr}
                IPFS ID: {Ipfs_id}''')
                print('-'*75)
                client_addrs.append(Client_eth_addr)
                Local_model, Client_signature = fetch_model_from_Ipfs(Ipfs_id,Client_eth_addr)

            # Verify the downloaded model hash with the hash in the transaction    
                assert Hash_model==hash_data(Local_model), "verification failed for Q1" # این قسمت شاید اضافه باشه چون صحت مدل با امضا هم میشه فهمید

                # load client public key
                #if Client_eth_addr == '0x3d6b25273dD4C310963cb6beD487Bdc186B4e80D': 
                #    Client_pq_pubkey = open(f"C:/Users/tester/Desktop/Post-quantum_Authentication_FL - Copy/client/keys/Qpub_key_{Client_eth_addr}.txt",'rb').read()
                
                #elif Client_eth_addr == "0xF0509A1635Fd3ce79e3F9322Ff080D75052954B4":
                #    Client_pq_pubkey = open(f"C:/Users/tester/Desktop/Post-quantum_Authentication_FL - Copy (2)/client/keys/Qpub_key_{Client_eth_addr}.txt",'rb').read()
                
                #elif Client_eth_addr == "0x99eB6C3796aDDCa22fA7AB91Be092Ec70bF7d626":
                #    Client_pq_pubkey = open(f"C:/Users/tester/Desktop/Post-quantum_Authentication_FL - Copy (3)/client/keys/Qpub_key_{Client_eth_addr}.txt",'rb').read()

                Client_pq_pubkey = clients_info[Client_eth_addr]["pq_key"] #open(main_dir + f"/client/keys/Qpub_key_{Client_eth_addr}.txt",'rb').read()  # It's suppose the client's public key is received from a secure channel
                
                # verification Signature
                Client_pq_pubkey=bytes.fromhex(Client_pq_pubkey)
                #assert dilithium2.verify(Client_pq_pubkey, Local_model, Client_signature), "Signature verifiicaton of model failed"
                assert sphincs_sha256_128f_simple.verify(Client_pq_pubkey, Local_model, Client_signature), "Signature verifiicaton of model failed"

                Res, Feedback_score = analyze_model(Local_model,Task_id)
                if Res:
                    Models.append(Local_model)
                    feedback_TX (Task_id, Client_eth_addr, Feedback_score)
                
                
                if len(Models)==1:
                    aggregate.aggregate_models(client_addrs) 
                    break
            else:
                time.sleep(1)
        Model= open(main_dir + "/server/files/global_model.pth",'rb').read() 
        Hash_model = hash_data(Model)
        #Model_signature = dilithium2.sign(pq_priKey,Model)
        Model_signature =  sphincs_sha256_128f_simple.sign(pq_priKey,Model)
        Hash_Model_signature = hash_data(Model_signature) 

terminate_project(Task_id)

