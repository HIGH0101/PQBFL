from web3 import Web3
from web3.middleware import geth_poa_middleware
from eth_account import Account
#import ipfshttpclient
#import ipfsApi
import ipfs_api
import tarfile, io ,gzip
from pqcrypto.sign.dilithium2 import generate_keypair,sign,verify
import json
import hashlib
import os, time, ast
import tempfile
#import os 


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


def register_project(initialDataset, initialModelHash, signature):
    Task_id = 1   # generate a Task identifier
    contract = web3.eth.contract(address=contract_address, abi=contract_abi)
    nonce = web3.eth.get_transaction_count(Eth_address)

    #Initial_model_hash=hash_data(Initial_model)
    transaction = contract.functions.registerProject(Task_id, initialDataset, initialModelHash, signature).build_transaction({
        'from': Eth_address,
        'gas': 2000000,
        'gasPrice': web3.to_wei('50', 'gwei'),
        'nonce': nonce,
    })
    signed_transaction = web3.eth.account.sign_transaction(transaction, Eth_private_key)
    tx_sent = web3.eth.send_raw_transaction(signed_transaction.rawTransaction)
    receipt = web3.eth.wait_for_transaction_receipt(tx_sent)

    gas_used=receipt['gasUsed']
    tx_registration = receipt['transactionHash'].hex()
    print(f"Project Registered: \n\t Tx_hash: {tx_registration} \n\t Gas: {gas_used} Wei \n\t Task_id: {Task_id}  " )
    return Task_id


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
    print(f"Task published: \n\t Tx_hash: {tx_publish} \n\t Gas: {gas_used} Wei \n\t Task_id: {Task_id}" )


def listen_for_updates():
    # Add PoA middleware for Ganache (if needed)
    
    if geth_poa_middleware not in web3.middleware_onion:
        web3.middleware_onion.inject(geth_poa_middleware, layer=0)

    # Create an instance of the contract with the ABI and address
    contract = web3.eth.contract(address=contract_address, abi=contract_abi)

    # Loop to listen for events
    print("listening for upadates...")
    while True:
        # Event filter for the YourContractEvent
        event_filter = contract.events.ModelUpdated.create_filter(fromBlock="latest")
        # Get events since the last checked block
        events = event_filter.get_all_entries()
        
        if events:
        # Process events
            for event in events:
                Task_id = event['args']['taskId']
                client_address = event['args']['clientAddress']
                Hash_model = event['args']['modelHash']
                Ipfs_id = event['args']['ipfsId']
                print(f"Update received \n\t Task ID: {Task_id} \n\t Client address: {client_address} \n\t IPFS ID: {Ipfs_id}")

                return  Task_id,client_address,Hash_model,Ipfs_id  

        # Wait for new events
            #web3.eth.wait_for_transaction_receipt(events[-1]['transactionHash'], timeout=60)
        #else:
        #    time.sleep(2)   # Sleep or perform other actions when no new events are found

    #return  Task_id,Ipfs_id,client_address  

'''
def fetch_model_from_Ipfs(Ipfs_id):
    Ipfs_data = ipfs_api.http_client.cat(Ipfs_id)
    Model, Signature=Ipfs_data 

    return Model , Signature
'''

def fetch_model_from_Ipfs(Ipfs_id):

    Ipfs_data = ipfs_api.http_client.cat(Ipfs_id)
    with open("wrapped_data.tar.gz", "wb") as f:
        f.write(Ipfs_data)
    zipfile ='wrapped_data.tar.gz' 
    model_file='model.bin'
    Signature_file='signature.bin'
    result=extract_files(zipfile,model_file,Signature_file )
    Model_data=result[model_file]
    Signature_data=result[Signature_file]
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
    print(f"Feedback Provided: \n\t Tx_hash: {tx_feedback} \n\t Gas: {gas_used} Wei \n\t Task_id: {Task_id} \n\t score: {Task_id}" )


def upload_model_to_Ipfs(Model,Signature):
    # Create a temporary directory to store the files
    '''
    directory_path= os.getcwd()
    if not os.path.exists(os.path.join(directory_path,'files')):    # create files directory to wrap signature an model
        os.makedirs('files')
        files_path= os.path.join(directory_path,'files')
    else:
        files_path= os.path.join(directory_path,'files')
    #with tempfile.TemporaryDirectory() as temp_dir:

        #file1_path = os.path.join(temp_dir, "model.txt")
        #file2_path = os.path.join(temp_dir, "signature.txt")
    os.chdir(files_path)
    with open("Model.txt", "wb") as file1:     # write model file 
        file1.write(Model)
        file1.close()

    with open("signature.txt", "wb") as file2:     # write signature file 
        file2.write(Signature)
        file2.close()
    #files_path="C:\\Users\\tester\\Desktop\\Post-quantum_Authentication_FL\\files"
    os.chdir(directory_path)
'''
    wrapfiles(Model, Signature)    # Wrap the model and signature into a zip file
    print('signature and Model files are saved in wrapped_data.tar.gz')

    result = ipfs_api.http_client.add("wrapped_data.tar.gz", recursive=True)   # Upload the zip file to IPFS
    start_index = str(result).find('{')
    end_index = str(result).rfind('}')
    content_inside_braces = str(result)[start_index:end_index + 1]
    result_dict = ast.literal_eval(content_inside_braces)

    return result_dict['Hash']

def analyze_model (Local_model,Task_id):

    res=True
    Feedback_score=1

    return res, Feedback_score

def aggregate_models(Models):

    return 0


if __name__ == "__main__":

# Connect to the local Ganache blockchain
    try:
        ganache_url = "http://127.0.0.1:7545"  
        web3 = Web3(Web3.HTTPProvider(ganache_url))
        print("Client connected to Ganache Successfully")
    except:
        print("An exception occurred")

# Connect to Ipfs environment
    #api = ipfsApi.Client('127.0.0.1', 5001)
    #try:
    # Add a sample file to IPFS
    #    result = api.add_str("Hello, IPFS!")
    #    print(f"Server connected IPFS. sample string: \n\t string:  Hello, IPFS! \n\t CID:  {result}" )
    #except Exception as e:
    #    print("Error:", e)

# Load the Ethereum account
    Eth_private_key = "0x795bbddf33a492b134a1e25f112a60b45409899ce96dd7aa577941a4baaff544"  			# Replace with the client's private key
    account = Account.from_key(Eth_private_key)
    Eth_address = account.address

# Load the smart contract ABI and address 
    contract_address = "0xEa2ff1BEa9B4235F6D77F1A065C7d85E0D25b690"   # Replace with the deployed contract address
   
    main_dir=os.getcwd()
    

    with open(main_dir+"/contract/contract_ABI.json", "r") as abi_file:
        contract_abi = json.load(abi_file)   # Load ABI from file
    contract = web3.eth.contract(address=contract_address, abi=contract_abi)  # Create a contract instance


    #QPub_key, Qpri_key = generate_keypair()    # Generate post-quantum signaure key pairs

    Qpri_key=open(main_dir + "/server/keys/pq_pri_key.txt",'rb').read()
    QPub_key=open(main_dir + "/server/keys/pq_pub_key.txt",'rb').read()


    Initial_dataset = b'ipfs://Qm...'
    Initial_model = b'ipfs://Qm...'
    Model_signature = sign(Qpri_key,Initial_model)

    Hash_init_model = hash_data(Initial_model)
    Hash_init_dataset = hash_data(Initial_dataset)
    Hash_Model_signature = hash_data(Model_signature)

    # register FL project on blockchain
    Task_id = register_project(Hash_init_dataset, Hash_init_model, Hash_Model_signature)


    Model=Initial_model
    Hash_model=Hash_init_model 
    Models=[]
    round=3
    for i in range(round):

        Uploaded_ipfs_id = upload_model_to_Ipfs(Model, Model_signature)
        publish_task(Task_id, Hash_model,Hash_Model_signature,Uploaded_ipfs_id)                 # publishing in rounds
        print(f"Round {i+1}: listening for upadates...")

        while True:
                
            Task_id,Client_address,Hash_model,Ipfs_id =listen_for_updates()
            Local_model, Client_signature = fetch_model_from_Ipfs(Ipfs_id)

        # Verify the downloaded model hash with the hash in the transaction    
            assert Hash_model==hash_data(Local_model)

        # verification Signature
            Client_pq_pubkey = open(main_dir + "/clients/keys/pq_pub_key.txt",'rb').read()  # It is suppose the client's public key is received from a secure channel
            assert verify(Client_pq_pubkey, Local_model, Client_signature)

            Res, Feedback_score = analyze_model(Local_model,Task_id)
            if Res:
                Models.append(Local_model)
                feedback_TX (Task_id, Client_address, Feedback_score)
            
            Count_local_models=len(Models)
            if Count_local_models==3:
                Updated_model=aggregate_models(Models) 
                break 
        Model=Updated_model  
        Hash_model = hash_data(Model)
        Model_signature = sign(Qpri_key,Model)
        Hash_Model_signature = hash_data(Model_signature) 
        

# Continue listening for updates and providing feedback...

