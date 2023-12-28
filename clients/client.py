from web3 import Web3
from eth_account import Account
#import ipfsApi
from pqcrypto.sign.dilithium2 import generate_keypair,sign,verify
import json
import ipfs_api
import tarfile, io ,gzip
import os, time, ast
import hashlib
import tempfile
import os 


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
    '''
    hash_object = hashlib.sha256()
    hash_object.update(data.encode('utf-8'))
    hashed_data= hash_object.hexdigest()
    return hashed_data
    '''
    hashed_data=hashlib.sha256(data).hexdigest()
    return hashed_data


# Register the client
def register_client():
    # Send a registration transaction
    Call_registration = contract.functions.registerClient().transact({'from': client_address})
    receipt = web3.eth.wait_for_transaction_receipt(Call_registration)

    gas_used=receipt['gasUsed']
    tx_registration=receipt['transactionHash'].hex()
    logs = receipt['logs']
    initial_score= [int(log['data'].hex()[66:], 16) for log in logs if log['address'].lower() == contract_address.lower()]
    
    print(f"Client registered successfully \n\t Tx: {tx_registration} \n\t Gas: {gas_used} Wei \n\t Score: {initial_score[0]}")
    return initial_score

# Wait for a task to be published
def listen_for_task():
    
    while True:
        task_event_filter = contract.events.TaskPublished.create_filter(fromBlock="latest")
        events = task_event_filter.get_all_entries()

        if events:
            Task_id = events[0]['args']['taskId']
            server_id = events[0]['args']['serverId']
            # primary_model_id = events[0]['args']['primaryModelId']
            Hashed_model = events[0]['args']['HashModel']
            Hash_signature = events[0]['args']['HashSignature']
            ipfs_address = events[0]['args']['ipfsAddress']
            print(f"Recieved a published task:\n\t Task id: {Task_id}\n\t Server addr: {server_id}\n\t IPFS addr: {ipfs_address}")
            # Download the initial model from IPFS and verify using server public key
            # Add your IPFS download and verification logic here

            return Task_id ,Hashed_model,Hash_signature, ipfs_address

def upload_model_to_Ipfs(Model,Signature):
    '''
    # Create a temporary directory to store the files
    with tempfile.TemporaryDirectory() as temp_dir:
        file1_path = os.path.join(temp_dir, "model.txt")
        file2_path = os.path.join(temp_dir, "signature.txt")

        with open(file1_path, "wb") as file1:
            file1.write(Model)

        with open(file2_path, "wb") as file2:
            file2.write(Signature)

    result = api.add('temp_dir, recursive=True')
    cid = result['Hash']
    print ('The model has uploaded successfully')
'''
    wrapfiles(Model, Signature)    # Wrap the model and signature into a zip file
    print('signature and Model files are saved in wrapped_data.tar.gz')

    result = ipfs_api.http_client.add("wrapped_data.tar.gz", recursive=True)   # Upload the zip file to IPFS
    start_index = str(result).find('{')
    end_index = str(result).rfind('}')
    content_inside_braces = str(result)[start_index:end_index + 1]
    result_dict = ast.literal_eval(content_inside_braces)

    return result_dict['Hash']

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

# Update the model and wait for feedback
def update_model_Tx(Task_id,Ipfs_id,hashed_Model):

    # Sign and encrypt the local model using the client's private key and server's public key
    # Add your signing and encryption logic here
    # Upload the model to IPFS and get the IPFS ID
    # Add your IPFS upload logic here
    # Send an update model transaction

    tx_hash = contract.functions.updateModel(Task_id, hashed_Model, Ipfs_id).transact({'from': client_address})
    tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    gas_used=tx_receipt['gasUsed']
    tx_registration=tx_receipt['transactionHash'].hex()
    
    print(f"Model updated successfully \n\t Tx: {tx_registration} \n\t Gas: {gas_used} Wei")
    '''
    # Wait for feedback
    feedback_event_filter = contract.events.FeedbackProvided.create_filter(fromBlock="latest")
    feedback_events = feedback_event_filter.get_all_entries()
    if feedback_events:

        feedback = feedback_events[0]
        accepted = feedback['args']['accepted']
        score_change = feedback['args']['scoreChange']

        print(f"Feedback Received - Accepted: {accepted}, Score: {score_change}")    
    '''
def listen_for_feedback():

    while True:
        feedback_event_filter = contract.events.FeedbackProvided.create_filter(fromBlock="latest")
        feedback_events = feedback_event_filter.get_all_entries()
        if feedback_events:

            feedback = feedback_events[0]
            accepted = feedback['args']['accepted']
            score_change = feedback['args']['scoreChange']

            print(f"Feedback Received - Accepted: {accepted}, Score: {score_change}")

            return score_change

'''
def Ipfs_extraction(Ipfs_data):
	model_data = json.loads(Ipfs_data)
	signature = model_data.get("signature", "")
	primary_model = model_data.get("primaryModel", "")
	return  primary_model, signature
'''


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
    Eth_private_key = "0x0395549dbbde35d32791ddfbeb1bc0cb9020d3d7fe49f76228036a6b6cd3a27f"  			# Replace with the client's private key
    account = Account.from_key(Eth_private_key)
    client_address = account.address

# Load the smart contract ABI and address 
    contract_address = "0xEa2ff1BEa9B4235F6D77F1A065C7d85E0D25b690"   # Replace with the deployed contract address
    with open("contract_ABI.json", "r") as abi_file:
        contract_abi = json.load(abi_file)      # Load ABI from file
    contract = web3.eth.contract(address=contract_address, abi=contract_abi)  # Create a contract instance

    ini_score = register_client()         # Register to model training

    #QPub_key, Qpri_key = generate_keypair()    # Generate post-quantum signaure key pairs
    main=os.getcwd()
    Qpri_key=open(main + "\\clients\\keys\\pq_pri_key.txt",'rb').read()
    QPub_key=open(main + "\\clients\\keys\\pq_pub_key.txt",'rb').read()

    i=1
    while True:               # several times contributions
        print(f"Round {i}: listening for task...")
        Task_id, Hash_model,Hash_signature,Ipfs_id = listen_for_task()          # Wait to Task publish 

        Model, server_model_signature = fetch_model_from_Ipfs(Ipfs_id)  # Recieve task from Ipfs

    # Verify the downloaded signature and model hashes with the hashes in the transaction
        assert Hash_model==hash_data(Model)
        assert Hash_signature==hash_data(server_model_signature)
        
    # verification Signature
        Server_pubkey = open(main + "\\server\\keys\\pq_pub_key.txt",'rb').read()    # It is suppose the server's public key is received from a secure channel
        assert verify(Server_pubkey, Model,server_model_signature)

# Train_local_model
        
        Local_model= Model  # training('primary_Model')   
        Model_signature = sign(Qpri_key,Local_model)

        Hash_model = hash_data(Local_model)

	# we need a json structre for local-data including Qpub_key, Model-Hash,Ipfs-id, Task_Id, Time,...  to send as tx
        Uploaded_Ipfs_id = upload_model_to_Ipfs(Local_model,Model_signature)
        update_model_Tx(Task_id,Uploaded_Ipfs_id,Hash_model)

        score=listen_for_feedback()
        i+=1