from web3 import Web3
from eth_account import Account
import ipfsApi
from pqcrypto.sign.dilithium2 import generate_keypair, sign, verify
import json
import hashlib
import tempfile
import os 


# Register the client

def register_client():
    # Send a registration transaction
    tx_hash = contract.functions.registerClient().transact({'from': client_address})
    tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash)
    print("Client registered successfully.")

# Wait for a task to be published
def wait_for_task():
    while True:
        task_event_filter = contract.events.TaskPublished.createFilter(fromBlock="latest")
        events = task_event_filter.get_all_entries()

        if events:
            task_id = events[0]['args']['taskId']
            server_id = events[0]['args']['serverId']
            primary_model_id = events[0]['args']['primaryModelId']
            ipfs_address = events[0]['args']['ipfsAddress']
            print(f"Task Published - Task ID: {task_id}, Server ID: {server_id}, IPFS Address: {ipfs_address}")
            # Download the initial model from IPFS and verify using server public key
            # Add your IPFS download and verification logic here

            return task_id , ipfs_address

def upload_model_to_Ipfs(Model,Signature):

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
    
    return cid

def fetch_model_from_Ipfs(Ipfs_id):
    Ipfs_data = api.cat(Ipfs_id)
    Model, Signature=Ipfs_data 
    return Model , Signature

# Update the model and wait for feedback
def update_model_TX(task_id, primaryModel):

    # Sign and encrypt the local model using the client's private key and server's public key
    # Add your signing and encryption logic here
    # Upload the model to IPFS and get the IPFS ID
    # Add your IPFS upload logic here
    # Send an update model transaction

    tx_hash = contract.functions.updateModel(task_id, Ipfs_id).transact({'from': client_address})
    tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash)
    print("Model updated successfully.")

    # Wait for feedback
    feedback_event_filter = contract.events.FeedbackProvided.createFilter(fromBlock="latest")
    feedback_events = feedback_event_filter.get_all_entries()
    if feedback_events:

        feedback = feedback_events[0]
        accepted = feedback['args']['accepted']
        score_change = feedback['args']['scoreChange']

        print(f"Feedback Received - Accepted: {accepted}, Score Change: {score_change}")    

def Ipfs_extraction(Ipfs_data):

	model_data = json.loads(ipfs_data)
	signature = model_data.get("signature", "")
	primary_model = model_data.get("primaryModel", "")
	return  primary_model, signature

if __name__ == "__main__":

# Connect to the local Ganache blockchain
    ganache_url = "http://127.0.0.1:7545"  
    web3 = Web3(Web3.HTTPProvider(ganache_url))

#connect to Ipfs environment
    api = ipfsApi.Client('127.0.0.1', 5001)

# Load the Ethereum account
    Eth_private_key = "YOUR_PRIVATE_KEY"  			# Replace with the client's private key
    account = Account.privateKeyToAccount(Eth_private_key)
    client_address = account.address

# Load the smart contract ABI and address 
    contract_address = "CONTRACT_ADDRESS"   # Replace with the deployed contract address
    contract_abi = [...]           # Replace with the contract ABI
    contract = web3.eth.contract(address=contract_address, abi=contract_abi)  # Create a contract instance

# Register to model training 
    register_client()

# Wait to Task publish 
    Task_id,Ipfs_id = wait_for_task()

# Recieve task from IPFS

    Model, signature = fetch_model_from_Ipfs(Ipfs_id)
    

# verification Signature
    Server_pubkey = ''      # the public key is recieve from secure channel
    assert verify(Server_pubkey, Primary_model, server_signature)

	

# Generate key pairs	
    QPub_key, Qpri_key = generate_keypair()

# Train_local_model
    Local_model=training.('primary_Model')   
    Model_signature = sign(Qpri_key,Local_model)

    hash_object = hashlib.sha256()
    hash_object.update(Local_model.encode('utf-8'))
    hashed_Model = hash_object.hexdigest()

	# we need a json structre for local-data including Qpub_key, Model-Hash,Ipfs-id, Task_Id, Time,...  to send as tx
    Ipfs_Id = upload_model_to_Ipfs(Local_model,Model_signature)
    update_model_Tx(Task_id,Primary_Model,hashed_Model)