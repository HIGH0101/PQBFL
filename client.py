from web3 import Web3
from eth_account import Account
import ipfsApi
from pqcrypto.sign.dilithium2 import generate_keypair,sign,verify
import json
import hashlib
import tempfile
import os 



def hash_data(data):
    hash_object = hashlib.sha256()
    hash_object.update(data.encode('utf-8'))
    hashed_data= hash_object.hexdigest()
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
    
    print(f"Client registered successfully \n\t Tx: {tx_registration} \n\t Gas: {gas_used} Wei \n\t Score: {initial_score[0]}  ")

# Wait for a task to be published
def wait_for_task():
    while True:
        task_event_filter = contract.events.TaskPublished.create_filter(fromBlock="latest")
        events = task_event_filter.get_all_entries()

        if events:
            task_id = events[0]['args']['taskId']
            server_id = events[0]['args']['serverId']
            # primary_model_id = events[0]['args']['primaryModelId']
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
def update_model_Tx(Task_id,Ipfs_id,hashed_Model):

    # Sign and encrypt the local model using the client's private key and server's public key
    # Add your signing and encryption logic here
    # Upload the model to IPFS and get the IPFS ID
    # Add your IPFS upload logic here
    # Send an update model transaction

    tx_hash = contract.functions.updateModel(Task_id,hashed_Model, Ipfs_id).transact({'from': client_address})
    tx_receipt = web3.eth.waitForTransactionReceipt(tx_hash)
    print("Model updated successfully. Now we have to wait for Feedback!!!")

    # Wait for feedback
    feedback_event_filter = contract.events.FeedbackProvided.createFilter(fromBlock="latest")
    feedback_events = feedback_event_filter.get_all_entries()
    if feedback_events:

        feedback = feedback_events[0]
        accepted = feedback['args']['accepted']
        score_change = feedback['args']['scoreChange']

        print(f"Feedback Received - Accepted: {accepted}, Score Change: {score_change}")    

def Ipfs_extraction(Ipfs_data):

	model_data = json.loads(Ipfs_data)
	signature = model_data.get("signature", "")
	primary_model = model_data.get("primaryModel", "")
	return  primary_model, signature



if __name__ == "__main__":

# Connect to the local Ganache blockchain
    try:
        ganache_url = "http://127.0.0.1:7545"  
        web3 = Web3(Web3.HTTPProvider(ganache_url))
        print("Client connected to Ganache Successfully")
    except:
        print("An exception occurred")

# Connect to Ipfs environment
    api = ipfsApi.Client('127.0.0.1', 5001)

# Load the Ethereum account
    Eth_private_key = "0x76d9dce1ab46d4e1127ef9b2240f12c0884c3ed88b36460b610cdab4d39140c4"  			# Replace with the client's private key
    account = Account.from_key(Eth_private_key)
    client_address = account.address

# Load the smart contract ABI and address 
    contract_address = "0xEA14317D6E9843337e2974582DEE618cDEF945ea"   # Replace with the deployed contract address
    with open("contract_ABI.json", "r") as abi_file:
        contract_abi = json.load(abi_file)      # Load ABI from file
    contract = web3.eth.contract(address=contract_address, abi=contract_abi)  # Create a contract instance

    register_client()         # Register to model training
    QPub_key, Qpri_key = generate_keypair()    # Generate post-quantum signaure key pairs
    Task_id, Ipfs_id = wait_for_task()    # Wait to Task publish 

    while True:               # several times contributions
          
        Model, Server_signature = fetch_model_from_Ipfs(Ipfs_id)  # Recieve task from Ipfs
    
# verification Signature
        Server_pubkey = ''    # the server's public key is recieve from secure channel
        assert verify(Server_pubkey, Model, Server_signature)

# Train_local_model
        Local_model=training('primary_Model')   
        Model_signature = sign(Qpri_key,Local_model)

        Hashed_model = hash_data(Local_model)

	# we need a json structre for local-data including Qpub_key, Model-Hash,Ipfs-id, Task_Id, Time,...  to send as tx
        Uploaded_Ipfs_id = upload_model_to_Ipfs(Local_model,Model_signature)
        update_model_Tx(Task_id,Local_model,Hashed_model)