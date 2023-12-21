from web3 import Web3
from web3.middleware import geth_poa_middleware
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

def register_project(Initial_dataset, Initial_model, Signature):
    Task_id = 1
    contract = web3.eth.contract(address=contract_address, abi=contract_abi)
    nonce = web3.eth.get_transaction_count(Eth_address)

    transaction = contract.functions.registerProject(Task_id, Initial_dataset, Initial_model, Signature).build_transaction({
        'from': Eth_address,
        'gas': 2000000,
        'gasPrice': web3.toWei('50', 'gwei'),
        'nonce': nonce,
    })

    signed_transaction = web3.eth.account.sign_transaction(transaction, Eth_private_key)
    tx_hash = web3.eth.send_raw_transaction(signed_transaction.rawTransaction)
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    print("Project Registered:", receipt)
    return Task_id

def publish_task(Task_id, Ipfs_id):
    contract = web3.eth.contract(address=contract_address, abi=contract_abi)
    nonce = web3.eth.get_transaction_count(Eth_address)

    transaction = contract.functions.publishTask(Task_id, Ipfs_id).build_transaction({
        'from': Eth_address,
        'gas': 2000000,
        'gasPrice': web3.toWei('50', 'gwei'),
        'nonce': nonce,
    })

    signed_transaction = web3.eth.account.sign_transaction(transaction, Eth_private_key)
    tx_hash = web3.eth.send_raw_transaction(signed_transaction.rawTransaction)
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    print("Task Published:", receipt)

    return receipt

def listen_for_updates():
    # Add PoA middleware for Ganache (if needed)
    web3.middleware_stack.inject(geth_poa_middleware, layer=0)

    # Create an instance of the contract with the ABI and address
    contract = web3.eth.contract(address=contract_address, abi=contract_abi)

    # Event filter for the YourContractEvent
    event_filter = contract.events.YourContractEvent.createFilter(fromBlock="latest")

    # Loop to listen for events
    while True:
        # Get events since the last checked block
        events = event_filter.get_all_entries()

        # Process events
        for event in events:
            Task_id = event['args']['taskId']
            client_address = event['args']['clientAddress']
            Ipfs_id = event['args']['ipfsId']

        # Wait for new events
        web3.eth.wait_for_transaction_receipt(events[-1]['transactionHash'], timeout=60)
    return  Task_id,Ipfs_id,client_address  


def fetch_model_from_Ipfs(Ipfs_id):
    Ipfs_data = api.cat(Ipfs_id)
    Model, Signature=Ipfs_data 

    return Model , Signature


def feedback_TX (task_id, client_address, feedback_score):
    contract = web3.eth.contract(address = contract_address, abi=contract_abi)
    nonce = web3.eth.get_transaction_count(Eth_address)

    transaction = contract.functions.provideFeedback(task_id, client_address, feedback_score).build_transaction({
        'from': Eth_address,
        'gas': 2000000,
        'gasPrice': web3.toWei('50', 'gwei'),
        'nonce': nonce,
    })

    signed_transaction = web3.eth.account.sign_transaction(transaction, Eth_private_key)
    tx_hash = web3.eth.send_raw_transaction(signed_transaction.rawTransaction)
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    print("Feedback Provided:", receipt)


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
    api = ipfsApi.Client('127.0.0.1', 5001)

# Load the Ethereum account
    Eth_private_key = "0x76d9dce1ab46d4e1127ef9b2240f12c0884c3ed88b36460b610cdab4d39140c4"  			# Replace with the client's private key
    account = Account.from_key(Eth_private_key)
    Eth_address = account.address

# Load the smart contract ABI and address 
    contract_address = "0xEA14317D6E9843337e2974582DEE618cDEF945ea"   # Replace with the deployed contract address
   
    with open("contract_ABI.json", "r") as abi_file:
        contract_abi = json.load(abi_file)   # Load ABI from file
    contract = web3.eth.contract(address=contract_address, abi=contract_abi)  # Create a contract instance


    QPub_key, Qpri_key = generate_keypair()    # Generate post-quantum signaure key pairs

    Initial_dataset = "ipfs://Qm..."
    Initial_model = "ipfs://Qm..."
    Signature = "0x..."
    Model_signature = sign(Qpri_key,Initial_model)
    Task_id = register_project(Initial_dataset, Initial_model, Signature)

    Hashed_init_model = hash_data(Initial_model)
    Uploaded_ipfs_id = upload_model_to_Ipfs(Initial_model,Model_signature)

    publish_task(Task_id, Uploaded_ipfs_id)  # First publication round

    Models=[]
    while True:

        Model_signature = sign(Qpri_key,Local_model)

        hash_object = hashlib.sha256()
        hash_object.update(Local_model.encode('utf-8'))
        hashed_Model = hash_object.hexdigest()

        # verification Signature
        Client_pubkey = ''           # the server's public key is recieve from secure channel
        
        Task_id,Client_address,Ipfs_id =listen_for_updates()

        Local_model, Client_signature = fetch_model_from_Ipfs(Ipfs_id)

        assert verify(Client_pubkey, Local_model, Client_signature)

        Res, Feedback_score = analyze_model(Local_model,Task_id)
        
        if Res:
            Models.append(Local_model)
            feedback_TX (Task_id, Client_address, Feedback_score)
        
        if len(Models)==10:
            Local_model=aggregate_models(Models) 

    #ipfs_id = "Qm..."
    #publish_task(task_id, ipfs_id)

# Continue listening for updates and providing feedback...

