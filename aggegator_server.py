from web3 import Web3
from web3.middleware import geth_poa_middleware
from eth_account import Account
import ipfshttpclient
import ipfsApi
from pqcrypto.sign.dilithium2 import generate_keypair,sign,verify
import json
import hashlib
import tempfile
import os 


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
    tx_hash = web3.eth.send_raw_transaction(signed_transaction.rawTransaction)
    receipt = web3.eth.wait_for_transaction_receipt(tx_hash)

    gas_used=receipt['gasUsed']
    tx_registration = receipt['transactionHash'].hex()
    print(f"Project Registered: \n\t Tx_hash: {tx_registration} \n\t Gas: {gas_used} Wei \n\t Task_id: {Task_id}  " )
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
    directory_path= os.getcwd()
    if not os.path.exists(os.path.join(directory_path,'files')):
        os.makedirs('files')
        files_path= os.path.join(directory_path,'files')
    else:
        files_path= os.path.join(directory_path,'files')
    #with tempfile.TemporaryDirectory() as temp_dir:

        #file1_path = os.path.join(temp_dir, "model.txt")
        #file2_path = os.path.join(temp_dir, "signature.txt")
    os.chdir(files_path)
    with open("Model.txt", "wb") as file1:
        file1.write(Model)
        file1.close()

    with open("signature.txt", "wb") as file2:
        file2.write(Signature)
        file2.close()
    #files_path="C:\\Users\\tester\\Desktop\\Post-quantum_Authentication_FL\\files"
    result = api.add(files_path, recursive=True)
    #print(result)
    #cid = result['Hash']
    files_entry = next((entry for entry in result if entry['Name'] == 'files'), None)
    print(files_entry)
    #print ('The model has uploaded successfully')
    return files_entry

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
    try:
    # Add a sample file to IPFS
        result = api.add_str("Hello, IPFS!")
        print(f"Client connected IPFS. sample string: \n\t string:  Hello, IPFS! \n\t CID:  {result}" )
    except Exception as e:
        print("Error:", e)

# Load the Ethereum account
    Eth_private_key = "0x795bbddf33a492b134a1e25f112a60b45409899ce96dd7aa577941a4baaff544"  			# Replace with the client's private key
    account = Account.from_key(Eth_private_key)
    Eth_address = account.address

# Load the smart contract ABI and address 
    contract_address = "0x6D86e8726E9826a3eEc7d6dA55Fcc9bcc4aA0181"   # Replace with the deployed contract address
   
    with open("contract_ABI.json", "r") as abi_file:
        contract_abi = json.load(abi_file)   # Load ABI from file
    contract = web3.eth.contract(address=contract_address, abi=contract_abi)  # Create a contract instance


    QPub_key, Qpri_key = generate_keypair()    # Generate post-quantum signaure key pairs

    Initial_dataset = b'ipfs://Qm...'
    Initial_model = b'ipfs://Qm...'
    Model_signature = sign(Qpri_key,Initial_model)

    Hashed_init_model = hash_data(Initial_model)
    Hashed_init_dataset = hash_data(Initial_dataset)
    Hashed_Model_signature = hash_data(Model_signature)

    Task_id = register_project(Hashed_init_dataset, Hashed_init_model, Hashed_Model_signature)

    Uploaded_ipfs_id = upload_model_to_Ipfs(Initial_model,Model_signature)

    publish_task(Task_id, Uploaded_ipfs_id)  # First publication round

    Models=[]
    round=3
    for i in range(round):
        while True:

            Task_id,Client_address,Ipfs_id =listen_for_updates()

            # verification Signature
            Client_pq_pubkey = ' sss'                 # It supposed to the client's public key is received from secure channel
            
            Local_model, Client_signature = fetch_model_from_Ipfs(Ipfs_id)

            assert verify(Client_pq_pubkey, Local_model, Client_signature)

            Res, Feedback_score = analyze_model(Local_model,Task_id)
            
            if Res:
                Models.append(Local_model)
                feedback_TX (Task_id, Client_address, Feedback_score)
            
            if len(Models)==10:
                updated_model=aggregate_models(Models) 
                break
        Model_signature = sign(Qpri_key,Local_model)

    #ipfs_id = "Qm..."
    #publish_task(task_id, ipfs_id)

# Continue listening for updates and providing feedback...

