from web3 import Web3
from eth_account import Account
from pqcrypto.sign import dilithium2 #generate_keypair,sign,verify
import json
import ipfs_api
import tarfile, io ,gzip
import os, time, ast
import hashlib
#import tempfile
import os 
import train_model

def wrapfiles(model_data, signature_data,client_eth_address):
    
    tar_buffer = io.BytesIO() # Create an in-memory TAR archive
    # Create a tarfile object
    with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
        # Add the model data to the archive
        model_info = tarfile.TarInfo(name=f'local_model_{client_eth_address}.pth')
        model_info.size = len(model_data)
        tar.addfile(model_info, io.BytesIO(model_data))

        # Add the signature data to the archive
        signature_info = tarfile.TarInfo(name=f'signature_{client_eth_address}.bin')
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


# Register the client
def register_client():

    # Send a registration transaction
    Call_registration = contract.functions.registerClient().transact({'from': client_eth_address})
    receipt = web3.eth.wait_for_transaction_receipt(Call_registration)
    gas_used=receipt['gasUsed']
    tx_registration=receipt['transactionHash'].hex()
    logs = receipt['logs']
    initial_score= [int(log['data'].hex()[66:], 16) for log in logs if log['address'].lower() == contract_address.lower()]
    print(f"Client registered successfully \n\t Tx: {tx_registration} \n\t Gas: {gas_used} Wei \n\t Score: {initial_score[0]}")
    return initial_score


def task_terminated(Task_Id):
    contract = web3.eth.contract(address=contract_address, abi=contract_abi)
    return contract.functions.isProjectTerminated(Task_Id).call()


# Wait for a task to be published
def listen_for_task(timeout):
    print("Listen for task...")
    start_time = time.time()
    Task_id = Hashed_model = Hash_signature = ipfs_address = server_address = 0  # Initialize with default value

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
                Task_id = events[0]['args']['taskId']
                server_address = events[0]['args']['serverId']
                Hashed_model = events[0]['args']['HashModel']
                Hash_signature = events[0]['args']['HashSignature']
                ipfs_address = events[0]['args']['ipfsAddress']
                print(f"Received a published task:\n\t Task id: {Task_id}\n\t Server addr: {server_address}\n\t IPFS addr: {ipfs_address}")
                # Download the initial model from IPFS and verify using server public key
                # Add your IPFS download and verification logic here
                break

            elapsed_time = time.time() - start_time
            if elapsed_time >= timeout:   
                break

            time.sleep(1)  # Sleep for 1 second and check again
        except Exception as e:
            print(f"Error occurred while fetching events: {e}")
            break

    return Task_id, Hashed_model, Hash_signature, ipfs_address, server_address


def upload_model_to_Ipfs(Model,Signature,client_eth_address):

    wrapfiles(Model, Signature,client_eth_address)    # Wrap the model and signature into a zip file
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

    tx_hash = contract.functions.updateModel(Task_id, hashed_Model, Ipfs_id).transact({'from': client_eth_address})
    tx_receipt = web3.eth.wait_for_transaction_receipt(tx_hash)
    gas_used=tx_receipt['gasUsed']
    tx_registration=tx_receipt['transactionHash'].hex()
    
    print(f"Model updated successfully \n\t Tx: {tx_registration} \n\t Gas: {gas_used} Wei")


def listen_for_feedback():
    print("linstening for feedback...")
    while True:
        feedback_event_filter = contract.events.FeedbackProvided.create_filter(fromBlock="latest")
        feedback_events = feedback_event_filter.get_all_entries()
        if feedback_events:

            feedback = feedback_events[0]
            accepted = feedback['args']['accepted']
            score_change = feedback['args']['scoreChange']

            print(f"Feedback Received - Accepted: {accepted}, Score: {score_change}")

            return score_change



if __name__ == "__main__":

    main_dir=os.getcwd()
# Connect to the local Ganache blockchain
    try:
        ganache_url = "http://127.0.0.1:7545"  
        web3 = Web3(Web3.HTTPProvider(ganache_url))
        print("Client connected to Ganache Successfully")
    except:
        print("An exception occurred")

# Load the Ethereum account
    #Eth_private_key = input("Enter private address: ")
    Eth_private_key = "0xe6090bb5353b875dae2f0c5f24995af6e54ea99d6435e9f9d79ea6e6154d2ec4"  			# Replace with the client's private key
    account = Account.from_key(Eth_private_key)
    client_eth_address = account.address

# Load the smart contract ABI and address 
    contract_address = "0xf4C582C278F6b89e604003d63606a2568941e822"   # Replace with the deployed contract address
    with open(main_dir+"/contract/contract-abi.json", "r") as abi_file:
        contract_abi = json.load(abi_file)      # Load ABI from file
    contract = web3.eth.contract(address=contract_address, abi=contract_abi)  # Create a contract instance

    ini_score = register_client()         # Register to model training

    QPub_key, Qpri_key = dilithium2.generate_keypair()    # Generate post-quantum signaure key pairs

    open(main_dir + f"/client/keys/Qpri_key_{client_eth_address}.txt",'wb').write(Qpri_key)
    open(main_dir + f"/client/keys/Qpub_key_{client_eth_address}.txt",'wb').write(QPub_key)
    
    #Qpri_key=open(main_dir + "/client/keys/pq_pri_key.txt",'rb').read()
    #QPub_key=open(main_dir + "/client/keys/pq_pub_key.txt",'rb').read()
    
    i=1
    timeout=80
    while True:                 # several times contributions
        Task_id, Hash_model,Hash_signature,Ipfs_id, server_eth_address= listen_for_task(timeout)          # Wait to Task publish 

        if task_terminated(Task_id):
            print(f"Server has terminated Task id: {Task_id} ")
            break
        if Task_id==0:
            print(f"No new task received within the timeout period ({timeout} seconds). Exit")
            break           
        print(f"Round {i}")
        Model, server_model_signature = fetch_model_from_Ipfs(Ipfs_id)  # Recieve task from Ipfs

    # Verify the downloaded signature and model hashes with the hashes in the transaction
        assert Hash_model==hash_data(Model)  # این قسمت با استفاده از امضا میشه تصدیق بشه ایا نیاز هست که هش هم چک بشه؟
        assert Hash_signature==hash_data(server_model_signature)
        
    # verification Signature
        Server_pubkey = open( f"C:/Users/tester/Desktop/Post-quantum_Authentication_FL/server/keys/Qpub_key_{server_eth_address}.txt",'rb').read() 
        #Server_pubkey = open(main_dir + f"/server/keys/Qpub_key_{server_eth_address}.txt",'rb').read()    # It's suppose the server's public key is received from a secure channel
        assert dilithium2.verify(Server_pubkey, Model,server_model_signature), "model signature verification failed"
        
    # Train_local_model
        dataset_part = input("Enter part dataset number: ")
        train_model.train(dataset_part,client_eth_address)   # train and save the model in files folder
        Local_model= open(main_dir + f"/client/files/local_model_{client_eth_address}.pth",'rb').read()     
        Model_signature = dilithium2.sign(Qpri_key,Local_model)

        Hash_model = hash_data(Local_model)

	# we need a json structre for local-data including Qpub_key, Model-Hash,Ipfs-id, Task_Id, Time,...  to send as tx
        Uploaded_Ipfs_id = upload_model_to_Ipfs(Local_model,Model_signature,client_eth_address)
        update_model_Tx(Task_id,Uploaded_Ipfs_id,Hash_model)

        score=listen_for_feedback()
        i+=1