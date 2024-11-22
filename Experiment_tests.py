import subprocess
import os
import argparse
import concurrent.futures
import json
import time

def run_client(client_eth_key, contract_address, client_path, num_epochs, homomorphic):
    cmd = f"python {client_path} {client_eth_key} {contract_address} {num_epochs} "
    cmd += f"{homomorphic}" if homomorphic else 'None'
    try:
        print(f"Running client with key: {client_eth_key}")
        result = subprocess.run(cmd, shell=True, capture_output=True, text=True)
        print(f"Client with key {client_eth_key} completed")
        time.sleep(0.5)
        return result
    except Exception as e:
        print(f"Error running client with key {client_eth_key}: {e}")
        return None
    



def load_private_keys(file_path):
    with open(file_path, 'r') as f:
        accounts = json.load(f)
    return [account['privateKey'] for account in accounts]


def run_multiple_clients(contract_address, num_epochs, homomorphic=None):
    main_dir = os.path.dirname(__file__)
    client_path = main_dir + "/participant/client.py"
    # Get test private keys
    private_keys = load_private_keys(main_dir+"/contract/ganache_accounts.json") 
    # Use ThreadPoolExecutor for concurrent execution
    with concurrent.futures.ThreadPoolExecutor(max_workers=7) as executor:
        # Submit clients for execution
        futures = [
            executor.submit(
                run_client, 
                client_eth_key, 
                contract_address, 
                client_path, 
                num_epochs, 
                homomorphic
            ) 
            for client_eth_key in private_keys
        ]
        
        # Wait for all clients to complete and collect results
        concurrent.futures.wait(futures)
        
        # Check results (optional)
        for future in futures:
            result = future.result()
            if result:
                print(f"Client output: {result.stdout}")
                if result.stderr:
                    print(f"Client error: {result.stderr}")

def main():
    #parser = argparse.ArgumentParser(description="Run multiple participants")
    #parser.add_argument("-c", "--contract", help="Contract address in hex(0x...)", required=True)
    #parser.add_argument("-e", "--num_epochs", type=int, help="Number of epochs for training", required=True)
    #parser.add_argument("-H", "--homomorphic", choices=["CKKS", "BFV"], help="Use homomorphic encryption algorithm")

    #args = parser.parse_args()
    
    # Run multiple clients
    run_multiple_clients(
        contract_address= '0x0E708702C9292A49b647C1Fb5De39f8B3E573a49',#args.contract, 
        num_epochs= 4, #args.num_epochs, 
        homomorphic= 'CKKS' #args.homomorphic
    )

if __name__ == "__main__":
    main()