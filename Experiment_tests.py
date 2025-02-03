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
        #time.sleep(2)
        return result
    except Exception as e:
        print(f"Error running client with key {client_eth_key}: {e}")
        return None
    



def load_private_keys(file_path):
    with open(file_path, 'r') as f:
        accounts = json.load(f)
    return [account['privateKey'] for account in accounts]

'''
def run_multiple_clients(contract_address, num_epochs, num_clients, homomorphic):
    main_dir = os.path.dirname(__file__)
    client_path = main_dir + "/participant/client.py"
    # Get test private keys
    private_keys = load_private_keys(main_dir+"/contract/ganache_accounts.json") 
    # Use ThreadPoolExecutor for concurrent execution
    with concurrent.futures.ThreadPoolExecutor(num_clients) as executor:
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
'''

def run_multiple_clients(contract_address, num_epochs, num_clients, homomorphic):
    main_dir = os.path.dirname(__file__)
    client_path = main_dir + "/participant/client.py"
    # Get test private keys
    private_keys = load_private_keys(main_dir + "/contract/ganache_accounts.json")
    
    # Use ThreadPoolExecutor for concurrent execution
    with concurrent.futures.ThreadPoolExecutor(num_clients) as executor:
        futures = []
        for client_eth_key in private_keys:
            # Submit client for execution
            futures.append(
                executor.submit(
                    run_client, 
                    client_eth_key, 
                    contract_address, 
                    client_path, 
                    num_epochs, 
                    homomorphic
                )
            )
            # Add delay between submissions
            time.sleep(2)  # Adjust this delay as needed

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
        contract_address= '0xD23C78a752D616fD26540a4d0F8E370a0b6a822B',#args.contract, 
        num_epochs= 10, #args.num_epochs, 
        num_clients= 7,
        homomorphic= 'BFV' #args.homomorphic
    )

if __name__ == "__main__":
    main()