import threading
import time
import subprocess
import os
import platform

'''
def run_client(eth_address, contract_address, client_path):
    subprocess.call(["wt", "-w", "0","python", client_path, eth_address, contract_address])

def run_server(server_address, contract_address, server_path):
    subprocess.call(["wt", "-w", "0","python", server_path, server_address, contract_address])
'''
def run_client(eth_address, contract_address, client_path):
    # Determine platform-specific command for opening a new terminal window
    if platform.system() == "Windows":
        cmd = f"start cmd /k python {client_path} {eth_address} {contract_address} && pause"
    elif platform.system() == "Darwin":  # macOS
        cmd = f"osascript -e 'tell app \"Terminal\" to do script \"python {client_path} {eth_address} {contract_address}; read -p \\\"Press Enter to close...\\\"\"'"
    else:  # Linux (assuming gnome-terminal)
        cmd = f"gnome-terminal -- bash -c \"python {client_path} {eth_address} {contract_address}; read -p 'Press Enter to close...'\""

    subprocess.call(cmd, shell=True)

def run_server(server_address,contract_address, server_path):
    # Determine platform-specific command for opening a new terminal window
    if platform.system() == "Windows":
        cmd = f"start cmd /k python {server_path} {server_address} {contract_address} && pause"
    elif platform.system() == "Darwin":  # macOS
        cmd = f"osascript -e 'tell app \"Terminal\" to do script \"python {server_path} {server_address} {contract_address}; read -p \\\"Press Enter to close...\\\"\"'"
    else:  # Linux (assuming gnome-terminal)
        cmd = f"gnome-terminal -- bash -c \"python {server_path} {server_address} {contract_address}; read -p 'Press Enter to close...'\""

    subprocess.call(cmd, shell=True)

if __name__ == "__main__":
    # Prompt the user for server address, contract address, and client addresses
    server_address = input("Enter server private key: ")
    contract_address = input("Enter contract address: ")
    
    eth_addresses = []
    for i in range(3):
        eth_address = input(f"Enter client {i+1} private key : ")
        eth_addresses.append(eth_address)
    
    # Specify the paths to server.py and client.py
    main_dir = os.path.dirname(__file__)
    server_path = main_dir+"/server/server.py"
    client_path = main_dir+"/client/client.py"

    # Create threads for each client
    client_threads = []
    for eth_address in eth_addresses:
        t = threading.Thread(target=run_client, args=(eth_address, contract_address, client_path))
        client_threads.append(t)
    
    # Start all client threads
    for t in client_threads:
        t.start()
    
    # Wait for 3 seconds
    time.sleep(3)
    
    # Start the server
    server_thread = threading.Thread(target=run_server, args=(server_address, contract_address, server_path))
    server_thread.start()
    
    # Wait for all threads to finish
    for t in client_threads:
        t.join()
    server_thread.join()
