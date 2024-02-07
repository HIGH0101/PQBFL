import threading
import time
import subprocess
import os
import platform
import argparse
import sys


def run_client(client_eth_key, contract_address, client_path, num_epochs):
    cmd = f"python {client_path} {client_eth_key} {contract_address} {num_epochs}"
    subprocess.call(cmd, shell=True)

def run_server(server_eth_key, contract_address, server_path, task_id):
    cmd = f"python {server_path} {server_eth_key} {contract_address} {task_id}"
    subprocess.call(cmd, shell=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run client or server mode with specific arguments")
    parser.add_argument("-m", "--mode", choices=["client", "server"], help="Mode (client or server)", required=True)
    parser.add_argument("-c", "--contract_address", help="Contract address in hex(0x...)", required=True)
    parser.add_argument("-k", "--private_key", help="ETH private key in hex (0x...)")
    parser.add_argument("-e", "--num_epochs", type=int, help="Number of epochs for training in client mode")
    parser.add_argument("-id", "--task_id", type=int, help="ID number for the task in server mode")

    args = parser.parse_args()

    main_dir = os.path.dirname(__file__)

    if args.mode == "client":
        if not (args.private_key and args.num_epochs):
            parser.error("For client mode, --private_key and --num_epochs are required.")
        client_eth_key = args.private_key
        num_epochs = args.num_epochs
        client_path = main_dir+"/client/client.py"   # Replace with the path to your client.py script
        run_client(client_eth_key, args.contract_address, client_path, num_epochs)
    elif args.mode == "server":
        if not args.task_id:
            parser.error("For server mode, -id is required.")
        server_eth_key = args.private_key  # Assuming server_address is stored in private_key argument
        server_path = main_dir+"/server/server.py"    # Replace with the path to your server.py script
        run_server(server_eth_key, args.contract_address, server_path, args.task_id)

'''
import sys
import threading
import time
import subprocess
import os

def run_client(eth_address, contract_address, client_path, num_epochs):
    cmd = f"python {client_path} {eth_address} {contract_address} {num_epochs}"
    subprocess.call(cmd, shell=True)

def run_server(server_address, contract_address, server_path, task_id):
    cmd = f"python {server_path} {server_address} {contract_address} {task_id}"
    subprocess.call(cmd, shell=True)

if __name__ == "__main__":
    if len(sys.argv) < 4:
        print("Usage:")
        print("  For client mode: python main.py client <client_private_key> <contract_address> <num_epochs>")
        print("  For server mode: python main.py server <server_private_key> <contract_address> <task_id>")
        sys.exit(1)

    main_dir = os.path.dirname(__file__)
    

    mode = sys.argv[1].lower()
    address = sys.argv[2]
    contract_address = sys.argv[3]

    if mode == "client":
        if len(sys.argv) != 5:
            print("Usage: python main.py client <eth_address> <contract_address> <num_epochs>")
            sys.exit(1)
        eth_address = address
        client_path = main_dir+"/client/client.py"  
        num_epochs = int(sys.argv[4])
        run_client(eth_address, contract_address, client_path, num_epochs)
    elif mode == "server":
        if len(sys.argv) != 5:
            print("Usage: python main.py server <server_address> <contract_address> <task_id>")
            sys.exit(1)
        server_address = address
        server_path = main_dir+"/server/server.py"  
        task_id = int(sys.argv[4])
        run_server(server_address, contract_address, server_path, task_id)
    else:
        print("Invalid mode. Please enter 'client' or 'server'.")
'''
