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

def run_server(server_eth_key, contract_address, server_path, project_id,round,participants):
    cmd = f"python {server_path} {server_eth_key} {contract_address} {project_id} {round} {participants}"
    subprocess.call(cmd, shell=True)

if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run client or server mode with specific arguments")
    parser.add_argument("-m", "--mode", choices=["client", "server"], help="Mode (client or server)", required=True)
    parser.add_argument("-c", "--contract_address", help="Contract address in hex(0x...)", required=True)
    parser.add_argument("-ek", "--eth_private_key", help="ETH private key in hex (0x...)")
    parser.add_argument("-e", "--num_epochs", type=int, help="Number of epochs for training in client mode")
    parser.add_argument("-id", "--project_id", type=int, help="ID number for the project in server mode")
    parser.add_argument("-r", "--round", type=int, help="Round number requirement for the project",default=2)
    parser.add_argument("-p", "--participants", type=int, help="participants number requirement for the project",default=2)
    args = parser.parse_args()

    main_dir = os.path.dirname(__file__)

    if args.mode == "client":
        if not (args.eth_private_key and args.num_epochs):
            parser.error("For client mode, --private_key and --num_epochs are required.")
        client_eth_key = args.eth_private_key
        num_epochs = args.num_epochs
        client_path = main_dir+"/participant/client.py"   # Replace with the path to your client.py script
        run_client(client_eth_key, args.contract_address, client_path, num_epochs)
    elif args.mode == "server":
        if not args.project_id:
            parser.error("For server mode, -id is required.")
        server_eth_key = args.eth_private_key  # Assuming server_address is stored in private_key argument
        server_path = main_dir+"/server/server.py"    # Replace with the path to your server.py script
        run_server(server_eth_key, args.contract_address, server_path, args.project_id, args.round, args.participants)


