import subprocess
import os
import argparse


def run_client(client_eth_key, contract_address, client_path, num_epochs, dataset,homomorphic):
    cmd = f"python {client_path} {client_eth_key} {contract_address} {num_epochs} {dataset} "
    if homomorphic:
        cmd += f"{homomorphic}"  # Add -H flag with the selected encryption type
    else:
        cmd += 'None'  # Add None for -H flag 
    subprocess.call(cmd, shell=True)


def run_server(server_eth_key, contract_address, server_path, project_id, round, participants, dataset,homomorphic):
    cmd = f"python {server_path} {server_eth_key} {contract_address} {project_id} {round} {participants} {dataset} "
    if homomorphic:
        cmd += f"{homomorphic}"  # Add  selected encryption type to -H flag 
    else:
        cmd += 'None'  # Add None to -H flag
    subprocess.call(cmd, shell=True)


if __name__ == "__main__":
    parser = argparse.ArgumentParser(description="Run participant or server mode with specific arguments")
    parser.add_argument("-m", "--mode", choices=["participant", "server"], help="Mode (participant or server)", required=True)
    parser.add_argument("-c", "--contract", help="Contract address in hex(0x...)", required=True)
    parser.add_argument("-ek", "--eth_key", help="ETH private key in hex (0x...)")
    parser.add_argument("-e", "--num_epochs", type=int, help="Number of epochs for training in client mode")
    parser.add_argument("-id", "--project_id", type=int, help="ID number for the project in server mode")
    parser.add_argument("-r", "--round", type=int, help="Round number requirement for the project", default=2)
    parser.add_argument("-p", "--participants", type=int, help="Participants number requirement for the project", default=2)
    parser.add_argument("-H", "--homomorphic", choices=["CKKS", "BFV"], help="Use homomorphic encryption algorithm (CKKS or BFV)")
    parser.add_argument("-d", "--dataset",choices=["MNIST","UCI_HAR"] ,help="Choose dataset for training (MNIST or UCI_HAR)", default="UCI_HAR")
    args = parser.parse_args()
    main_dir = os.path.dirname(__file__)
    
    if args.mode == "participant":
        if not (args.eth_key and args.num_epochs):
            parser.error("For participant mode, -ek, -e, -c are required.")
        client_eth_key = args.eth_key
        num_epochs = args.num_epochs
        client_path = main_dir + "/participant/client.py"  # Replace with the path to your client.py script
        run_client(client_eth_key, args.contract, client_path, num_epochs, args.dataset, args.homomorphic)

    elif args.mode == "server":
        if not args.project_id:
            parser.error("For server mode, -c, -ek, -r, -id and -p  is required.")
        server_eth_key = args.eth_key  # Assuming server_address is stored in private_key argument
        server_path = main_dir + "/server/server.py"  # Replace with the path to your server.py script
        run_server(server_eth_key, args.contract, server_path, args.project_id, args.round, args.participants, args.dataset, args.homomorphic)
