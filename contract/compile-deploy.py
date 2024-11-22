
from web3 import Web3, HTTPProvider
import json
from solcx import compile_standard
import os


 #Connect to Ganache (local blockchain)
ganache_url = "http://127.0.0.1:7545"  # Update with your Ganache URL
web3 = Web3(HTTPProvider(ganache_url))

# Check connection status
if not web3.is_connected():
    print("Error: Unable to connect to Ganache. Please check the URL and try again.")
else:
    print("Connected to Blockchain (Ganache)")

    # User input for deployer account and private key
    deployer_account = input("Enter deployer account address: ")
    private_key = input("Enter deployer private key: ")
    # Set the deployer account as the default account
    web3.eth.default_account = deployer_account

    # Read the Solidity source code from the .sol file
    with open("./contract/contract.sol", "r") as f:
        contract_source_code = f.read()

    compiled_sol = compile_standard(
    {
        "language": "Solidity",
        "sources": {"contract.sol": {"content": contract_source_code}},
        "settings": {
            "outputSelection": {
                "*": {
                    "*": ["abi", "metadata", "evm.bytecode", "evm.bytecode.sourceMap"]
                }
            }
        },
    },
    solc_version="0.8.0",
    ) 
    with open("./contract/compiled-code.json", "w") as f:
        json.dump(compiled_sol, f)
    # get bytecode
    contract_bytecode = compiled_sol["contracts"]["contract.sol"]["PQB_FederatedLearning"]["evm"]["bytecode"]["object"]
    # get abi
    contract_abi = json.loads(compiled_sol["contracts"]["contract.sol"]["PQB_FederatedLearning"]["metadata"])["output"]["abi"]

    with open("./contract/contract-abi.json", "w") as f:
        json.dump(contract_abi, f)

    # Deploy the contract
    contract = web3.eth.contract(abi=contract_abi, bytecode=contract_bytecode)
    nonce = web3.eth.get_transaction_count(deployer_account)
    transaction = contract.constructor().build_transaction({
        "chainId":  web3.eth.chain_id,
        "from":  deployer_account, 
        "nonce": nonce
    })
    signed_tx = web3.eth.account.sign_transaction(transaction, private_key=private_key)
    tx_sent = web3.eth.send_raw_transaction(signed_tx.rawTransaction)

    # Wait for the transaction to be mined
    transaction_receipt = web3.eth.wait_for_transaction_receipt(tx_sent)

    # Get the deployed contract address
    deployed_contract_address = transaction_receipt["contractAddress"]
    print(f"Contract deployed successfully at address: {deployed_contract_address}")
