from mnemonic import Mnemonic
from eth_account import Account
import bip32utils
import json

# Replace this with the actual mnemonic used in Ganache
MNEMONIC = input('Enter mnemonic of current Ganache workspace: ')

# Derivation path for Ethereum (Ganache default)
Derivation_PATH = "m/44'/60'/0'/0/"

def generate_private_key_from_mnemonic(mnemonic, path):
    # Generate the seed from the mnemonic
    mnemo = Mnemonic("english")
    seed = mnemo.to_seed(mnemonic)
    bip32_root_key_obj = bip32utils.BIP32Key.fromEntropy(seed)
    path_parts = path.split('/')[1:]  # Remove the "m"
    child_key = bip32_root_key_obj
    for part in path_parts:
        if "'" in part:
            # Handle hardened key derivation
            index = int(part[:-1]) + 0x80000000  # Hardened derivation
        else:
            index = int(part) 
        child_key = child_key.ChildKey(index)
    return child_key.PrivateKey()


def generate_ganache_accounts(mnemonic, num_accounts):
    accounts = []
    for i in range(1,num_accounts):
        path = f"{Derivation_PATH}{i}"
        priv_key = generate_private_key_from_mnemonic(mnemonic, path)
        # Generate the corresponding Ethereum address
        account = Account.from_key(priv_key)
        accounts.append({
            "address": account.address,
            "privateKey": '0x'+priv_key.hex(),  # Ensure hex encoding of the private key
        })
    return accounts
   

num_accounts=19
accounts = generate_ganache_accounts(MNEMONIC, num_accounts)
filename="./contract/ganache_accounts.json"
with open(filename, "w") as f:
        json.dump(accounts, f, indent=2)
print(f"Accounts saved to {filename}")


