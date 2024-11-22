
import ipfs_api
import gzip, io
import os, sys,time, ast
import tarfile, io ,gzip
import pickle
import tenseal as ts
import torch

from eth_account.messages import *
from eth_keys import keys
from eth_account._utils.legacy_transactions import serializable_unsigned_transaction_from_dict
from eth_account._utils.signing import to_standard_v
from eth_account.datastructures import SignedMessage


from Crypto.Util.number import *
from Crypto.Hash import SHAKE128, SHA384
from Crypto.Cipher import AES




def get_from_Ipfs(self, Ipfs_id,client_address):

    Ipfs_data = ipfs_api.http_client.cat(Ipfs_id)
    '''
    with open(f"wrapped_data_{client_address}.tar.gz", "wb") as f:
        f.write(Ipfs_data)
    zipfile =f'wrapped_data_{client_address}.tar.gz' 
    model_file=f'local_model_{client_address}.pth'
    Signature_file=f'signature_{client_address}.bin'
    result=extract_files(zipfile,model_file,Signature_file)

    Model_data=result[model_file]
    open(main_dir +'/server/files/'+model_file,'wb').write(Model_data)
    Signature_data=result[Signature_file]
    open(main_dir +'/server/keys/'+Signature_file,'wb').write(Signature_data)
    '''
    return Ipfs_data

def upload_to_Ipfs(self, wrapped_data, ETH_address):

    bytes_buffer = io.BytesIO()
    # Write the compressed data to the in-memory buffer
    with gzip.GzipFile(fileobj=bytes_buffer, mode='wb') as gzip_file:
        gzip_file.write(wrapped_data)

    bytes_buffer.seek(0) # Ensure the buffer's position is at the start
    result = ipfs_api.http_client.add(f"wrapped_data_{ETH_address}.tar.gz", recursive=True)   # Upload the zip file to IPFS
    start_index = str(result).find('{')
    end_index = str(result).rfind('}')
    content_inside_braces = str(result)[start_index:end_index + 1]
    result_dict = ast.literal_eval(content_inside_braces)

    return result_dict['Hash']

def analyze_model (self,Local_model,Task_id,project_id_update):
    res=True
    Feedback_score=1
    return res, Feedback_score

def wrapfiles( *files):   # input sample: (('A.bin', A), ('B.enc',B),...)
    tar_buffer = io.BytesIO()  # Create an in-memory TAR archive
    # Create a tarfile object
    with tarfile.open(fileobj=tar_buffer, mode='w') as tar:
        for file_name, file_data in files:
            # Add the file to the archive
            file_info = tarfile.TarInfo(name=file_name)
            file_info.size = len(file_data)
            tar.addfile(file_info, io.BytesIO(file_data))
    
    tar_data = tar_buffer.getvalue()  # Get the TAR archive content as bytes

    return tar_data

def unwrap_files(tar_data):

    extracted_files = {}
    # Create an in-memory byte stream from the tar_data
    tar_buffer = io.BytesIO(tar_data)

    with tarfile.open(fileobj=tar_buffer, mode='r') as tar:
        # Iterate through the members of the tarfile
        for member in tar.getmembers():
            file = tar.extractfile(member)
            if file is not None:
                extracted_files[member.name] = file.read()

    return extracted_files

def deserialize_data(serialized_data, context):
# Load data from bytes without context metadata
    serialized_weights = pickle.loads(serialized_data)
    
    # Deserialize weights into TenSEAL BFV vectors using provided context
    deserialized_weights = {}
    for name, weight_bytes in serialized_weights.items():
        deserialized_weights[name] = ts.bfv_vector_from(context, weight_bytes)  # deserialize with context

    return deserialized_weights


def serialize_data(encrypted_model):
    # Serialize each encrypted weight
    serialized_weights = {}
    for name, enc_weight in encrypted_model.items():
        serialized_weights[name] = enc_weight.serialize()  # serialize only the weights, not context
    
    # Convert to bytes using pickle
    buffer = io.BytesIO()
    pickle.dump(serialized_weights, buffer)
    return buffer.getvalue()

def HE_decrypt_model(encrypted_weights, model, context):
    context.generate_galois_keys()
    context.generate_relin_keys()
    decrypted_weights = {}
    for name, encrypted_weight in encrypted_weights.items():
        decrypted_weights[name] = encrypted_weight.decrypt()  # Decrypt using context's secret key

    # Convert decrypted weights back into PyTorch tensors
    state_dict = model.state_dict()
    for name, decrypted_weight in decrypted_weights.items():
        tensor_weight = torch.tensor(decrypted_weight).view(state_dict[name].shape)
        state_dict[name].copy_(tensor_weight)
    return model


def HE_encrypt_model(model, context):
    context.global_scale = 2 ** 40
    context.generate_galois_keys()
    context.generate_relin_keys()
    encrypted_weights = {}
    for name, param in model.named_parameters():
        param_data = param.detach().numpy().flatten().tolist()    
        encrypted_weights[name] = ts.bfv_vector(context, param_data)  # Encrypt the data
    return encrypted_weights

def scale_HE_encrypted(aggregated_weights, num_clients, scaling_factor=1000000):
    for name in aggregated_weights:
        # Multiply by scaling factor to make division integer-friendly
        aggregated_weights[name] *= scaling_factor  # Integer scaling (multiplying by large factor)

        # Perform integer division by num_clients to scale down
        aggregated_weights[name] *= int(scaling_factor / num_clients)  # Integer-safe division (approximate)
    return aggregated_weights

def unzip(gzip_data):
    with gzip.GzipFile(fileobj=io.BytesIO(gzip_data)) as gz_file:
        tar_data = gz_file.read()
    return tar_data

def pubKey_from_tx(tx_hash):
    tx = w3.eth.get_transaction(tx_hash)
    v = tx['v']
    r = int(tx['r'].hex(), 16)
    s = int(tx['s'].hex(), 16)
    unsigned_tx = serializable_unsigned_transaction_from_dict({     # Reconstruct the unsigned transaction
        'nonce': tx['nonce'],
        'gasPrice': tx['gasPrice'],
        'gas': tx['gas'],
        'to': tx['to'],
        'value': tx['value'],
        'data': tx['input']
    })
    tx_hash = unsigned_tx.hash()    
    standard_v = to_standard_v(v) # Convert v value to standard
    signature = keys.Signature(vrs=(standard_v, r, s))
    public_key = signature.recover_public_key_from_msg_hash(tx_hash)     # Recover the public key from the signature
    return public_key

def sign_data(msg, Eth_private_key):
    encoded_ct = encode_defunct(msg)
    signed_ct = w3.eth.account.sign_message(encoded_ct, private_key=Eth_private_key)
    message_hash =signed_ct.messageHash
    r_bytes = long_to_bytes(signed_ct.r)
    s_bytes  = long_to_bytes(signed_ct.s)
    v_bytes  = long_to_bytes(signed_ct.v)
    sign_bytes = signed_ct.signature
    signed_msg = message_hash + r_bytes + s_bytes  + v_bytes  + sign_bytes
    return signed_msg

def verify_sign(signed_data,msg,pubkey):
    # recover signature from signature data recieved
    msg_hash = signed_data[:32]
    r_sign = bytes_to_long(signed_data[32:64])
    s_sign = bytes_to_long(signed_data[64:96])
    v_sign = bytes_to_long(signed_data[96:97])
    sign_bytes = signed_data[97:]
    signature = SignedMessage( messageHash=msg_hash,r=r_sign,s=s_sign,v=v_sign,signature=sign_bytes)
    '''
    # Signature verification  
    key = ECC.import_key(pubkey)
    verifier = DSS.new(key, 'fips-186-3')
    try:                # verify signature of client's public Keys
        verifier.verify(msg, signature)
    except ValueError:
        print("The message is not authentic.")
    '''

def kdf(x):
    return SHAKE128.new(x).read(32)

def encrypt_data(key,msg):
    nonce = os.urandom(8)
    crypto = AES.new(key, AES.MODE_CTR, nonce=nonce)
    model_ct = crypto.encrypt(msg)
    encrypted= nonce + model_ct
    return encrypted

def decrypt_data(key,cipher):
    nonce = cipher[:8]
    crypto = AES.new(key, AES.MODE_CTR, nonce=nonce)
    dec = crypto.decrypt(cipher[8:])
    return dec