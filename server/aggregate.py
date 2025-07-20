"""
Created on Wed Jan  3 18:07:07 2024
@author: HIGHer
"""
import os,  io 
import torch
from torch.utils.data import DataLoader, TensorDataset
import numpy as np
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import LabelEncoder
import pickle
import tenseal as ts
from torchvision import datasets, transforms
from collections import defaultdict

from simple_cnn_config import SimpleCNN


def deserialize_data(serialized_data, context):
    data_package = pickle.loads(serialized_data) # Load the complete data package
    # Extract components
    serialized_weights = data_package['weights']
    metadata = data_package['metadata']
    algorithm = data_package['algorithm']
    deserialized_weights = {}   # Deserialize weights
    for name, weight_bytes in serialized_weights.items():
        if algorithm == 'BFV':
            deserialized_weights[name] = ts.bfv_vector_from(context, weight_bytes)
        else:
            deserialized_weights[name] = ts.ckks_vector_from(context, weight_bytes)   
    return deserialized_weights, metadata


def serialize_data(encrypted_model, metadata, HE_algorithm):
    data_package = {  # Create a package containing both weights and metadata
        'weights': {},
        'metadata': metadata,
        'algorithm': HE_algorithm
    }
    for name, enc_weight in encrypted_model.items(): # Serialize each encrypted weight
        data_package['weights'][name] = enc_weight.serialize()
    # Convert the entire package to bytes
    buffer = io.BytesIO()
    pickle.dump(data_package, buffer)
    return buffer.getvalue()


def federated_average(global_model, local_models):
    num_models = len(local_models)
    global_state_dict = global_model.state_dict()
    # Cache all local state dicts first to avoid repeated calls
    local_state_dicts = [model.state_dict() for model in local_models]
    # Initialize the global parameters with zeros
    for key in global_state_dict:
        global_state_dict[key] = sum([local_state_dict[key] for local_state_dict in local_state_dicts]) / num_models
    global_model.load_state_dict(global_state_dict)



def preprocess_mnist_test(dataset_addr):
    transform = transforms.Compose([
        transforms.Grayscale(num_output_channels=1),
        transforms.ToTensor(),
        transforms.Normalize((0.5,), (0.5,))  # Normalize with the same mean and std
    ])
    mnist_test_dataset = datasets.MNIST(root=dataset_addr, train=False, download=True, transform=transform)
    return mnist_test_dataset


def aggregate_bfv(encrypted_weights_list, metadata_list, num_clients):
    aggregated_weights = {}
    avg_scaling_factors = defaultdict(float)
    avg_norms = defaultdict(float)
    for metadata in metadata_list:
        for name, scale in metadata['scaling_factors'].items():
            avg_scaling_factors[name] += scale / num_clients
        for name, norm in metadata['norms'].items():
            avg_norms[name] += norm / num_clients
    for name in encrypted_weights_list[0]:
        first_weights = encrypted_weights_list[0][name]      # Initialize with first client's weights, scaled by 1/num_clients
        # For BFV, we need to use integer scaling
        scaling_factor = int(1)  # Start with scale of 1 for first client
        aggregated_weights[name] = first_weights * scaling_factor
        # Add other clients' weights with scaling compensation
        for client_idx in range(1, len(encrypted_weights_list)):
            client_weights = encrypted_weights_list[client_idx][name]
            client_scale = metadata_list[client_idx]['scaling_factors'][name]
            target_scale = avg_scaling_factors[name]
            if abs(client_scale) > 1e-10:  # Prevent division by zero
                scale_ratio = target_scale / client_scale
                # Convert to nearest integer scaling
                int_scale = int(round(scale_ratio))
                if int_scale != 0:
                    scaled_weights = client_weights * int_scale
                    aggregated_weights[name] += scaled_weights
                else:
                    aggregated_weights[name] += client_weights
            else:
                aggregated_weights[name] += client_weights   
    aggregation_metadata = {   # Store the average scaling factors and norms in metadata
        'scaling_factors': dict(avg_scaling_factors),
        'norms': dict(avg_norms),
        'num_clients': num_clients  # Store num_clients for proper rescaling during decryption
    }
    return aggregated_weights, aggregation_metadata


def aggregate_ckks(encrypted_weights_list, metadata_list, num_clients):
    aggregated_weights = {name: encrypted_weights_list[0][name].copy() 
                         for name in encrypted_weights_list[0]} # Initialize aggregated weights
    # Calculate average scaling factors
    avg_scaling_factors = defaultdict(float)
    for metadata in metadata_list:
        for name, scale in metadata['scaling_factors'].items():
            avg_scaling_factors[name] += scale / num_clients
    # Add remaining clients' weights
    for client_weights in encrypted_weights_list[1:]:
        for name in aggregated_weights:
            aggregated_weights[name] += client_weights[name]
    factor = 1.0 / num_clients 
    for name in aggregated_weights: # Average the weights
        aggregated_weights[name] *= factor
    aggregation_metadata = {  # Create metadata for CKKS
        'scaling_factors': dict(avg_scaling_factors),
        'num_clients': num_clients
    } 
    return aggregated_weights, aggregation_metadata


def aggregate_models(client_addrs,HE_algorithm,dataset_type):
    global_model=SimpleCNN(dataset_type)
    script_dir = os.path.dirname(os.path.abspath(__file__))
    main_dir = os.path.dirname(script_dir)
    if HE_algorithm!='None':
        if HE_algorithm=='BFV':
            with open(main_dir + f'/server/keys/BFV_without_priv_key.pkl', "rb") as f:
                context_bytes = pickle.load(f)
        if HE_algorithm=='CKKS':
            with open(main_dir + f'/server/keys/CKKS_without_priv_key.pkl', "rb") as f:
                context_bytes = pickle.load(f)
        HE_config = ts.context_from(context_bytes)   
        
    # Deserialize and aggregate client weights
        list_of_encrypted_weights = []
        list_of_metadata = []
        for i in client_addrs:
            local_model_path = main_dir + f'/server/files/local models/local_HE_model_{i}.bin'
            with open(local_model_path, 'rb') as f:
                serialized_data = f.read()  
    
            encrypted_weights, metadata = deserialize_data(serialized_data, HE_config)
            list_of_encrypted_weights.append(encrypted_weights)
            if HE_algorithm == "BFV":
                list_of_metadata.append(metadata)
        if not list_of_encrypted_weights:
            raise ValueError("No encrypted weights found.")
        if HE_algorithm == "BFV":
            HE_aggregated,metadata=aggregate_bfv(list_of_encrypted_weights, list_of_metadata, len(client_addrs))
        elif HE_algorithm == "CKKS":
            HE_aggregated,metadata=aggregate_ckks(list_of_encrypted_weights, list_of_metadata, len(client_addrs))
        serialized_HE_model=serialize_data(HE_aggregated,metadata,HE_algorithm) 
        return serialized_HE_model
        
    else:
        local_models = [] 
        for i in client_addrs:
            local_model_path = main_dir+ f'/server/files/local models/local_model_{i}.pth'  
            local_model=SimpleCNN(dataset_type) # Initialize local model based on the dataset type
            Loaded_model=pickle.loads (open(local_model_path,'rb').read())
            local_model.load_state_dict(Loaded_model)
            local_models.append(local_model)        # Append the local model to the list

        # Aggregate the models
        federated_average(global_model, local_models)

        if dataset_type == "MNIST":
            dataset_addr = main_dir + '/dataset/'     #'/files/test dataset/MNIST/'
            test_dataset = preprocess_mnist_test(dataset_addr)
        elif dataset_type == "UCI_HAR":              #...\dataset\UCI HAR Dataset\test
            dataset_addr = main_dir + '/dataset/UCI HAR Dataset/test/'
            x_test_file = dataset_addr + 'X_test.txt'
            y_test_file = dataset_addr + 'y_test.txt'
            x_test = np.loadtxt(x_test_file)
            y_test = np.loadtxt(y_test_file)
            label_encoder = LabelEncoder()
            y_test_encoded = label_encoder.fit_transform(y_test)
            # Convert to PyTorch tensors
            x_tensor = torch.FloatTensor(x_test)
            y_tensor = torch.LongTensor(y_test_encoded)
            test_dataset = TensorDataset(x_tensor, y_tensor)  # Combine features and labels into a TensorDataset
        global_model.eval()
        test_dataloader = DataLoader(test_dataset, batch_size=64, shuffle=False)
        all_predictions = []
        all_labels = []
        with torch.no_grad():
            for inputs, labels in test_dataloader:
                outputs = global_model(inputs)
                _, predictions = torch.max(outputs, 1)
                all_predictions.extend(predictions.cpu().numpy())
                all_labels.extend(labels.cpu().numpy())
        accuracy = accuracy_score(all_labels, all_predictions) # Calculate accuracy
        return global_model, accuracy


