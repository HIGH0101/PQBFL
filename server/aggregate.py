"""
Created on Wed Jan  3 18:07:07 2024

@author: HIGHer
"""
import os
import torch
from torch.utils.data import DataLoader, TensorDataset
import numpy as np
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import LabelEncoder
import pickle
import tenseal as ts


def deserialize_data(serialized_data, context,HE_algorithm):
    # Load data from bytes without context metadata
    serialized_weights = pickle.loads(serialized_data) 
    # Deserialize weights into TenSEAL BFV vectors using provided context
    deserialized_weights = {}
    for name, weight_bytes in serialized_weights.items():
        if HE_algorithm=='BFV':
            deserialized_weights[name] = ts.bfv_vector_from(context, weight_bytes)  # deserialize with context
        else:
            deserialized_weights[name] = ts.ckks_vector_from(context, weight_bytes)  # deserialize with context
    return deserialized_weights

'''
def load_encrypted_weights(file_path, context):
    encrypted_weights = {}
    with open(file_path, 'rb') as f:
        while True:
            # Read the length of the parameter name (4 bytes)
            name_len_bytes = f.read(4)
            if len(name_len_bytes) == 0:
                break  # End of file reached
            # Convert the length bytes to an integer
            name_len = int.from_bytes(name_len_bytes, 'big')
            # Read the parameter name (as binary and decode)
            name = f.read(name_len).decode('utf-8')
            # Read the length of the serialized data (4 bytes)
            length = int.from_bytes(f.read(4), 'big')
            # Read the serialized data
            serialized_weight = f.read(length)
            # Deserialize the weight back into a BFVVector using the context
            encrypted_weights[name] = ts.bfv_vector_from(context, serialized_weight)
    return encrypted_weights
'''

# Federated Averaging
def federated_average(global_model, local_models):
    num_models = len(local_models)
    # Initialize an empty state_dict for the global model
    global_state_dict = global_model.state_dict()
    # Aggregate the parameters from local models
    for local_model in local_models:
        local_state_dict = local_model.state_dict()
        for key in global_state_dict:
            # Perform federated averaging
            global_state_dict[key] += local_state_dict[key] / num_models
    # Update the global model with the aggregated parameters
    global_model.load_state_dict(global_state_dict)


def aggregate_models(client_addrs,HE_algorithm):

    # Define your a SimpleCNN model
    class SimpleCNN(torch.nn.Module):
        def __init__(self, input_size, num_classes):
            super(SimpleCNN, self).__init__()
            # Assuming input_size is the number of features in each sample

            # Reshape the input to (batch_size, 1, input_size, 1)
            self.conv1 = torch.nn.Conv2d(in_channels=1, out_channels=32, kernel_size=(3, 1), stride=1, padding=(1, 0))
            self.relu = torch.nn.ReLU()
            self.maxpool = torch.nn.MaxPool2d(kernel_size=(2, 1), stride=(2, 1))
            self.flatten = torch.nn.Flatten()
            self.fc = torch.nn.Linear(32 * (input_size // 2), num_classes)

        def forward(self, x):
            # Reshape the input to (batch_size, 1, input_size, 1)
            x = x.view(x.size(0), 1, x.size(1), 1)
            x = self.conv1(x)
            x = self.relu(x)
            x = self.maxpool(x)
            x = self.flatten(x)
            x = self.fc(x)
            return x
        
        # Initialize a global model with the same architecture
    input_size = 561  # number of features
    num_classes = 6  # Replace with the actual number of classes in your data
    global_model = SimpleCNN(input_size, num_classes)
    main_dir = os.path.dirname(__file__)

    if HE_algorithm!='None':

        if HE_algorithm=='BFV':
            with open(main_dir + f'/keys/BFV_without_priv_key.pkl', "rb") as f:
                context_bytes = pickle.load(f)
        if HE_algorithm=='CKKS':
            with open(main_dir + f'/keys/CKKS_without_priv_key.pkl', "rb") as f:
                context_bytes = pickle.load(f)

        HE_config = ts.context_from(context_bytes)

    # Deserialize and aggregate client weights
        list_of_encrypted_weights = []
        for i in client_addrs:
            local_model_path = main_dir + f'/files/models/local_HE_model_{i}.bin'
            with open(local_model_path, 'rb') as f:
                serialized_data = f.read()  
            # Deserialize the data using shared context
            encrypted_weights = deserialize_data(serialized_data, HE_config,HE_algorithm)
            list_of_encrypted_weights.append(encrypted_weights)
        if not list_of_encrypted_weights:
            raise ValueError("No encrypted weights found.")

        # Initialize the aggregated weights dictionary using the first client's encrypted weights
        aggregated_weights = {name: list_of_encrypted_weights[0][name].copy() for name in list_of_encrypted_weights[0]}
        # Aggregate by adding weights homomorphically
        for client_weights in list_of_encrypted_weights[1:]:
            for name in client_weights:
                aggregated_weights[name] += client_weights[name]  # Homomorphic addition
        return aggregated_weights
    
    else:
        local_models = [] 
        for i in client_addrs:
            local_model_path = main_dir+ f'/files/models/local_model_{i}.pth'
            local_model = SimpleCNN(input_size, num_classes)               # Initialize a local model
            Loaded_model=pickle.loads (open(local_model_path,'rb').read())
            local_model.load_state_dict(Loaded_model)
            local_models.append(local_model)        # Append the local model to the list

        # Aggregate the models
        federated_average(global_model, local_models)

        #...\dataset\UCI HAR Dataset\test
        x_test_file = main_dir+f'/files/test dataset/X_test.txt'
        y_test_file = main_dir+f'/files/test dataset/y_test.txt'

        x_test = np.loadtxt(x_test_file)
        y_test = np.loadtxt(y_test_file)

        label_encoder = LabelEncoder()
        y_test_encoded = label_encoder.fit_transform(y_test)
        # Convert to PyTorch tensors
        x_tensor = torch.FloatTensor(x_test)
        y_tensor = torch.LongTensor(y_test_encoded)

        # Combine features and labels into a TensorDataset
        test_dataset = TensorDataset(x_tensor, y_tensor)

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

        # Calculate accuracy
        accuracy = accuracy_score(all_labels, all_predictions)
        #print(f'Test Accuracy on global model: {accuracy:.4f}')

        return global_model, accuracy
        #torch.save(global_model.state_dict(), main_dir+'/files/global_model.pth')

