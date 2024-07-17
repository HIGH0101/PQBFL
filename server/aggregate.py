# -*- coding: utf-8 -*-
"""
Created on Wed Jan  3 18:07:07 2024

@author: tester
"""
import os
import torch
from torch.utils.data import DataLoader, TensorDataset
import numpy as np
from sklearn.metrics import accuracy_score
from sklearn.preprocessing import LabelEncoder


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


def aggregate_models(client_addrs):

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

    local_models = [] 
    for i in client_addrs:
        local_model_path = main_dir+ f'/files/models/local_model_{i}.pth'
        local_model = SimpleCNN(input_size, num_classes)               # Initialize a local model
        local_model.load_state_dict(torch.load(local_model_path))      # Load the state_dict from the saved model file
        local_models.append(local_model)        # Append the local model to the list


    # Aggregate the models
    federated_average(global_model, local_models)


    #C:\Users\tester\Desktop\Post-quantum_Authentication_FL\dataset\UCI HAR Dataset\test
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

    #global_model=local_model 

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
    print(f'Test Accuracy on global model: {accuracy:.4f}')

    # Save the globally aggregated model
    torch.save(global_model.state_dict(), main_dir+'/files/global_model.pth')

