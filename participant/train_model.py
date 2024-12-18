"""
Created on Tue Jan  2 14:18:41 2024

@author: HIGHer
"""  

import os
import torch
from torch.utils.data import TensorDataset, DataLoader
import numpy as np
from sklearn.preprocessing import LabelEncoder

# Define the SimpleCNN model globally (outside the train function)
class SimpleCNN(torch.nn.Module):
    def __init__(self, input_size, num_classes):
        super(SimpleCNN, self).__init__()
        # Assuming input_size is the number of features in each sample
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

# Function for training on a given dataset
def train_model(model, dataloader, validation_dataloader, criterion, optimizer, epochs, device):
    print_every = len(dataloader)
    model.to(device)
    for epoch in range(epochs):
        running_loss = 0.0
        for i, (inputs, labels) in enumerate(dataloader, 1):
            inputs, labels = inputs.to(device), labels.to(device)
            optimizer.zero_grad()
            outputs = model(inputs)
            loss = criterion(outputs, labels)
            loss.backward()
            optimizer.step()
            running_loss += loss.item()
            if i % print_every == 0:
                print(f'Epoch {epoch+1}, Batch {i}/{len(dataloader)}, Loss: {running_loss/print_every:.4f}')
                running_loss = 0.0

        validate_model(model, validation_dataloader, device)

# Validation function
def validate_model(model, dataloader, device):
    model.eval()
    total_correct = 0
    total_samples = 0
    with torch.no_grad():
        for inputs, labels in dataloader:
            inputs, labels = inputs.to(device), labels.to(device)
            outputs = model(inputs)
            _, predicted = torch.max(outputs, 1)
            total_samples += labels.size(0)
            total_correct += (predicted == labels).sum().item()
    
    accuracy = total_correct / total_samples
    print(f'Validation Accuracy: {accuracy:.4f}')

# Main training function
def train(num_epochs, dataset_addr, num_classes):
    #script_dir = os.path.dirname(os.path.abspath(__file__))
    #main_dir = os.path.dirname(script_dir)
    x_train_file=dataset_addr+'X_train.txt'
    y_train_file=dataset_addr+'y_train.txt'

    #x_train_file = main_dir + '/dataset/UCI HAR Dataset/train/X_train.txt'
    #y_train_file = main_dir + '/dataset/UCI HAR Dataset/train/y_train.txt'

    # Load features and labels
    x_train = np.loadtxt(x_train_file)
    y_train = np.loadtxt(y_train_file)

    label_encoder = LabelEncoder()
    y_train_encoded = label_encoder.fit_transform(y_train)
    
    # Convert to PyTorch tensors
    x_tensor = torch.FloatTensor(x_train)
    y_tensor = torch.LongTensor(y_train_encoded)

    # Combine features and labels into a TensorDataset
    dataset = TensorDataset(x_tensor, y_tensor)

    # Set random seed for reproducibility
    torch.manual_seed(42)

    # Shuffle the dataset
    shuffled_indices = torch.randperm(len(dataset))
    shuffled_dataset = TensorDataset(x_tensor[shuffled_indices], y_tensor[shuffled_indices])

    # Instantiate the model
    #num_classes = 6
    input_size = x_train.shape[1] 
    model = SimpleCNN(input_size=input_size, num_classes=num_classes)

    # Define training parameters
    criterion = torch.nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)

    # Split the shuffled dataset into training and validation sets
    train_size = int(0.8 * len(shuffled_dataset))
    validation_size = len(shuffled_dataset) - train_size
    train_dataset, validation_dataset = torch.utils.data.random_split(shuffled_dataset, [train_size, validation_size])

    # Define your dataloaders for training and validation
    train_dataloader = DataLoader(train_dataset, batch_size=64, shuffle=True)
    validation_dataloader = DataLoader(validation_dataset, batch_size=64)

    # Training the model
    train_model(model, train_dataloader, validation_dataloader, criterion, optimizer, num_epochs, device='cpu')

    # Save the entire model (since it is now defined globally, this won't throw a pickle error)
    #torch.save(model, main_dir + f'/participant/files/local_model_{client_eth_address}.pth')
    return model

