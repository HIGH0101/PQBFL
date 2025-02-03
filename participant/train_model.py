"""
Created on Tue Jan  2 14:18:41 2024

@author: HIGHer
"""  

import os, pickle
import torch
from torch.utils.data import TensorDataset, DataLoader, random_split
import numpy as np
from sklearn.preprocessing import LabelEncoder
from torchvision import datasets, transforms

from simple_cnn_config import SimpleCNN 


def train_model(model, dataloader, validation_dataloader, criterion, optimizer, epochs, device):
    print_every = len(dataloader)
    model.to(device)
    for epoch in range(epochs):
        running_loss = 0.0
        model.train()
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


def preprocess_uci_har(dataset_addr):
    x_train_file = dataset_addr + 'X_train.txt'
    y_train_file = dataset_addr + 'y_train.txt'
    x_train = np.loadtxt(x_train_file)
    y_train = np.loadtxt(y_train_file)
    label_encoder = LabelEncoder()
    y_train_encoded = label_encoder.fit_transform(y_train)
    x_tensor = torch.FloatTensor(x_train)
    y_tensor = torch.LongTensor(y_train_encoded)
    dataset = TensorDataset(x_tensor, y_tensor)
    input_size = x_train.shape[1]  # Number of features per sample
    return dataset, input_size

def preprocess_mnist(dataset_addr):
    transform = transforms.Compose([
        transforms.Grayscale(num_output_channels=1),
        transforms.ToTensor(),
        transforms.Normalize((0.5,), (0.5,))
    ])
    mnist_dataset = datasets.MNIST(root=dataset_addr, train=True, download=True, transform=transform)
    input_size = 28  # MNIST images are 28x28
    return mnist_dataset, input_size


def train(global_model,num_epochs, dataset_type):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    main_dir = os.path.dirname(script_dir)
    if dataset_type == "UCI_HAR":
        dataset_addr = main_dir + '/dataset/UCI HAR Dataset/train/'
        dataset, input_size=preprocess_uci_har(dataset_addr)
    # Split UCI HAR dataset into multiple parts should be remove after the experiment-----
        #if not os.path.exists(os.path.join(os.path.dirname(dataset_addr), 'split_UCI_HAR')):
        #    split_uci_har(dataset_addr)
        #if part_number is None:
        #    raise ValueError("For federated learning, each client must specify a dataset part number!")
        #dataset, input_size = load_uci_har_part(dataset_addr, part_number)
    #------------------------
    elif dataset_type == "MNIST":
        dataset_addr = main_dir + '/dataset/'
        dataset, input_size = preprocess_mnist(dataset_addr)
    else:
        raise ValueError("Unsupported dataset type!")
    torch.manual_seed(42)

        # Shuffle the dataset
    if isinstance(dataset, TensorDataset):
        data, targets = dataset.tensors
        shuffled_indices = torch.randperm(len(data))
        shuffled_dataset = TensorDataset(data[shuffled_indices], targets[shuffled_indices])
    else:
        shuffled_dataset = dataset

    train_size = int(0.8 * len(shuffled_dataset))
    validation_size = len(shuffled_dataset) - train_size
    train_dataset, validation_dataset = random_split(shuffled_dataset, [train_size, validation_size])

    train_dataloader = DataLoader(train_dataset, batch_size=64, shuffle=True)
    validation_dataloader = DataLoader(validation_dataset, batch_size=64)

    model = SimpleCNN(dataset_type=dataset_type)
    global_model=pickle.loads (global_model)  # convert the string to model structure
    model.load_state_dict(global_model)    # apply recieved global model to local model
    criterion = torch.nn.CrossEntropyLoss()
    optimizer = torch.optim.Adam(model.parameters(), lr=0.001)
    train_model(model, train_dataloader, validation_dataloader, criterion, optimizer, num_epochs, device='cpu')
    return model


def evaluate_model_on_test_data(model, dataset_type, device, batch_size=64):
    test_dataloader = prepare_test_dataset(dataset_type, batch_size)
    model.eval()
    total_correct = 0
    total_samples = 0
    with torch.no_grad():
        for inputs, labels in test_dataloader:
            inputs, labels = inputs.to(device), labels.to(device)
            outputs = model(inputs)
            _, predicted = torch.max(outputs, 1)
            total_samples += labels.size(0)
            total_correct += (predicted == labels).sum().item()
    accuracy = total_correct / total_samples
    print(f'Test Accuracy: {accuracy:.5f}')
    return accuracy


def prepare_test_dataset(dataset_type, batch_size):
    script_dir = os.path.dirname(os.path.abspath(__file__))
    main_dir = os.path.dirname(script_dir)
    if dataset_type == "UCI_HAR":
        dataset_addr = main_dir + '/dataset/UCI HAR Dataset/test/'
        x_test_file = dataset_addr + 'X_test.txt'
        y_test_file = dataset_addr + 'y_test.txt'
        x_test = np.loadtxt(x_test_file)
        y_test = np.loadtxt(y_test_file)
        label_encoder = LabelEncoder()
        y_test_encoded = label_encoder.fit_transform(y_test)
        x_tensor = torch.FloatTensor(x_test)
        y_tensor = torch.LongTensor(y_test_encoded)
        test_dataset = TensorDataset(x_tensor, y_tensor)
    elif dataset_type == "MNIST":
        dataset_addr = main_dir + '/dataset/'
        transform = transforms.Compose([
            transforms.Grayscale(num_output_channels=1),
            transforms.ToTensor(),
            transforms.Normalize((0.5,), (0.5,))
        ])
        test_dataset = datasets.MNIST(root=dataset_addr, train=False, download=True, transform=transform)
    else:
        raise ValueError(f"Unsupported dataset type: {dataset_type}. Supported types are 'MNIST' and 'UCI_HAR'.")
    
    test_dataloader = DataLoader(test_dataset, batch_size=batch_size, shuffle=False)
    return test_dataloader

'''
## UCI HAR dataset utilities    should be remove after the experiment

def split_uci_har(dataset_addr, num_splits=5):
    """Splits UCI HAR dataset into multiple parts and saves them."""
    x_train_file = dataset_addr + 'X_train.txt'
    y_train_file = dataset_addr + 'y_train.txt'
    
    x_train = np.loadtxt(x_train_file)
    y_train = np.loadtxt(y_train_file)
    
    label_encoder = LabelEncoder()
    y_train_encoded = label_encoder.fit_transform(y_train)

    # Split dataset into `num_splits` parts
    split_size = len(x_train) // num_splits
    split_dir = os.path.join(os.path.dirname(dataset_addr), 'split_UCI_HAR')

    if not os.path.exists(split_dir):
        os.makedirs(split_dir)

    for i in range(num_splits):
        start = i * split_size
        end = (i + 1) * split_size if i != num_splits - 1 else len(x_train)

        np.save(os.path.join(split_dir, f'X_train_part_{i}.npy'), x_train[start:end])
        np.save(os.path.join(split_dir, f'y_train_part_{i}.npy'), y_train_encoded[start:end])

    print(f"Dataset split into {num_splits} parts and saved in {split_dir}")

def load_uci_har_part(dataset_addr, part_number):
    """Loads a specific partition of UCI HAR dataset."""
    split_dir = os.path.join(os.path.dirname(dataset_addr), 'split_UCI_HAR')

    x_train = np.load(os.path.join(split_dir, f'X_train_part_{part_number}.npy'))
    y_train = np.load(os.path.join(split_dir, f'y_train_part_{part_number}.npy'))

    x_tensor = torch.FloatTensor(x_train)
    y_tensor = torch.LongTensor(y_train)

    dataset = TensorDataset(x_tensor, y_tensor)
    input_size = x_train.shape[1]

    return dataset, input_size
'''