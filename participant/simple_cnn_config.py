import torch
import torch.nn as nn


class SimpleCNN(torch.nn.Module):
    def __init__(self, dataset_type):
        super(SimpleCNN, self).__init__()
        self.dataset_type = dataset_type

        if dataset_type == "MNIST":
            input_size = 28  # MNIST images are 28x28
            num_classes = 10  # Digits 0-9
            self.conv1 = torch.nn.Conv2d(in_channels=1, out_channels=32, kernel_size=3, stride=1, padding=1)
            self.relu = torch.nn.ReLU()
            self.maxpool = torch.nn.MaxPool2d(kernel_size=2, stride=2)
            self.feature_dim = self._calculate_feature_dim(input_size, input_size, is_mnist=True)
            self.fc = torch.nn.Linear(self.feature_dim, num_classes)

        elif dataset_type == "UCI_HAR":
            input_size = 561  # Example input size for UCI HAR
            num_classes = 6 
            # For UCI HAR (1D input with 561 features)
            self.conv1 = torch.nn.Conv2d(in_channels=1, out_channels=32, kernel_size=(3, 1), stride=1, padding=(1, 0))
            self.relu = torch.nn.ReLU()
            self.maxpool = torch.nn.MaxPool2d(kernel_size=(2, 1), stride=(2, 1))
            self.flatten = torch.nn.Flatten()
            self.fc = torch.nn.Linear(32 * (input_size // 2), num_classes)
        else:
            raise ValueError(f"Unsupported dataset type: {dataset_type}")

    def _calculate_feature_dim(self, height, width, is_mnist):
        # Pass a dummy tensor through the layers to compute the output size
        if is_mnist:
            dummy_input = torch.zeros(1, 1, height, width)  # Shape: (batch_size, channels, height, width)
        else:
            dummy_input = torch.zeros(1, 1, width, 1)  # Shape: (batch_size, channels, features, 1)
        x = self.conv1(dummy_input)
        x = self.relu(x)
        x = self.maxpool(x)
        return x.numel()  # Total number of elements in the tensor

    def forward(self, x):
        if self.dataset_type == "MNIST":
            # Reshape to (batch_size, 1, 28, 28)
            x = x.view(x.size(0), 1, 28, 28)
        elif self.dataset_type == "UCI_HAR":
            # Reshape to (batch_size, 1, input_size, 1)
            x = x.view(x.size(0), 1, x.size(1), 1)

        x = self.conv1(x)
        x = self.relu(x)
        x = self.maxpool(x)
        if self.dataset_type == "MNIST":
            x = x.view(x.size(0), -1)  # Flatten the tensor
        elif self.dataset_type == "UCI_HAR":
            x = self.flatten(x)
        x = self.fc(x)
        return x
