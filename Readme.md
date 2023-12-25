#  Quantum-secure blockchain-based for Federated Learning IoT (FL-IoT) environments
This project is implementation of a quantum-secure blockchain-based mechanism for Federated Learning IoT (FL-IoT) environments.
It garantees post-quantum authentication of contributors in a federated learnind project based on blockchain and IPFS technology. the paper related to project can be download here.



## prerequisites
Download and run Ganache  from 
you have to install IPFS CLI (kubo) from here https://docs.ipfs.tech/how-to/kubo-basic-cli/#install-kubo

**Enable "Libp2pStreamMounting" in IPFS:**
In CLI:
```
ipfs config --json Experimental.Libp2pStreamMounting true
```


It's need to personal Ethereum blockchain Ganache. Download Here:   


```
pip install -r requirement.txt
```

git clone https://github.com/kpdemetriou/pqcrypto.git
cd pqcrypto
sudo python3 compile.py

You have to compile c files

## Run

**1. Run IPFS cli:**

```
ipfs daemon
```
2. Run Blockchain: 
Double click ganache simulation to provide us 10 accounts with 100 ETH

