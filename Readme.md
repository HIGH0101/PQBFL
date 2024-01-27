#  Quantum-secure and blockchain-based Federated Learning in IoT (FL-IoT)
This project is implementation of a quantum-secure blockchain-based framework for Federated Learning IoT (FL-IoT) environments.
It garantees post-quantum authentication of contributors in a federated learnind project based on blockchain and IPFS technology. the paper related to project can be download here.



## prerequisites

**1. Download  Ganache  from:** https://trufflesuite.com/ganache/

**2. you have to install IPFS CLI (kubo) from here:** https://docs.ipfs.tech/how-to/kubo-basic-cli/#install-kubo

**2. Enable "Libp2pStreamMounting" in IPFS:**
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

**2. Run Blockchain:** 

Double click ganache emulation to provide us 10 accounts with 100 ETH

**3. Compile and Deploy**

you must compile and deploy the solidity contract on Ethereum blockchain(gnanache) 


## Note
Currently, the existing implementation does not support previously released tasks and only checks the last block for the current task. This means that if the server first publishes the task while the clients are not listening to receive the task, these clients cannot receive the previously published task. Therefore, clients should first start listening to receive a task as soon as it is published on the server. This is more of a programming problem for the industrial version, and in our academic framework, there is no need to implement it at the moment, and this amount is sufficient for our experiments. It can be considered for the next steps.


**to do:**
In order for clients to be aware of tasks that have been published in the past and receive them, the client must check the blocks before the last block to receive the event related to a task that has already been published. But this work requires the management of tasks on the client and server side, and the codes must also be changed. For example

    - The client must be able to distinguish between past and present tasks.
    - The server should be able to manage and integrate the tasks based on the identifiers that come from the clients. For example, one client updates and sends Task 12 and another one sends Task 13...
    - I commented the client-side code to filter the previous blocks in the listen_for_task() function

