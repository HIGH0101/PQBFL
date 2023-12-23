// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract FederatedLearningContract {
    address public owner;

    struct Task {
        uint taskId;
        address serverId;
        //uint primaryModelId;
        string ipfsAddress;
        uint creationTime;
        bool completed;
    }

    struct Client {
        address clientAddress; // Use Ethereum address as the client identifier
        int8 score;
    }

    struct ProjectRegistration {
        uint taskId;
        address clientAddress;
        uint transactionTime;
        string signature; // Signature of the client
        string initialDataset; // Initial dataset
        string modelHash;

    }

    struct UpdatedModel {
        uint taskId;
        address clientAddress; // Use Ethereum address as the client identifier
        string modelHash; // Hash of the model
        // string clientSignature; // Signature of the client
        string ipfsId; // IPFS ID
    }

    struct Feedback {
        uint taskId;
        address clientAddress; // Use Ethereum address as the client identifier
        address serverId;
        uint transactionTime;
        bool accepted;
        int8 scoreChange;
    }
    mapping(uint => ProjectRegistration) public projectRegistrations;
    mapping(uint => Task) public tasks;
    mapping(address => Client) public clients;
    mapping(uint => UpdatedModel) public updatedModels;
    mapping(uint => Feedback) public feedbacks;

    event ProjectRegistered(uint taskId, address clientAddress, uint transactionTime);
    event TaskPublished(uint taskId, address serverId, string ipfsAddress, uint creationTime);
    event ModelUpdated(uint taskId, address clientAddress, string modelHash, string ipfsId);
    event FeedbackProvided(uint taskId, address clientAddress, address serverId, uint transactionTime, bool accepted, int8 scoreChange);
    event ClientRegistered(address clientAddress, int8 initialScore);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only the owner can call this function");
        _;
    }

    constructor() {
        owner = msg.sender;
    }

    // Function to register a new client
    function registerClient() external {
        // Use Ethereum address as the client identifier
        address clientAddress = msg.sender;

        // Initialize the client's score (you can set it to zero initially)
        int8 initialScore = 0;

        // Store client information in the 'clients' mapping
        clients[clientAddress] = Client({
            clientAddress: clientAddress,
            score: initialScore
        });

        // Emit an event to notify external entities about the new client registration
        emit ClientRegistered(clientAddress, initialScore);
    }

    function registerProject(uint taskId, string memory initialDataset, string memory initialModelHash, string memory signature) external {
        //require(tasks[taskId].taskId != 0, "Task does not exist");
        require(!tasks[taskId].completed, "Task is already completed");

        address clientAddress = tasks[taskId].serverId;
        /*
        UpdatedModel memory updatedModel = UpdatedModel({
            taskId: taskId,
            clientAddress: clientAddress,
            modelHash: initialModelHash,
            ipfsId: ""
        });
        */
        ProjectRegistration memory projectReg = ProjectRegistration({
            taskId: taskId,
            clientAddress: clientAddress,
            transactionTime: block.timestamp,
            signature: signature,
            initialDataset: initialDataset,
            modelHash:initialModelHash
        });

        projectRegistrations[taskId] = projectReg;

        // Emit the ProjectRegistered event to notify external entities
        emit ProjectRegistered(taskId, clientAddress, block.timestamp);
        //updatedModels[taskId] = updatedModel;
        //emit ModelUpdated(taskId, clientAddress, initialModelHash, "");
        //tasks[taskId].completed = true;
        //emit FeedbackProvided(taskId, clientAddress, owner, block.timestamp, true, 0);
    }

    // Function to publish a new task
    function publishTask(string memory ipfsAddress) external onlyOwner {
        // Generate a unique task ID
        uint taskId = generateUniqueTaskId();

        // Validate inputs (add more validation as needed)
        //require(primaryModelId > 0, "Invalid primary model ID");
        require(bytes(ipfsAddress).length > 0, "IPFS address cannot be empty");

        // Create a Task object
        Task memory newTask = Task({
            taskId: taskId,
            serverId: msg.sender, // Server's address can be used as an identifier
            //primaryModelId: primaryModelId,
            ipfsAddress: ipfsAddress,
            creationTime: block.timestamp, // Current block timestamp
            completed: false
        });

        // Store task information in the 'tasks' mapping
        tasks[taskId] = newTask;

        // Emit an event to notify external entities about the new task
        emit TaskPublished(taskId, msg.sender, ipfsAddress, block.timestamp);
    }

    // Function to update a model by a client
    function updateModel(uint taskId, string memory modelHash, string memory ipfsId) external {
        // Validate inputs (add more validation as needed)
        require(bytes(modelHash).length > 0, "Model hash cannot be empty");
        // require(bytes(clientSignature).length > 0, "Client signature cannot be empty");
        require(bytes(ipfsId).length > 0, "IPFS ID cannot be empty");

        // Check if the task exists
        require(tasks[taskId].taskId != 0, "Task does not exist");

        // Get the client address from the sender's address
        address clientAddress = msg.sender;

        // Create an UpdatedModel object
        UpdatedModel memory updatedModel = UpdatedModel({
            taskId: taskId,
            clientAddress: clientAddress,
            modelHash: modelHash,
            ipfsId: ipfsId
        });

        // Store updated model information in the 'updatedModels' mapping
        updatedModels[taskId] = updatedModel;

        // Emit an event to notify the server about the updated model
        emit ModelUpdated(taskId, clientAddress, modelHash, ipfsId);
    }

    // Function to provide feedback by the server
    function provideFeedback(uint taskId, bool accepted, int8 scoreChange) external onlyOwner {
        // Validate inputs (add more validation as needed)
        require(tasks[taskId].taskId != 0, "Task does not exist");

        // Ensure the task is completed before providing feedback
        require(tasks[taskId].completed, "Task is not completed");

        // Get the server ID from the owner's address
        address serverId = msg.sender;

        // Get the client ID from the task
        address clientAddress = tasks[taskId].serverId;

        // Record the feedback information
        Feedback memory feedback = Feedback({
            taskId: taskId,
            clientAddress: clientAddress,
            serverId: serverId,
            transactionTime: block.timestamp,
            accepted: accepted,
            scoreChange: scoreChange
        });

        // Store feedback information in the 'feedbacks' mapping
        feedbacks[taskId] = feedback;

        // Update the client's score based on the feedback
        updateClientScore(clientAddress, scoreChange);

        // Emit an event to notify about the provided feedback
        emit FeedbackProvided(taskId, clientAddress, serverId, block.timestamp, accepted, scoreChange);
    }

    // Function to update the client's score based on the feedback
    function updateClientScore(address clientAddress, int8 scoreChange) internal {
        // Update the client's score
        clients[clientAddress].score += scoreChange;

        // Ensure the score is within a certain range (optional)
        // You can add more logic based on your specific scoring requirements
        if (clients[clientAddress].score < 0) {
            clients[clientAddress].score = 0;
        }

        // Additional logic for rewarding or penalizing the client based on the feedback
        // Add your own reward/penalty mechanism based on the feedback
    }
    
    // Function to get the client ID based on the client's address
    //function getClientId(address clientAddress) internal view returns (uint) {
        // Implement your logic to retrieve the client ID based on the address
        // This could involve iterating through 'clients' mapping or using another lookup mechanism
        // For simplicity, let's assume the client's address is the client ID
    //    return clientAddress;
    //}

    // Function to generate a unique task ID (replace with your own logic)
    function generateUniqueTaskId() internal view returns (uint) {
        // Implement your logic to generate a unique task ID
        // This could involve incrementing a counter or using another method
        return block.number + 1; // Placeholder, replace with your own logic
    }
}
