// SPDX-License-Identifier: MIT
pragma solidity ^0.8.0;

contract PQB_FederatedLearning {
    address public owner;

    struct Task {
        uint round;
        string HashModel;
        uint taskId;
        address serverAddress;
        string hash_keys;
        uint project_id;
        uint DeadlineTask;
        uint creationTime;
        bool completed;
    }

    struct Client {
        address clientAddress; // Use Ethereum address as the client identifier
        uint project_id;
        int8 score;
        string hash_PubKeys;
    }

    struct Project {
        uint project_id;
        int8 cnt_clients;
        address serverAddress;
        uint transactionTime;
        string hash_init_model;
        string hash_keys;
        int8 registeredClients;
    }

    struct UpdatedModel {
        uint taskId;
        uint round;
        string HashModel;
        string hash_ct_epk;
        uint project_id;
        uint creationTime;
        address clientAddress;
    }

    struct Feedback {
        uint round;
        uint taskId;
        address clientAddress; // Use Ethereum address as the client identifier
        address serverId;
        uint project_id;
        uint transactionTime;
        bool terminate;
        bool accepted;
        int8 scoreChange;
    }

    mapping(uint => Project) public projects;
    mapping(uint => Task) public tasks;
    mapping(address => Client) public clients;
    mapping(uint => UpdatedModel) public updatedModels;
    mapping(uint => Feedback) public feedbacks;
    mapping(uint => bool) public TaskDone;
    mapping(uint => bool) public ProjectDone;

    event ProjectRegistered(uint project_id,int8 cnt_clients,address serverAddress,uint transactionTime, string hash_init_model, string hash_keys);
    event TaskPublished(uint round,string HashModel, string hash_keys, uint taskId,address serverAddress,uint project_id, uint creationTime, uint DeadlineTask);
    event ModelUpdated(uint round, string HashModel, string hash_ct_epk, uint taskId,address clientAddress, uint project_id, uint creationTime );
    event FeedbackProvided(uint round,uint taskId, uint project_id,address clientAddress, address serverId, uint transactionTime, bool accepted, int8 scoreChange,bool terminate);
    event ClientRegistered(address clientAddress,uint project_id,int8 initialScore, string hash_PubKeys);
    event ProjectTerminated(uint project_id);
    event TaskisDone(uint taskId, uint project_id);

    modifier onlyOwner() {
        require(msg.sender == owner, "Only the owner can call this function");
        _;
    }

    constructor() {
        owner = msg.sender;
    }


    // Function to register a new client
    function registerClient(string calldata hash_PubKeys, uint project_id) external {
        // Use Ethereum address as the client identifier
        require(projects[project_id].registeredClients < projects[project_id].cnt_clients, "Registration completed");
        address clientAddress = msg.sender;
        int8 initialScore = 0;
        // Store client information in the 'clients' mapping
        clients[clientAddress] = Client({
            clientAddress: clientAddress,
            score: initialScore,
            project_id:project_id,
            hash_PubKeys: hash_PubKeys
        });
        projects[project_id].registeredClients += 1;
        // Emit an event to notify external entities about the new client registration
        emit ClientRegistered(clientAddress, project_id, initialScore, hash_PubKeys);
    }


        // Register a project
    function registerProject(uint project_id, int8 cnt_clients, string memory hash_init_model, string memory hash_keys) external {
        require(!ProjectDone[project_id], "Project is already terminated");
        //require(projects[project_id].project_id == 0, "Project already exists");
        projects[project_id] = Project({
            project_id: project_id,
            cnt_clients: cnt_clients,
            serverAddress: msg.sender,
            transactionTime: block.timestamp,
            hash_init_model: hash_init_model,
            hash_keys: hash_keys,
            registeredClients: 0
        });
        emit ProjectRegistered(project_id, cnt_clients, msg.sender, block.timestamp, hash_init_model, hash_keys);
    }


    // Function to publish a new task
    function publishTask(uint r,  string memory HashModel, string memory hash_keys, uint Task_id, uint project_id, uint deadline) external onlyOwner {
        // Create a Task object
        Task memory newTask = Task({
            round: r,
            HashModel: HashModel,
            taskId: Task_id,
            project_id: project_id,
            DeadlineTask: deadline,
            hash_keys: hash_keys,
            //serverId: msg.sender, // Server address can be used as an identifier
            serverAddress:  msg.sender,
            //primaryModelId: primaryModelId,
            //ipfsAddress: Ipfs_id,
            creationTime: block.timestamp, // Current block timestamp
            completed: false
        });
        tasks[Task_id] = newTask; // Store task info in the 'tasks' mapping
        // Emit an event to notify external entities about the new task
        emit TaskPublished(r, HashModel, hash_keys, Task_id, msg.sender, project_id, block.timestamp, deadline);
    }
    

    // Function to update a model by a client
    function updateModel(uint r, string memory HashModel,string memory hash_ct_epk, uint Task_id, uint project_id) external {
        // Validate inputs (add more validation as needed)
        require(bytes(HashModel).length > 0, "Model hash cannot be empty");
        // Check if the task exists
        require(tasks[Task_id].taskId != 0, "Task does not exist");
        // Get the client address from the sender address
        address clientAddress = msg.sender;
        // Create an UpdatedModel object
        UpdatedModel memory updatedModel = UpdatedModel({
            round: r,
            taskId: Task_id,
            clientAddress: clientAddress,
            HashModel: HashModel,
            hash_ct_epk: hash_ct_epk,
            creationTime: block.timestamp, // Current block timestamp
            project_id: project_id
        });
        updatedModels[Task_id] = updatedModel;  // Store updated model info in the 'updatedModels' mapping
        // Emit an event to notify the server about the updated model
        emit ModelUpdated(r, HashModel, hash_ct_epk,Task_id, msg.sender, project_id, block.timestamp);
    }


    // Function to provide feedback by the server
    function provideFeedback(uint r, uint taskId,uint project_id ,address clientAddress , int8 scoreChange,bool termination ) external onlyOwner {
        // Validate inputs (add more validation as needed)
        require(tasks[taskId].taskId != 0, "Task does not exist");
        // Ensure the task is completed before providing feedback
        //require(tasks[taskId].completed, "Task is not completed");
        address serverId = msg.sender; // Get the server ID from the owner address
        // Record the feedback information
        Feedback memory feedback = Feedback({
            round: r,
            taskId: taskId,
            terminate:termination,
            project_id: project_id,
            clientAddress: clientAddress,
            serverId: serverId,
            transactionTime: block.timestamp,
            accepted: true,
            scoreChange: scoreChange
        });
        feedbacks[taskId] = feedback;   // Store feedback info in the 'feedbacks' mapping
        updateClientScore(clientAddress, scoreChange);   // Update the clients score based on the feedback
        // Emit an event to notify about the provided feedback
        emit FeedbackProvided(r, taskId, project_id, clientAddress, serverId, block.timestamp, true, scoreChange,termination);
    }
    

    // Function to update the clients score based on the feedback
    function updateClientScore(address clientAddress, int8 scoreChange) internal {
        // Update the client score
        clients[clientAddress].score += scoreChange;
        // You can add more logic based on your specific scoring requirements
        if (clients[clientAddress].score < 0) {
            clients[clientAddress].score = 0;
        }
    }


    function finishProject(uint project_id) external onlyOwner {
        require(projects[project_id].project_id != 0, "Project does not exist");
        require(!ProjectDone[project_id], "Project is already terminated");
        ProjectDone[project_id] = true;
        // Emit an event to notify about project termination
        emit ProjectTerminated(project_id);
    }

    function finishTask(uint taskId, uint projectId) external onlyOwner {
    // Ensure the project exists
        require(tasks[taskId].taskId != 0, "Task does not exist");
        require(tasks[taskId].project_id == projectId, "Task does not belong to the specified project");
        require(!TaskDone[taskId], "Task is already marked as done");
        TaskDone[taskId] = true; // Mark the project as terminated
    // Emit an event to notify about project termination
    emit TaskisDone(taskId, projectId);
    }


    function isTaskDone(uint taskId, uint projectId) external view returns (bool) {
        // Ensure the task exists and belongs to the specified project
        require(tasks[taskId].project_id == projectId, "Task does not belong to the specified project");
        return TaskDone[taskId];    // Return the termination status
    }


    // Function to check if a project is terminated
    function isProjectTerminated(uint project_id) external view returns (bool) {
       return ProjectDone[project_id];
    }


    // Function to generate a unique task ID (replace with your own logic)
    function generateUniqueTaskId() internal view returns (uint) {
        // Implement your logic to generate a unique task ID
        // This could involve incrementing a counter or using another method
        return block.number + 1; // Placeholder, replace with your own logic
    }
}
