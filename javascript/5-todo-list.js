/**
 * TODO List Application
 * 
 * A command-line todo list manager that demonstrates:
 * - Object-oriented programming concepts
 * - Array manipulation methods
 * - Async/await for user input
 * - Error handling
 * - Data filtering and sorting
 * 
 * Features:
 * - Add new todos with title, description, and priority
 * - List all todos with completion status
 * - Mark todos as completed
 * - Remove todos
 * - Filter todos by priority
 * - Persistent storage using arrays
 * 
 * @author Ibrahim
 * @version 1.0
 */

const readline = require('readline').createInterface({
    input: process.stdin,
    output: process.stdout
});

// Initialize an empty array to store todo items
const todoList = [];

/**
 * Adds a new todo item to the list
 * @param {string} title - The title of the todo
 * @param {string} description - The description of the todo
 * @param {string} [priority="medium"] - The priority level (low, medium, high)
 */
function addTodo(title, description, priority = "medium") {
    const todoItem = {
        id: todoList.length + 1,
        title,
        description,
        priority,
        completed: false
    };
    
    todoList.push(todoItem);
    console.log(`Added: ${title}`);
}

/**
 * Displays all todos in the list
 */
function listTodos() {
    if (todoList.length === 0) {
        console.log("No todos found. Your list is empty!");
        return;
    }
    
    console.log("\n=== YOUR TODO LIST ===");
    todoList.forEach(item => {
        const status = item.completed ? "✓" : " ";
        console.log(`${status} [${item.id}] ${item.title} - ${item.description} (Priority: ${item.priority})`);
    });
}

/**
 * Marks a todo as completed
 * @param {number} todoId - The ID of the todo to mark as completed
 */
function markCompleted(todoId) {
    const todo = todoList.find(item => item.id === todoId);
    if (todo) {
        todo.completed = true;
        console.log(`Marked as completed: ${todo.title}`);
    } else {
        console.log(`Todo with ID ${todoId} not found.`);
    }
}

/**
 * Removes a todo from the list
 * @param {number} todoId - The ID of the todo to remove
 */
function removeTodo(todoId) {
    const index = todoList.findIndex(item => item.id === todoId);
    if (index !== -1) {
        const removedItem = todoList.splice(index, 1)[0];
        console.log(`Removed: ${removedItem.title}`);
    } else {
        console.log(`Todo with ID ${todoId} not found.`);
    }
}

/**
 * Filters and displays todos by priority
 * @param {string} priority - The priority level to filter by
 */
function filterByPriority(priority) {
    const filteredTodos = todoList.filter(item => item.priority === priority);
    
    if (filteredTodos.length === 0) {
        console.log(`No todos found with priority: ${priority}`);
        return;
    }
    
    console.log(`\n=== TODOS WITH PRIORITY: ${priority.toUpperCase()} ===`);
    filteredTodos.forEach(item => {
        const status = item.completed ? "✓" : " ";
        console.log(`${status} [${item.id}] ${item.title} - ${item.description}`);
    });
}

/**
 * Prompts the user with a question and returns their response
 * @param {string} question - The question to ask the user
 * @returns {Promise<string>} The user's response
 */
async function askQuestion(question) {
    return new Promise((resolve) => {
        readline.question(question, resolve);
    });
}

/**
 * Main application loop
 */
async function main() {
    console.log("=== TODO LIST APPLICATION ===");
    console.log("This program helps you manage your todo list.");
    
    while (true) {
        console.log("\nOptions:");
        console.log("1. Add a new todo");
        console.log("2. List all todos");
        console.log("3. Mark a todo as completed");
        console.log("4. Remove a todo");
        console.log("5. Filter todos by priority");
        console.log("6. Exit");
        
        const choice = await askQuestion("\nEnter your choice (1-6): ");
        
        if (choice === '6') {
            console.log("Goodbye!");
            readline.close();
            break;
        }
        
        switch (choice) {
            case '1':
                const title = await askQuestion("Enter todo title: ");
                const description = await askQuestion("Enter todo description: ");
                let priority = (await askQuestion("Enter priority (low, medium, high) [default: medium]: ")).toLowerCase();
                
                if (!['low', 'medium', 'high'].includes(priority)) {
                    priority = 'medium';
                }
                
                addTodo(title, description, priority);
                break;
                
            case '2':
                listTodos();
                break;
                
            case '3':
                const completeId = parseInt(await askQuestion("Enter the ID of the todo to mark as completed: "));
                if (!isNaN(completeId)) {
                    markCompleted(completeId);
                } else {
                    console.log("Please enter a valid ID (number).");
                }
                break;
                
            case '4':
                const removeId = parseInt(await askQuestion("Enter the ID of the todo to remove: "));
                if (!isNaN(removeId)) {
                    removeTodo(removeId);
                } else {
                    console.log("Please enter a valid ID (number).");
                }
                break;
                
            case '5':
                const filterPriority = (await askQuestion("Enter priority to filter by (low, medium, high): ")).toLowerCase();
                if (['low', 'medium', 'high'].includes(filterPriority)) {
                    filterByPriority(filterPriority);
                } else {
                    console.log("Invalid priority. Please enter low, medium, or high.");
                }
                break;
                
            default:
                console.log("Invalid choice. Please enter a number between 1 and 6.");
        }
    }
}

// Start the application
main().catch(console.error); 