/**
 * Simple Calculator with Error Handling
 * 
 * A command-line calculator that demonstrates:
 * - Basic arithmetic operations
 * - Error handling with try-catch blocks
 * - Input validation
 * - Async/await for user input
 * - Switch statements
 * - Function organization
 * 
 * Features:
 * - Addition, subtraction, multiplication, and division
 * - Division by zero error handling
 * - Invalid input validation
 * - Continuous operation until user exits
 * - Clean error messages
 * 
 * @author Ibrahim
 * @version 1.0
 */

const readline = require('readline').createInterface({
    input: process.stdin,
    output: process.stdout
});

/**
 * Adds two numbers
 * @param {number} x - First number
 * @param {number} y - Second number
 * @returns {number} The sum of x and y
 */
function add(x, y) {
    return x + y;
}

/**
 * Subtracts two numbers
 * @param {number} x - First number
 * @param {number} y - Second number
 * @returns {number} The difference between x and y
 */
function subtract(x, y) {
    return x - y;
}

/**
 * Multiplies two numbers
 * @param {number} x - First number
 * @param {number} y - Second number
 * @returns {number} The product of x and y
 */
function multiply(x, y) {
    return x * y;
}

/**
 * Divides two numbers
 * @param {number} x - First number
 * @param {number} y - Second number
 * @returns {number} The quotient of x divided by y
 * @throws {Error} When attempting to divide by zero
 */
function divide(x, y) {
    if (y === 0) {
        throw new Error("Division by zero is not allowed!");
    }
    return x / y;
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
 * Main calculator function that handles the program flow
 */
async function calculator() {
    console.log("=== Simple Calculator ===");
    console.log("This calculator handles division by zero errors.");
    
    while (true) {
        console.log("\nOperations:");
        console.log("1. Add");
        console.log("2. Subtract");
        console.log("3. Multiply");
        console.log("4. Divide");
        console.log("5. Exit");
        
        const choice = await askQuestion("\nEnter your choice (1-5): ");
        
        if (choice === '5') {
            console.log("Goodbye!");
            readline.close();
            break;
        }
        
        if (!['1', '2', '3', '4'].includes(choice)) {
            console.log("Invalid choice. Please enter a number between 1 and 5.");
            continue;
        }
        
        try {
            const num1 = parseFloat(await askQuestion("Enter first number: "));
            const num2 = parseFloat(await askQuestion("Enter second number: "));
            
            if (isNaN(num1) || isNaN(num2)) {
                throw new Error("Please enter valid numbers.");
            }
            
            let result;
            switch (choice) {
                case '1':
                    result = add(num1, num2);
                    console.log(`${num1} + ${num2} = ${result}`);
                    break;
                    
                case '2':
                    result = subtract(num1, num2);
                    console.log(`${num1} - ${num2} = ${result}`);
                    break;
                    
                case '3':
                    result = multiply(num1, num2);
                    console.log(`${num1} × ${num2} = ${result}`);
                    break;
                    
                case '4':
                    try {
                        result = divide(num1, num2);
                        console.log(`${num1} ÷ ${num2} = ${result}`);
                    } catch (e) {
                        console.log(`Error: ${e.message}`);
                    }
                    break;
            }
        } catch (e) {
            console.log(`Error: ${e.message}`);
        }
    }
}

// Start the calculator
calculator().catch(console.error); 