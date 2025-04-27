/**
 * Hello User Script
 * 
 * A simple Node.js script that demonstrates basic user input and output.
 * This script creates an interactive command-line interface that:
 * 1. Prompts the user for their name
 * 2. Greets them with a personalized message
 * 
 * @author Ibrahim
 * @version 1.0
 */

const readline = require('readline').createInterface({
    input: process.stdin,
    output: process.stdout
});

// Ask for the user's name
readline.question('What is your name? ', name => {
    console.log(`Hello, ${name}! Nice to meet you!`);
    readline.close();
}); 