/**
 * Factorial Calculator
 * 
 * A Node.js program that demonstrates two different approaches to calculating factorials:
 * 1. Iterative approach using a for loop
 * 2. Recursive approach using function calls
 * 
 * Features:
 * - Handles negative numbers and invalid input
 * - Shows the step-by-step calculation
 * - Demonstrates both iterative and recursive solutions
 * - Provides detailed output formatting
 * 
 * @author Ibrahim
 * @version 1.0
 */

const readline = require('readline').createInterface({
    input: process.stdin,
    output: process.stdout
});

/**
 * Calculates factorial using an iterative approach
 * @param {number} n - The number to calculate factorial for
 * @returns {number|string} The factorial result or error message
 */
function factorialIterative(n) {
    if (n < 0) return "Factorial is not defined for negative numbers";
    if (n === 0 || n === 1) return 1;
    
    let result = 1;
    for (let i = 1; i <= n; i++) {
        result *= i;
    }
    return result;
}

/**
 * Calculates factorial using a recursive approach
 * @param {number} n - The number to calculate factorial for
 * @returns {number|string} The factorial result or error message
 */
function factorialRecursive(n) {
    if (n < 0) return "Factorial is not defined for negative numbers";
    if (n === 0 || n === 1) return 1;
    return n * factorialRecursive(n - 1);
}

console.log('=== Factorial Calculator ===');
console.log('This program calculates the factorial of a number using two different methods.');

readline.question('Enter a non-negative integer: ', (input) => {
    const num = parseInt(input);
    
    if (isNaN(num)) {
        console.log('Please enter a valid number.');
        readline.close();
        return;
    }
    
    if (num < 0) {
        console.log('Factorial is not defined for negative numbers.');
        readline.close();
        return;
    }
    
    // Using iterative function
    const resultIterative = factorialIterative(num);
    console.log('\nUsing iterative method:');
    console.log(`The factorial of ${num} is: ${resultIterative}`);
    
    // Using recursive function
    const resultRecursive = factorialRecursive(num);
    console.log('\nUsing recursive method:');
    console.log(`The factorial of ${num} is: ${resultRecursive}`);
    
    // Show the calculation
    if (num > 0) {
        const calculation = Array.from({length: num}, (_, i) => i + 1).join(' × ');
        console.log(`\nCalculation: ${calculation} = ${resultIterative}`);
    }
    
    readline.close();
}); 