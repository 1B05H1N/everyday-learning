/**
 * Guess the Number Game
 * 
 * A Node.js implementation of the classic number guessing game.
 * Features:
 * - Generates a random number between 1 and 100
 * - Gives the player 10 attempts to guess correctly
 * - Provides feedback after each guess (too high/too low)
 * - Handles invalid input gracefully
 * - Tracks number of attempts
 * 
 * @author Ibrahim
 * @version 1.0
 */

const readline = require('readline').createInterface({
    input: process.stdin,
    output: process.stdout
});

// Generate a random number between 1 and 100
const secretNumber = Math.floor(Math.random() * 100) + 1;
let attempts = 0;
const maxAttempts = 10;

console.log('Welcome to the Guess the Number game!');
console.log(`I'm thinking of a number between 1 and 100. You have ${maxAttempts} attempts to guess it.`);

/**
 * Main game loop that handles user input and game logic
 */
function askGuess() {
    if (attempts >= maxAttempts) {
        console.log(`Game over! You've run out of attempts. The number was ${secretNumber}.`);
        readline.close();
        return;
    }

    readline.question('Enter your guess: ', (guess) => {
        const number = parseInt(guess);

        if (isNaN(number)) {
            console.log('Please enter a valid number!');
            askGuess();
            return;
        }

        attempts++;

        if (number === secretNumber) {
            console.log(`Congratulations! You guessed the number in ${attempts} attempts!`);
            readline.close();
        } else if (number < secretNumber) {
            console.log('Too low! Try a higher number.');
            console.log(`Attempts remaining: ${maxAttempts - attempts}`);
            askGuess();
        } else {
            console.log('Too high! Try a lower number.');
            console.log(`Attempts remaining: ${maxAttempts - attempts}`);
            askGuess();
        }
    });
}

// Start the game
askGuess(); 