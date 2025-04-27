/**
 * Dog Class Example
 * 
 * A demonstration of Object-Oriented Programming (OOP) concepts in JavaScript:
 * - Class definition and instantiation
 * - Constructor methods
 * - Instance methods
 * - Object properties
 * - String template literals
 * - User input handling
 * 
 * This program creates a Dog class with basic properties and methods,
 * demonstrates its usage with predefined dogs, and allows users to
 * create their own dog instances.
 * 
 * @author Ibrahim
 * @version 1.0
 */

/**
 * Represents a Dog with basic properties and behaviors
 */
class Dog {
    /**
     * Creates a new Dog instance
     * @param {string} name - The dog's name
     * @param {string} breed - The dog's breed
     * @param {number} age - The dog's age in years
     */
    constructor(name, breed, age) {
        this.name = name;
        this.breed = breed;
        this.age = age;
    }
    
    /**
     * Makes the dog bark
     * @returns {string} The dog's bark message
     */
    bark() {
        return `${this.name} says: Woof! Woof!`;
    }
    
    /**
     * Gets information about the dog
     * @returns {string} A formatted string with the dog's information
     */
    getInfo() {
        return `${this.name} is a ${this.age}-year-old ${this.breed}.`;
    }
}

// Main program
console.log("=== Dog Class Example ===");
console.log("This program demonstrates a simple Dog class with a bark() method.");

// Create some dog objects
const dog1 = new Dog("Rex", "German Shepherd", 3);
const dog2 = new Dog("Bella", "Golden Retriever", 2);
const dog3 = new Dog("Max", "Beagle", 5);

// Demonstrate the bark() method
console.log("\nLet's make the dogs bark:");
console.log(dog1.bark());
console.log(dog2.bark());
console.log(dog3.bark());

// Demonstrate getting dog information
console.log("\nDog Information:");
console.log(dog1.getInfo());
console.log(dog2.getInfo());
console.log(dog3.getInfo());

// Interactive part using readline
const readline = require('readline').createInterface({
    input: process.stdin,
    output: process.stdout
});

console.log("\nLet's create your own dog!");
readline.question("Enter the dog's name: ", (name) => {
    readline.question("Enter the dog's breed: ", (breed) => {
        readline.question("Enter the dog's age: ", (ageStr) => {
            const age = parseInt(ageStr);
            
            if (isNaN(age)) {
                console.log("Please enter a valid age number.");
                readline.close();
                return;
            }
            
            const myDog = new Dog(name, breed, age);
            console.log(`\nYou created: ${myDog.getInfo()}`);
            console.log(myDog.bark());
            
            readline.close();
        });
    });
}); 