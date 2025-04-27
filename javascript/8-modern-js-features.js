/**
 * Modern JavaScript Features
 * 
 * This script demonstrates modern JavaScript features and best practices:
 * - ES6+ syntax and features
 * - Promises and async/await
 * - Arrow functions
 * - Template literals
 * - Destructuring
 * - Spread and rest operators
 * - Classes and inheritance
 * - Modules
 * - Optional chaining and nullish coalescing
 * - Map, Set, and other modern data structures
 * 
 * @author Ibrahim
 * @version 1.0
 */

// ===== ES6+ Features =====

// 1. Arrow Functions
const greet = (name) => `Hello, ${name}!`;
console.log(greet('World')); // Hello, World!

// 2. Template Literals
const firstName = 'John';
const lastName = 'Doe';
const fullName = `${firstName} ${lastName}`;
console.log(fullName); // John Doe

// 3. Destructuring
const person = { name: 'Alice', age: 30, city: 'New York' };
const { name, age } = person;
console.log(name, age); // Alice 30

// Array destructuring
const [first, second, ...rest] = [1, 2, 3, 4, 5];
console.log(first, second, rest); // 1 2 [3, 4, 5]

// 4. Spread Operator
const arr1 = [1, 2, 3];
const arr2 = [4, 5, 6];
const combined = [...arr1, ...arr2];
console.log(combined); // [1, 2, 3, 4, 5, 6]

// Object spread
const obj1 = { a: 1, b: 2 };
const obj2 = { c: 3, d: 4 };
const merged = { ...obj1, ...obj2 };
console.log(merged); // { a: 1, b: 2, c: 3, d: 4 }

// 5. Rest Parameters
function sum(...numbers) {
    return numbers.reduce((total, num) => total + num, 0);
}
console.log(sum(1, 2, 3, 4, 5)); // 15

// 6. Default Parameters
function greetWithDefault(name = 'Guest') {
    return `Hello, ${name}!`;
}
console.log(greetWithDefault()); // Hello, Guest!
console.log(greetWithDefault('Bob')); // Hello, Bob!

// 7. Classes and Inheritance
class Animal {
    constructor(name) {
        this.name = name;
    }
    
    speak() {
        return `${this.name} makes a sound.`;
    }
}

class Dog extends Animal {
    constructor(name, breed) {
        super(name);
        this.breed = breed;
    }
    
    speak() {
        return `${this.name} barks.`;
    }
    
    fetch() {
        return `${this.name} fetches the ball.`;
    }
}

const dog = new Dog('Rex', 'German Shepherd');
console.log(dog.speak()); // Rex barks.
console.log(dog.fetch()); // Rex fetches the ball.

// 8. Promises
function fetchData() {
    return new Promise((resolve, reject) => {
        setTimeout(() => {
            const success = Math.random() > 0.5;
            if (success) {
                resolve({ id: 1, name: 'Data' });
            } else {
                reject(new Error('Failed to fetch data'));
            }
        }, 1000);
    });
}

// 9. Async/Await
async function getData() {
    try {
        console.log('Fetching data...');
        const data = await fetchData();
        console.log('Data received:', data);
        return data;
    } catch (error) {
        console.error('Error:', error.message);
        throw error;
    }
}

// 10. Optional Chaining
const user = {
    name: 'John',
    address: {
        street: '123 Main St',
        city: 'Boston'
    }
};

console.log(user?.address?.city); // Boston
console.log(user?.contact?.email); // undefined (no error)

// 11. Nullish Coalescing
const value = null;
const defaultValue = 'Default';
console.log(value ?? defaultValue); // Default

// 12. Map and Set
const map = new Map();
map.set('name', 'John');
map.set('age', 30);
console.log(map.get('name')); // John
console.log(map.has('age')); // true

const set = new Set([1, 2, 3, 3, 4, 4, 5]); // Duplicates are removed
console.log(set); // Set { 1, 2, 3, 4, 5 }
console.log(set.has(3)); // true

// 13. Array Methods
const numbers = [1, 2, 3, 4, 5, 6, 7, 8, 9, 10];

// Filter
const evenNumbers = numbers.filter(num => num % 2 === 0);
console.log(evenNumbers); // [2, 4, 6, 8, 10]

// Map
const doubled = numbers.map(num => num * 2);
console.log(doubled); // [2, 4, 6, 8, 10, 12, 14, 16, 18, 20]

// Reduce
const sum = numbers.reduce((total, num) => total + num, 0);
console.log(sum); // 55

// Find
const found = numbers.find(num => num > 5);
console.log(found); // 6

// Some and Every
const hasEven = numbers.some(num => num % 2 === 0);
console.log(hasEven); // true

const allPositive = numbers.every(num => num > 0);
console.log(allPositive); // true

// 14. String Methods
const str = '  Hello, World!  ';
console.log(str.trim()); // 'Hello, World!'
console.log(str.startsWith('Hello')); // false (due to leading spaces)
console.log(str.includes('World')); // true

// 15. Object Methods
const obj = { a: 1, b: 2, c: 3 };
console.log(Object.keys(obj)); // ['a', 'b', 'c']
console.log(Object.values(obj)); // [1, 2, 3]
console.log(Object.entries(obj)); // [['a', 1], ['b', 2], ['c', 3]]

// 16. Symbol
const sym = Symbol('description');
const objWithSymbol = {
    [sym]: 'value'
};
console.log(objWithSymbol[sym]); // 'value'

// 17. Iterators and Generators
function* numberGenerator() {
    yield 1;
    yield 2;
    yield 3;
}

const generator = numberGenerator();
console.log(generator.next().value); // 1
console.log(generator.next().value); // 2
console.log(generator.next().value); // 3
console.log(generator.next().done); // true

// 18. Modules (this would typically be in separate files)
// export.js
// export const add = (a, b) => a + b;
// export default class Calculator { ... }

// import.js
// import { add } from './export.js';
// import Calculator from './export.js';

// 19. Error Handling
try {
    throw new Error('Something went wrong');
} catch (error) {
    console.error('Caught error:', error.message);
} finally {
    console.log('This always runs');
}

// 20. Performance API
console.log('Performance timing:', performance.now());

// Execute the async function
getData()
    .then(data => console.log('Data in promise chain:', data))
    .catch(error => console.error('Error in promise chain:', error.message));

// Export for module usage
if (typeof module !== 'undefined' && module.exports) {
    module.exports = {
        greet,
        sum,
        Animal,
        Dog,
        fetchData,
        getData
    };
} 