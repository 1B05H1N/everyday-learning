/**
 * Simple Counter Program
 * 
 * A demonstration of different types of loops in JavaScript.
 * This script showcases:
 * 1. For loops
 * 2. While loops
 * 3. For loops with step increments
 * 4. Do...while loops
 * 
 * Each loop type demonstrates a different way to implement counting
 * and iteration in JavaScript.
 * 
 * @author Ibrahim
 * @version 1.0
 */

console.log('=== Simple Counter Program ===');
console.log('This program demonstrates different types of loops.');

// Using a for loop to count from 1 to 5
console.log('\n1. For Loop Counter (1 to 5):');
for (let i = 1; i <= 5; i++) {
    console.log(`Count: ${i}`);
}

// Using a while loop to count from 1 to 5
console.log('\n2. While Loop Counter (1 to 5):');
let count = 1;
while (count <= 5) {
    console.log(`Count: ${count}`);
    count++;
}

// Using a for loop with step to count by 2s
console.log('\n3. For Loop Counter (counting by 2s from 1 to 10):');
for (let i = 1; i <= 10; i += 2) {
    console.log(`Count: ${i}`);
}

// Using a do...while loop (JavaScript specific)
console.log('\n4. Do...While Loop Counter (1 to 5):');
count = 1;
do {
    console.log(`Count: ${count}`);
    count++;
} while (count <= 5);

console.log('\nCounter program completed!'); 