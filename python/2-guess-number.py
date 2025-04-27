# Guess the Number Game
# This script generates a random number and lets the user guess it

import random

# Generate a random number between 1 and 100
secret_number = random.randint(1, 100)
attempts = 0
max_attempts = 10

print("Welcome to the Guess the Number game!")
print(f"I'm thinking of a number between 1 and 100. You have {max_attempts} attempts to guess it.")

# Game loop
while attempts < max_attempts:
    # Get the user's guess
    try:
        guess = int(input("Enter your guess: "))
        attempts += 1
        
        # Check if the guess is correct
        if guess == secret_number:
            print(f"Congratulations! You guessed the number in {attempts} attempts!")
            break
        elif guess < secret_number:
            print("Too low! Try a higher number.")
        else:
            print("Too high! Try a lower number.")
            
        # Show remaining attempts
        print(f"Attempts remaining: {max_attempts - attempts}")
        
    except ValueError:
        print("Please enter a valid number!")
        continue

# If the user runs out of attempts
if attempts == max_attempts and guess != secret_number:
    print(f"Game over! You've run out of attempts. The number was {secret_number}.") 