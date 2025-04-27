# Simple Counter Program
# This script demonstrates different types of loops in Python

print("=== Simple Counter Program ===")
print("This program demonstrates different types of loops.")

# Using a for loop to count from 1 to 5
print("\n1. For Loop Counter (1 to 5):")
for i in range(1, 6):
    print(f"Count: {i}")

# Using a while loop to count from 1 to 5
print("\n2. While Loop Counter (1 to 5):")
count = 1
while count <= 5:
    print(f"Count: {count}")
    count += 1

# Using a for loop with step to count by 2s
print("\n3. For Loop Counter (counting by 2s from 1 to 10):")
for i in range(1, 11, 2):
    print(f"Count: {i}")

# Using a while loop with user input to count up to a number
print("\n4. Interactive While Loop Counter:")
try:
    max_count = int(input("Enter a number to count up to: "))
    if max_count < 1:
        print("Please enter a positive number.")
    else:
        count = 1
        while count <= max_count:
            print(f"Count: {count}")
            count += 1
except ValueError:
    print("Please enter a valid number.")

print("\nCounter program completed!") 