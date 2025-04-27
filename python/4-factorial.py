# Factorial Calculator
# This script demonstrates functions by calculating factorials

def factorial_iterative(n):
    """
    Calculate the factorial of a number using an iterative approach.
    
    Args:
        n (int): The number to calculate the factorial for
        
    Returns:
        int: The factorial of n
    """
    if n < 0:
        return "Factorial is not defined for negative numbers"
    elif n == 0 or n == 1:
        return 1
    else:
        result = 1
        for i in range(1, n + 1):
            result *= i
        return result

def factorial_recursive(n):
    """
    Calculate the factorial of a number using a recursive approach.
    
    Args:
        n (int): The number to calculate the factorial for
        
    Returns:
        int: The factorial of n
    """
    if n < 0:
        return "Factorial is not defined for negative numbers"
    elif n == 0 or n == 1:
        return 1
    else:
        return n * factorial_recursive(n - 1)

# Main program
print("=== Factorial Calculator ===")
print("This program calculates the factorial of a number using two different methods.")

try:
    # Get input from the user
    num = int(input("Enter a non-negative integer: "))
    
    # Calculate and display results
    if num < 0:
        print("Factorial is not defined for negative numbers.")
    else:
        # Using iterative function
        result_iterative = factorial_iterative(num)
        print(f"\nUsing iterative method:")
        print(f"The factorial of {num} is: {result_iterative}")
        
        # Using recursive function
        result_recursive = factorial_recursive(num)
        print(f"\nUsing recursive method:")
        print(f"The factorial of {num} is: {result_recursive}")
        
        # Show the calculation
        if num > 0:
            calculation = " × ".join(str(i) for i in range(1, num + 1))
            print(f"\nCalculation: {calculation} = {result_iterative}")
            
except ValueError:
    print("Please enter a valid integer.") 