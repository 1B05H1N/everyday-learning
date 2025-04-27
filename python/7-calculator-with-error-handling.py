# Simple Calculator with Error Handling
# This script demonstrates how to handle exceptions in Python

def add(x, y):
    """Add two numbers."""
    return x + y

def subtract(x, y):
    """Subtract y from x."""
    return x - y

def multiply(x, y):
    """Multiply two numbers."""
    return x * y

def divide(x, y):
    """
    Divide x by y.
    
    Raises:
        ZeroDivisionError: If y is zero
    """
    if y == 0:
        raise ZeroDivisionError("Division by zero is not allowed!")
    return x / y

def calculator():
    """Run the calculator application."""
    print("=== Simple Calculator ===")
    print("This calculator handles division by zero errors.")
    
    while True:
        print("\nOperations:")
        print("1. Add")
        print("2. Subtract")
        print("3. Multiply")
        print("4. Divide")
        print("5. Exit")
        
        choice = input("\nEnter your choice (1-5): ")
        
        if choice == '5':
            print("Goodbye!")
            break
            
        if choice not in ['1', '2', '3', '4']:
            print("Invalid choice. Please enter a number between 1 and 5.")
            continue
            
        try:
            num1 = float(input("Enter first number: "))
            num2 = float(input("Enter second number: "))
            
            if choice == '1':
                result = add(num1, num2)
                print(f"{num1} + {num2} = {result}")
                
            elif choice == '2':
                result = subtract(num1, num2)
                print(f"{num1} - {num2} = {result}")
                
            elif choice == '3':
                result = multiply(num1, num2)
                print(f"{num1} × {num2} = {result}")
                
            elif choice == '4':
                try:
                    result = divide(num1, num2)
                    print(f"{num1} ÷ {num2} = {result}")
                except ZeroDivisionError as e:
                    print(f"Error: {e}")
                    
        except ValueError:
            print("Error: Please enter valid numbers.")
        except Exception as e:
            print(f"An unexpected error occurred: {e}")

# Run the calculator
if __name__ == "__main__":
    calculator() 