# Dog Class Example
# This script demonstrates basic object-oriented programming with a Dog class

class Dog:
    """
    A simple Dog class to demonstrate basic OOP concepts.
    """
    
    def __init__(self, name, breed, age):
        """
        Initialize a new Dog object.
        
        Args:
            name (str): The dog's name
            breed (str): The dog's breed
            age (int): The dog's age in years
        """
        self.name = name
        self.breed = breed
        self.age = age
    
    def bark(self):
        """
        Make the dog bark.
        
        Returns:
            str: A barking sound
        """
        return f"{self.name} says: Woof! Woof!"
    
    def get_info(self):
        """
        Get information about the dog.
        
        Returns:
            str: A string with the dog's information
        """
        return f"{self.name} is a {self.age}-year-old {self.breed}."

# Main program
print("=== Dog Class Example ===")
print("This program demonstrates a simple Dog class with a bark() method.")

# Create some dog objects
dog1 = Dog("Rex", "German Shepherd", 3)
dog2 = Dog("Bella", "Golden Retriever", 2)
dog3 = Dog("Max", "Beagle", 5)

# Demonstrate the bark() method
print("\nLet's make the dogs bark:")
print(dog1.bark())
print(dog2.bark())
print(dog3.bark())

# Demonstrate getting dog information
print("\nDog Information:")
print(dog1.get_info())
print(dog2.get_info())
print(dog3.get_info())

# Interactive part
print("\nLet's create your own dog!")
name = input("Enter the dog's name: ")
breed = input("Enter the dog's breed: ")
age = int(input("Enter the dog's age: "))

my_dog = Dog(name, breed, age)
print(f"\nYou created: {my_dog.get_info()}")
print(my_dog.bark()) 