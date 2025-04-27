# TODO List Application
# This script demonstrates the use of lists and dictionaries in Python

# Initialize an empty list to store todo items
todo_list = []

def add_todo(title, description, priority="medium"):
    """
    Add a new todo item to the list.
    
    Args:
        title (str): The title of the todo item
        description (str): A description of the todo item
        priority (str): The priority of the todo item (low, medium, high)
    """
    # Create a dictionary for the todo item
    todo_item = {
        "id": len(todo_list) + 1,
        "title": title,
        "description": description,
        "priority": priority,
        "completed": False
    }
    
    # Add the todo item to the list
    todo_list.append(todo_item)
    print(f"Added: {title}")

def list_todos():
    """Display all todo items in the list."""
    if not todo_list:
        print("No todos found. Your list is empty!")
        return
    
    print("\n=== YOUR TODO LIST ===")
    for item in todo_list:
        status = "✓" if item["completed"] else " "
        print(f"{status} [{item['id']}] {item['title']} - {item['description']} (Priority: {item['priority']})")

def mark_completed(todo_id):
    """
    Mark a todo item as completed.
    
    Args:
        todo_id (int): The ID of the todo item to mark as completed
    """
    for item in todo_list:
        if item["id"] == todo_id:
            item["completed"] = True
            print(f"Marked as completed: {item['title']}")
            return
    
    print(f"Todo with ID {todo_id} not found.")

def remove_todo(todo_id):
    """
    Remove a todo item from the list.
    
    Args:
        todo_id (int): The ID of the todo item to remove
    """
    for i, item in enumerate(todo_list):
        if item["id"] == todo_id:
            removed_item = todo_list.pop(i)
            print(f"Removed: {removed_item['title']}")
            return
    
    print(f"Todo with ID {todo_id} not found.")

def filter_by_priority(priority):
    """
    Filter todos by priority.
    
    Args:
        priority (str): The priority to filter by (low, medium, high)
    """
    filtered_todos = [item for item in todo_list if item["priority"] == priority]
    
    if not filtered_todos:
        print(f"No todos found with priority: {priority}")
        return
    
    print(f"\n=== TODOS WITH PRIORITY: {priority.upper()} ===")
    for item in filtered_todos:
        status = "✓" if item["completed"] else " "
        print(f"{status} [{item['id']}] {item['title']} - {item['description']}")

# Main program
print("=== TODO LIST APPLICATION ===")
print("This program helps you manage your todo list.")

while True:
    print("\nOptions:")
    print("1. Add a new todo")
    print("2. List all todos")
    print("3. Mark a todo as completed")
    print("4. Remove a todo")
    print("5. Filter todos by priority")
    print("6. Exit")
    
    choice = input("\nEnter your choice (1-6): ")
    
    if choice == "1":
        title = input("Enter todo title: ")
        description = input("Enter todo description: ")
        priority = input("Enter priority (low, medium, high) [default: medium]: ").lower()
        
        if priority not in ["low", "medium", "high"]:
            priority = "medium"
            
        add_todo(title, description, priority)
        
    elif choice == "2":
        list_todos()
        
    elif choice == "3":
        try:
            todo_id = int(input("Enter the ID of the todo to mark as completed: "))
            mark_completed(todo_id)
        except ValueError:
            print("Please enter a valid ID (number).")
            
    elif choice == "4":
        try:
            todo_id = int(input("Enter the ID of the todo to remove: "))
            remove_todo(todo_id)
        except ValueError:
            print("Please enter a valid ID (number).")
            
    elif choice == "5":
        priority = input("Enter priority to filter by (low, medium, high): ").lower()
        if priority in ["low", "medium", "high"]:
            filter_by_priority(priority)
        else:
            print("Invalid priority. Please enter low, medium, or high.")
            
    elif choice == "6":
        print("Goodbye!")
        break
        
    else:
        print("Invalid choice. Please enter a number between 1 and 6.") 