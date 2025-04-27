/**
 * DOM Manipulation and Event Handling
 * 
 * This script demonstrates various DOM manipulation techniques and event handling:
 * - Element selection and traversal
 * - Creating and modifying elements
 * - Event listeners and delegation
 * - Form handling
 * - Dynamic styling
 * - Animation
 * - Local storage
 * - Custom events
 * 
 * @author Ibrahim
 * @version 1.0
 */

// Wait for DOM to be fully loaded
document.addEventListener('DOMContentLoaded', () => {
    // Create main container
    const container = document.createElement('div');
    container.className = 'container';
    document.body.appendChild(container);

    // Create header
    const header = document.createElement('header');
    header.innerHTML = '<h1>DOM Manipulation Demo</h1>';
    container.appendChild(header);

    // Create main content area
    const main = document.createElement('main');
    container.appendChild(main);

    // ===== Element Creation and Manipulation =====
    
    // Create a form
    const form = document.createElement('form');
    form.id = 'todo-form';
    form.innerHTML = `
        <div class="form-group">
            <input type="text" id="todo-input" placeholder="Enter a task" required>
            <button type="submit">Add Task</button>
        </div>
    `;
    main.appendChild(form);

    // Create task list
    const taskList = document.createElement('ul');
    taskList.id = 'task-list';
    main.appendChild(taskList);

    // Create filter section
    const filterSection = document.createElement('div');
    filterSection.className = 'filter-section';
    filterSection.innerHTML = `
        <button class="filter-btn active" data-filter="all">All</button>
        <button class="filter-btn" data-filter="active">Active</button>
        <button class="filter-btn" data-filter="completed">Completed</button>
    `;
    main.appendChild(filterSection);

    // ===== Event Handling =====

    // Form submission
    form.addEventListener('submit', (e) => {
        e.preventDefault();
        const input = document.getElementById('todo-input');
        const taskText = input.value.trim();
        
        if (taskText) {
            addTask(taskText);
            input.value = '';
            
            // Dispatch custom event
            const event = new CustomEvent('taskAdded', {
                detail: { taskText }
            });
            document.dispatchEvent(event);
        }
    });

    // Event delegation for task list
    taskList.addEventListener('click', (e) => {
        const taskItem = e.target.closest('.task-item');
        if (!taskItem) return;

        if (e.target.classList.contains('delete-btn')) {
            deleteTask(taskItem);
        } else if (e.target.classList.contains('complete-btn')) {
            toggleTaskComplete(taskItem);
        }
    });

    // Filter buttons
    filterSection.addEventListener('click', (e) => {
        if (e.target.classList.contains('filter-btn')) {
            // Update active button
            document.querySelectorAll('.filter-btn').forEach(btn => {
                btn.classList.remove('active');
            });
            e.target.classList.add('active');

            // Filter tasks
            const filter = e.target.dataset.filter;
            filterTasks(filter);
        }
    });

    // ===== Task Management Functions =====

    function addTask(text) {
        const taskItem = document.createElement('li');
        taskItem.className = 'task-item';
        taskItem.innerHTML = `
            <span class="task-text">${text}</span>
            <div class="task-actions">
                <button class="complete-btn">✓</button>
                <button class="delete-btn">×</button>
            </div>
        `;

        // Add animation class
        taskItem.classList.add('slide-in');
        
        taskList.appendChild(taskItem);
        saveTasks();
    }

    function deleteTask(taskItem) {
        // Add fade-out animation
        taskItem.classList.add('fade-out');
        
        taskItem.addEventListener('animationend', () => {
            taskItem.remove();
            saveTasks();
        });
    }

    function toggleTaskComplete(taskItem) {
        taskItem.classList.toggle('completed');
        saveTasks();
    }

    function filterTasks(filter) {
        const tasks = document.querySelectorAll('.task-item');
        
        tasks.forEach(task => {
            switch (filter) {
                case 'active':
                    task.style.display = task.classList.contains('completed') ? 'none' : 'flex';
                    break;
                case 'completed':
                    task.style.display = task.classList.contains('completed') ? 'flex' : 'none';
                    break;
                default:
                    task.style.display = 'flex';
            }
        });
    }

    // ===== Local Storage =====

    function saveTasks() {
        const tasks = Array.from(document.querySelectorAll('.task-item')).map(task => ({
            text: task.querySelector('.task-text').textContent,
            completed: task.classList.contains('completed')
        }));
        localStorage.setItem('tasks', JSON.stringify(tasks));
    }

    function loadTasks() {
        const tasks = JSON.parse(localStorage.getItem('tasks') || '[]');
        tasks.forEach(task => {
            const taskItem = document.createElement('li');
            taskItem.className = 'task-item';
            if (task.completed) taskItem.classList.add('completed');
            
            taskItem.innerHTML = `
                <span class="task-text">${task.text}</span>
                <div class="task-actions">
                    <button class="complete-btn">✓</button>
                    <button class="delete-btn">×</button>
                </div>
            `;
            
            taskList.appendChild(taskItem);
        });
    }

    // ===== Dynamic Styling =====

    // Add styles
    const style = document.createElement('style');
    style.textContent = `
        .container {
            max-width: 600px;
            margin: 0 auto;
            padding: 20px;
            font-family: Arial, sans-serif;
        }

        header {
            text-align: center;
            margin-bottom: 20px;
        }

        .form-group {
            display: flex;
            gap: 10px;
            margin-bottom: 20px;
        }

        input[type="text"] {
            flex: 1;
            padding: 8px;
            border: 1px solid #ddd;
            border-radius: 4px;
        }

        button {
            padding: 8px 16px;
            background-color: #007bff;
            color: white;
            border: none;
            border-radius: 4px;
            cursor: pointer;
            transition: background-color 0.3s;
        }

        button:hover {
            background-color: #0056b3;
        }

        .task-item {
            display: flex;
            justify-content: space-between;
            align-items: center;
            padding: 10px;
            margin-bottom: 10px;
            background-color: #f8f9fa;
            border-radius: 4px;
            animation: slideIn 0.3s ease-out;
        }

        .task-item.completed .task-text {
            text-decoration: line-through;
            color: #6c757d;
        }

        .task-actions {
            display: flex;
            gap: 5px;
        }

        .complete-btn {
            background-color: #28a745;
        }

        .delete-btn {
            background-color: #dc3545;
        }

        .filter-section {
            display: flex;
            gap: 10px;
            margin-top: 20px;
        }

        .filter-btn {
            background-color: #6c757d;
        }

        .filter-btn.active {
            background-color: #007bff;
        }

        @keyframes slideIn {
            from {
                opacity: 0;
                transform: translateX(-20px);
            }
            to {
                opacity: 1;
                transform: translateX(0);
            }
        }

        @keyframes fadeOut {
            from {
                opacity: 1;
                transform: translateX(0);
            }
            to {
                opacity: 0;
                transform: translateX(20px);
            }
        }

        .slide-in {
            animation: slideIn 0.3s ease-out;
        }

        .fade-out {
            animation: fadeOut 0.3s ease-out;
        }
    `;
    document.head.appendChild(style);

    // Load saved tasks
    loadTasks();

    // Listen for custom events
    document.addEventListener('taskAdded', (e) => {
        console.log('Task added:', e.detail.taskText);
    });
}); 