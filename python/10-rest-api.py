#!/usr/bin/env python3
"""
REST API Example

This script demonstrates REST API development skills using Flask:
- Creating RESTful endpoints
- Handling HTTP methods (GET, POST, PUT, DELETE)
- Request validation
- Response formatting
- Error handling
- Database integration (simulated)
- Authentication and authorization
- API documentation

@author Ibrahim
@version 1.0
"""

from flask import Flask, request, jsonify
from flask_httpauth import HTTPBasicAuth
from functools import wraps
import json
import uuid
import datetime
import os

app = Flask(__name__)
auth = HTTPBasicAuth()

# Simulated database
db = {
    'users': [
        {'id': '1', 'username': 'admin', 'password': 'admin123', 'role': 'admin'},
        {'id': '2', 'username': 'user', 'password': 'user123', 'role': 'user'}
    ],
    'tasks': [
        {'id': '1', 'title': 'Learn Flask', 'description': 'Build a REST API with Flask', 'completed': False, 'user_id': '1'},
        {'id': '2', 'title': 'Learn React', 'description': 'Build a frontend with React', 'completed': True, 'user_id': '1'},
        {'id': '3', 'title': 'Learn Docker', 'description': 'Containerize the application', 'completed': False, 'user_id': '2'}
    ]
}

# User authentication
@auth.verify_password
def verify_password(username, password):
    """Verify username and password"""
    user = next((user for user in db['users'] if user['username'] == username and user['password'] == password), None)
    if user:
        return user
    return False

# Role-based authorization
def requires_role(role):
    """Decorator to check if user has required role"""
    def decorator(f):
        @wraps(f)
        def decorated_function(*args, **kwargs):
            user = auth.current_user()
            if user and user['role'] == role:
                return f(*args, **kwargs)
            return jsonify({'error': 'Permission denied'}), 403
        return decorated_function
    return decorator

# API Documentation
@app.route('/api', methods=['GET'])
def api_documentation():
    """Return API documentation"""
    return jsonify({
        'name': 'Task Management API',
        'version': '1.0',
        'endpoints': {
            '/api/tasks': {
                'GET': 'Get all tasks',
                'POST': 'Create a new task'
            },
            '/api/tasks/<task_id>': {
                'GET': 'Get a specific task',
                'PUT': 'Update a task',
                'DELETE': 'Delete a task'
            },
            '/api/users': {
                'GET': 'Get all users (admin only)',
                'POST': 'Create a new user (admin only)'
            }
        }
    })

# Task endpoints
@app.route('/api/tasks', methods=['GET'])
@auth.login_required
def get_tasks():
    """Get all tasks for the current user"""
    user = auth.current_user()
    user_tasks = [task for task in db['tasks'] if task['user_id'] == user['id']]
    return jsonify(user_tasks)

@app.route('/api/tasks', methods=['POST'])
@auth.login_required
def create_task():
    """Create a new task"""
    if not request.json or 'title' not in request.json:
        return jsonify({'error': 'Title is required'}), 400
    
    user = auth.current_user()
    task = {
        'id': str(uuid.uuid4()),
        'title': request.json['title'],
        'description': request.json.get('description', ''),
        'completed': False,
        'user_id': user['id'],
        'created_at': datetime.datetime.now().isoformat()
    }
    
    db['tasks'].append(task)
    return jsonify(task), 201

@app.route('/api/tasks/<task_id>', methods=['GET'])
@auth.login_required
def get_task(task_id):
    """Get a specific task"""
    user = auth.current_user()
    task = next((task for task in db['tasks'] if task['id'] == task_id and task['user_id'] == user['id']), None)
    
    if task is None:
        return jsonify({'error': 'Task not found'}), 404
    
    return jsonify(task)

@app.route('/api/tasks/<task_id>', methods=['PUT'])
@auth.login_required
def update_task(task_id):
    """Update a task"""
    user = auth.current_user()
    task = next((task for task in db['tasks'] if task['id'] == task_id and task['user_id'] == user['id']), None)
    
    if task is None:
        return jsonify({'error': 'Task not found'}), 404
    
    if not request.json:
        return jsonify({'error': 'No data provided'}), 400
    
    task['title'] = request.json.get('title', task['title'])
    task['description'] = request.json.get('description', task['description'])
    task['completed'] = request.json.get('completed', task['completed'])
    
    return jsonify(task)

@app.route('/api/tasks/<task_id>', methods=['DELETE'])
@auth.login_required
def delete_task(task_id):
    """Delete a task"""
    user = auth.current_user()
    task = next((task for task in db['tasks'] if task['id'] == task_id and task['user_id'] == user['id']), None)
    
    if task is None:
        return jsonify({'error': 'Task not found'}), 404
    
    db['tasks'].remove(task)
    return jsonify({'result': 'Task deleted'})

# User endpoints (admin only)
@app.route('/api/users', methods=['GET'])
@auth.login_required
@requires_role('admin')
def get_users():
    """Get all users (admin only)"""
    # Remove passwords from response
    users = [{'id': user['id'], 'username': user['username'], 'role': user['role']} for user in db['users']]
    return jsonify(users)

@app.route('/api/users', methods=['POST'])
@auth.login_required
@requires_role('admin')
def create_user():
    """Create a new user (admin only)"""
    if not request.json or 'username' not in request.json or 'password' not in request.json:
        return jsonify({'error': 'Username and password are required'}), 400
    
    # Check if username already exists
    if any(user['username'] == request.json['username'] for user in db['users']):
        return jsonify({'error': 'Username already exists'}), 400
    
    user = {
        'id': str(uuid.uuid4()),
        'username': request.json['username'],
        'password': request.json['password'],
        'role': request.json.get('role', 'user')
    }
    
    db['users'].append(user)
    return jsonify({'id': user['id'], 'username': user['username'], 'role': user['role']}), 201

# Error handlers
@app.errorhandler(404)
def not_found(error):
    """Handle 404 errors"""
    return jsonify({'error': 'Not found'}), 404

@app.errorhandler(500)
def server_error(error):
    """Handle 500 errors"""
    return jsonify({'error': 'Internal server error'}), 500

def main():
    """Main function to run the API server"""
    port = int(os.environ.get('PORT', 5000))
    app.run(host='0.0.0.0', port=port, debug=True)

if __name__ == '__main__':
    main() 