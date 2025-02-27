# app.py
from flask import Flask, render_template, request, redirect, url_for, session, jsonify
from datetime import datetime
import os
import json
from werkzeug.security import generate_password_hash, check_password_hash

app = Flask(__name__)
app.secret_key = os.urandom(24)

# Simple in-memory data storage
users = {}
messages = []
conversations = {}  # To track conversations between users

@app.route('/')
def index():
    if 'username' not in session:
        return redirect(url_for('login'))
    return render_template('index.html', username=session['username'])

@app.route('/login', methods=['GET', 'POST'])
def login():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in users and check_password_hash(users[username]['password'], password):
            session['username'] = username
            return redirect(url_for('index'))
        
        return render_template('login.html', error='Invalid username or password')
    
    return render_template('login.html')

@app.route('/register', methods=['GET', 'POST'])
def register():
    if request.method == 'POST':
        username = request.form['username']
        password = request.form['password']
        
        if username in users:
            return render_template('register.html', error='Username already exists')
        
        users[username] = {
            'password': generate_password_hash(password),
            'joined_at': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
        }
        
        # Initialize an empty conversation list for the new user
        conversations[username] = []
        
        return redirect(url_for('login'))
    
    return render_template('register.html')

@app.route('/logout')
def logout():
    session.pop('username', None)
    return redirect(url_for('login'))

@app.route('/get_contacts')
def get_contacts():
    if 'username' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    # Get all users except the current user
    contacts = [user for user in users.keys() if user != session['username']]
    
    # Add contact info including last message if it exists
    contact_info = []
    for contact in contacts:
        # Create a unique conversation ID
        conv_id = get_conversation_id(session['username'], contact)
        
        # Find the last message between these users
        last_message = None
        for msg in reversed(messages):
            if (msg['sender'] == session['username'] and msg['recipient'] == contact) or \
               (msg['sender'] == contact and msg['recipient'] == session['username']):
                last_message = {
                    'content': msg['content'],
                    'timestamp': msg['timestamp'],
                    'sender': msg['sender']
                }
                break
        
        contact_info.append({
            'username': contact,
            'conversation_id': conv_id,
            'last_message': last_message
        })
    
    return jsonify(contact_info)

@app.route('/send_message', methods=['POST'])
def send_message():
    if 'username' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    data = request.get_json()
    recipient = data.get('recipient')
    content = data.get('content')
    
    if not recipient or not content:
        return jsonify({'error': 'Recipient and content are required'}), 400
    
    # Check if recipient exists
    if recipient not in users:
        return jsonify({'error': 'Recipient not found'}), 404
    
    # Create a message
    message = {
        'sender': session['username'],
        'recipient': recipient,
        'content': content,
        'timestamp': datetime.now().strftime('%Y-%m-%d %H:%M:%S')
    }
    
    # Add to global messages list
    messages.append(message)
    
    # Make sure both users have this conversation in their list
    ensure_conversation_exists(session['username'], recipient)
    
    return jsonify(message)

@app.route('/get_messages/<recipient>')
def get_messages(recipient):
    if 'username' not in session:
        return jsonify({'error': 'Not logged in'}), 401
    
    # Check if recipient exists
    if recipient not in users:
        return jsonify({'error': 'Recipient not found'}), 404
    
    # Filter messages between the current user and the recipient
    conversation = []
    for message in messages:
        if (message['sender'] == session['username'] and message['recipient'] == recipient) or \
           (message['sender'] == recipient and message['recipient'] == session['username']):
            conversation.append(message)
    
    return jsonify(conversation)

def get_conversation_id(user1, user2):
    """Generate a unique, consistent ID for a conversation between two users"""
    sorted_users = sorted([user1, user2])
    return f"{sorted_users[0]}_{sorted_users[1]}"

def ensure_conversation_exists(user1, user2):
    """Make sure both users have this conversation in their list"""
    conv_id = get_conversation_id(user1, user2)
    
    if user1 in conversations and conv_id not in conversations[user1]:
        conversations[user1].append(conv_id)
    
    if user2 in conversations and conv_id not in conversations[user2]:
        conversations[user2].append(conv_id)

if __name__ == '__main__':
    app.run(debug=True)