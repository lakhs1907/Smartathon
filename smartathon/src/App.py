# Backend Implementation using Flask and WebSockets with Post-Quantum Cryptography
from flask import Flask, request, jsonify, send_from_directory
from flask_socketio import SocketIO, emit, join_room
from flask_cors import CORS
import json
import os
import uuid
import time
from cryptography.hazmat.primitives.asymmetric import rsa
from cryptography.hazmat.primitives import serialization
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.asymmetric import padding
import base64

# Note: In a production environment, you would use a proper PQC library
# For this demo, we'll simulate PQC with RSA (for educational purposes only)
# In a real implementation, you would use libraries like liboqs or PQClean
# that implement Kyber, NTRU, or Dilithium algorithms

app = Flask(__name__, static_folder='../frontend/build')
CORS(app)
socketio = SocketIO(app, cors_allowed_origins="*")

# In-memory data storage (use a database in production)
users = {}
rooms = {}
user_keys = {}
room_messages = {}

# Simulating PQC key generation (in production, use actual PQC algorithms)
def generate_pqc_keypair():
    # Note: This is RSA, not actual PQC
    # In production, use Kyber, NTRU, or Dilithium
    private_key = rsa.generate_private_key(
        public_exponent=65537,
        key_size=2048
    )
    public_key = private_key.public_key()
    
    # Serialize keys for transmission
    public_pem = public_key.public_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PublicFormat.SubjectPublicKeyInfo
    )
    
    private_pem = private_key.private_bytes(
        encoding=serialization.Encoding.PEM,
        format=serialization.PrivateFormat.PKCS8,
        encryption_algorithm=serialization.NoEncryption()
    )
    
    return {
        "public_key": public_pem.decode('utf-8'),
        "private_key": private_pem.decode('utf-8')
    }

# Simulate PQC encryption (in production, use actual PQC algorithms)
def pqc_encrypt(message, public_key_pem):
    # Note: This is RSA, not actual PQC
    public_key = serialization.load_pem_public_key(public_key_pem.encode('utf-8'))
    encrypted = public_key.encrypt(
        message.encode('utf-8'),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return base64.b64encode(encrypted).decode('utf-8')

# Simulate PQC decryption (in production, use actual PQC algorithms)
def pqc_decrypt(encrypted_message, private_key_pem):
    # Note: This is RSA, not actual PQC
    private_key = serialization.load_pem_private_key(
        private_key_pem.encode('utf-8'),
        password=None
    )
    decrypted = private_key.decrypt(
        base64.b64decode(encrypted_message),
        padding.OAEP(
            mgf=padding.MGF1(algorithm=hashes.SHA256()),
            algorithm=hashes.SHA256(),
            label=None
        )
    )
    return decrypted.decode('utf-8')

@app.route('/')
def serve_frontend():
    return send_from_directory(app.static_folder, 'index.html')

@app.route('/<path:path>')
def static_files(path):
    return send_from_directory(app.static_folder, path)

@app.route('/api/register', methods=['POST'])
def register():
    data = request.json
    username = data.get('username')
    
    if not username:
        return jsonify({"error": "Username is required"}), 400
        
    if username in users:
        return jsonify({"error": "Username already exists"}), 409
    
    # Generate user ID and keys
    user_id = str(uuid.uuid4())
    key_pair = generate_pqc_keypair()
    
    # Store user data
    users[username] = {
        "id": user_id,
        "username": username,
        "created_at": time.time()
    }
    
    # Store user's keys
    user_keys[username] = key_pair
    
    return jsonify({
        "user": users[username],
        "public_key": key_pair["public_key"]
    }), 201

@app.route('/api/login', methods=['POST'])
def login():
    data = request.json
    username = data.get('username')
    
    if not username or username not in users:
        return jsonify({"error": "Invalid username"}), 401
    
    return jsonify({
        "user": users[username],
        "public_key": user_keys[username]["public_key"]
    }), 200

@app.route('/api/users', methods=['GET'])
def get_users():
    return jsonify({"users": list(users.values())}), 200

@app.route('/api/rooms', methods=['GET'])
def get_rooms():
    return jsonify({"rooms": list(rooms.values())}), 200

@app.route('/api/rooms', methods=['POST'])
def create_room():
    data = request.json
    room_name = data.get('name')
    created_by = data.get('created_by')
    
    if not room_name or not created_by:
        return jsonify({"error": "Room name and creator are required"}), 400
        
    if room_name in rooms:
        return jsonify({"error": "Room already exists"}), 409
    
    room_id = str(uuid.uuid4())
    rooms[room_name] = {
        "id": room_id,
        "name": room_name,
        "created_by": created_by,
        "created_at": time.time(),
        "users": [created_by]
    }
    
    room_messages[room_id] = []
    
    return jsonify({"room": rooms[room_name]}), 201

@app.route('/api/rooms/<room_id>/messages', methods=['GET'])
def get_messages(room_id):
    if room_id not in room_messages:
        return jsonify({"error": "Room not found"}), 404
        
    return jsonify({"messages": room_messages[room_id]}), 200

@socketio.on('connect')
def handle_connect():
    print('Client connected')

@socketio.on('disconnect')
def handle_disconnect():
    print('Client disconnected')

@socketio.on('join_room')
def handle_join_room(data):
    room_id = data.get('room_id')
    username = data.get('username')
    
    # Find room by ID
    room = None
    for r in rooms.values():
        if r['id'] == room_id:
            room = r
            break
    
    if not room:
        emit('error', {'message': 'Room not found'})
        return
        
    # Add user to room if not already in
    if username not in room['users']:
        room['users'].append(username)
    
    join_room(room_id)
    emit('room_joined', {'room': room}, room=room_id)
    
    # Send system message
    system_message = {
        'id': str(uuid.uuid4()),
        'room_id': room_id,
        'sender': 'system',
        'content': f'{username} joined the room',
        'timestamp': time.time(),
        'type': 'system'
    }
    
    room_messages[room_id].append(system_message)
    emit('message', system_message, room=room_id)

@socketio.on('send_message')
def handle_message(data):
    room_id = data.get('room_id')
    sender = data.get('sender')
    encrypted_content = data.get('content')
    recipient = data.get('recipient')
    
    # Verify that room exists
    room_exists = False
    for r in rooms.values():
        if r['id'] == room_id:
            room_exists = True
            break
    
    if not room_exists:
        emit('error', {'message': 'Room not found'})
        return
    
    # Create message
    message = {
        'id': str(uuid.uuid4()),
        'room_id': room_id,
        'sender': sender,
        'recipient': recipient,
        'content': encrypted_content,
        'timestamp': time.time(),
        'type': 'user'
    }
    
    # Store message
    room_messages[room_id].append(message)
    
    # Broadcast message to room
    emit('message', message, room=room_id)

@socketio.on('get_public_key')
def handle_get_public_key(data):
    username = data.get('username')
    
    if username not in user_keys:
        emit('error', {'message': 'User not found'})
        return
        
    emit('public_key', {
        'username': username,
        'public_key': user_keys[username]['public_key']
    })

if __name__ == '__main__':
    socketio.run(app, debug=True, host='0.0.0.0', port=5000)