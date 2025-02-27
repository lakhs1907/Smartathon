# server.py
import socket
import threading
import json
import base64
import pickle
import time
import uuid
import numpy as np
import qutip as qt
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import hashlib

# ===============================
# Part 1: Quantum Key Distribution using QuTiP (BB84 Protocol Simulation)
# ===============================

class BB84Simulation:
    def __init__(self, num_qubits=100, eavesdropper=False, error_rate=0.0, seed=None):
        self.num_qubits = num_qubits
        self.eavesdropper = eavesdropper
        self.error_rate = error_rate
        
        # Set random seed for reproducibility in demo
        if seed is not None:
            np.random.seed(seed)
        
        # Basis states
        self.basis_0 = qt.basis(2, 0)  # |0⟩
        self.basis_1 = qt.basis(2, 1)  # |1⟩
        
        # Measurement operators
        self.Z_basis = [self.basis_0 * self.basis_0.dag(), self.basis_1 * self.basis_1.dag()]
        self.X_basis = [(self.basis_0 + self.basis_1).unit() * (self.basis_0 + self.basis_1).unit().dag(),
                        (self.basis_0 - self.basis_1).unit() * (self.basis_0 - self.basis_1).unit().dag()]
        
    def generate_random_bits(self, n):
        """Generate n random bits."""
        return np.random.randint(0, 2, n)
    
    def generate_random_bases(self, n):
        """Generate n random bases (0: Z-basis, 1: X-basis)."""
        return np.random.randint(0, 2, n)
    
    def prepare_qubit(self, bit, basis):
        """Prepare a qubit based on the bit value and basis."""
        if basis == 0:  # Z-basis
            return self.basis_0 if bit == 0 else self.basis_1
        else:  # X-basis
            return (self.basis_0 + (-1)**bit * self.basis_1).unit()
    
    def measure_qubit(self, qubit, basis):
        """Measure a qubit in the given basis."""
        if basis == 0:  # Z-basis
            projectors = self.Z_basis
        else:  # X-basis
            projectors = self.X_basis
        
        probs = [qt.expect(proj, qubit) for proj in projectors]
        outcome = np.random.choice([0, 1], p=probs)
        return outcome
    
    def simulate_channel(self, qubit):
        """Simulate quantum channel with possible noise."""
        if np.random.random() < self.error_rate:
            # Apply a random Pauli error
            error_type = np.random.randint(0, 3)
            if error_type == 0:
                return qt.sigmax() * qubit  # X error (bit flip)
            elif error_type == 1:
                return qt.sigmay() * qubit  # Y error
            else:
                return qt.sigmaz() * qubit  # Z error (phase flip)
        return qubit
    
    def simulate_eavesdropper(self, qubit):
        """Simulate an eavesdropper (Eve) intercepting the qubit."""
        if not self.eavesdropper:
            return qubit
        
        # Eve measures in a random basis
        eve_basis = np.random.randint(0, 2)
        self.measure_qubit(qubit, eve_basis)
        
        # Eve prepares a new qubit based on her measurement
        return self.prepare_qubit(self.measure_qubit(qubit, eve_basis), eve_basis)
    
    def run_protocol(self):
        """Run the BB84 QKD protocol simulation."""
        # Alice generates random bits and bases
        alice_bits = self.generate_random_bits(self.num_qubits)
        alice_bases = self.generate_random_bases(self.num_qubits)
        
        # Bob generates random measurement bases
        bob_bases = self.generate_random_bases(self.num_qubits)
        
        # Transmitted and received qubits
        bob_results = np.zeros(self.num_qubits, dtype=int)
        
        # Simulate quantum transmission
        for i in range(self.num_qubits):
            # Alice prepares qubit
            qubit = self.prepare_qubit(alice_bits[i], alice_bases[i])
            
            # Qubit passes through channel (possibly intercepted by Eve)
            qubit = self.simulate_eavesdropper(qubit)
            qubit = self.simulate_channel(qubit)
            
            # Bob measures qubit
            bob_results[i] = self.measure_qubit(qubit, bob_bases[i])
        
        # Basis reconciliation (public discussion)
        matching_bases = alice_bases == bob_bases
        
        # Key sifting - keep only bits where bases match
        sifted_alice_bits = alice_bits[matching_bases]
        sifted_bob_bits = bob_results[matching_bases]
        
        # Error estimation
        if len(sifted_alice_bits) > 0:
            error_rate = np.sum(sifted_alice_bits != sifted_bob_bits) / len(sifted_alice_bits)
        else:
            error_rate = 0
        
        # Return the raw bits and statistics
        return {
            'raw_key_bits': sifted_alice_bits,
            'key_length': len(sifted_alice_bits),
            'error_rate': error_rate,
            'matching_bases_count': np.sum(matching_bases),
            'total_qubits': self.num_qubits
        }

# ===============================
# Part 2: Post-Quantum Cryptographic Layer
# ===============================

class PostQuantumSecureChannel:
    def __init__(self, seed=None):
        # For demo purposes, use deterministic seed if provided
        if seed is not None:
            np.random.seed(seed)
        
        # Generate X25519 key pair (as a classical component)
        self.private_key = x25519.X25519PrivateKey.generate()
        self.public_key = self.private_key.public_key()
    
    def get_public_key_bytes(self):
        """Export public key as bytes."""
        return self.public_key.public_bytes_raw()
    
    def derive_shared_key(self, peer_public_key_bytes):
        """Perform key exchange to derive a shared secret."""
        peer_public_key = x25519.X25519PublicKey.from_public_bytes(peer_public_key_bytes)
        shared_secret = self.private_key.exchange(peer_public_key)
        
        # Derive a key using HKDF
        derived_key = HKDF(
            algorithm=hashes.SHA256(),
            length=32,
            salt=None,
            info=b'handshake data'
        ).derive(shared_secret)
        
        return derived_key
    
    def encrypt(self, message, key):
        """Encrypt a message using AES-GCM with the provided key."""
        iv = os.urandom(12)  # GCM nonce
        encryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv)
        ).encryptor()
        
        ciphertext = encryptor.update(message) + encryptor.finalize()
        
        return {
            'iv': base64.b64encode(iv).decode('utf-8'),
            'ciphertext': base64.b64encode(ciphertext).decode('utf-8'),
            'tag': base64.b64encode(encryptor.tag).decode('utf-8')
        }
    
    def decrypt(self, encrypted_data, key):
        """Decrypt a message using AES-GCM with the provided key."""
        iv = base64.b64decode(encrypted_data['iv'])
        ciphertext = base64.b64decode(encrypted_data['ciphertext'])
        tag = base64.b64decode(encrypted_data['tag'])
        
        decryptor = Cipher(
            algorithms.AES(key),
            modes.GCM(iv, tag)
        ).decryptor()
        
        return decryptor.update(ciphertext) + decryptor.finalize()

# ===============================
# Part 3: Key Processing Utilities
# ===============================

class KeyProcessor:
    @staticmethod
    def process_quantum_key(raw_bits, target_length=32):
        """Process raw quantum bits into a key of desired length (default 256 bits/32 bytes for AES-256)."""
        # Convert bits to a string for hashing
        bit_str = ''.join(map(str, raw_bits))
        
        # Use SHA-256 to generate a fixed-length key from the quantum bits
        # This ensures we always get a 256-bit (32-byte) key regardless of input length
        hash_obj = hashlib.sha256(bit_str.encode())
        return hash_obj.digest()
    
    @staticmethod
    def combine_keys(quantum_key, classical_key):
        """Combine quantum and classical keys securely."""
        if len(quantum_key) != len(classical_key):
            raise ValueError("Keys must be of equal length for combination")
        
        # XOR the keys together
        combined = bytes(q ^ c for q, c in zip(quantum_key, classical_key))
        
        # Hash the result to ensure uniform distribution
        hash_obj = hashlib.sha256(combined)
        return hash_obj.digest()

# ===============================
# Part 4: Secure Communication System
# ===============================

class SecureMessagingSystem:
    def __init__(self, use_qkd=True, qkd_qubits=100, simulate_eavesdropper=False, 
                 channel_noise=0.01, seed=None, simulation_mode=True):
        self.use_qkd = use_qkd
        self.simulation_mode = simulation_mode
        
        # In simulation mode, use the same seed for all random generators
        # to ensure matching keys for demo purposes
        self.seed = seed if simulation_mode else None
        
        self.qkd_simulation = BB84Simulation(
            num_qubits=qkd_qubits,
            eavesdropper=simulate_eavesdropper,
            error_rate=channel_noise,
            seed=self.seed
        )
        self.pq_channel = PostQuantumSecureChannel(seed=self.seed)
        self.key_processor = KeyProcessor()
        self.shared_keys = {}  # Dictionary to store keys for different peers
        
    def establish_connection(self, peer_id, peer_public_key):
        """Establish a secure connection with a specific peer."""
        keys = {}
        quantum_key = None
        classical_key = None
        
        # Step 1: Run QKD protocol if enabled
        if self.use_qkd:
            qkd_result = self.qkd_simulation.run_protocol()
            # Process raw quantum bits into a proper 256-bit key
            quantum_key = self.key_processor.process_quantum_key(qkd_result['raw_key_bits'], 32)
            keys['qkd'] = {
                'raw_key_length': qkd_result['key_length'],
                'processed_key_length': len(quantum_key) * 8,  # in bits
                'error_rate': qkd_result['error_rate'],
                'matching_bases': qkd_result['matching_bases_count'],
                'total_qubits': qkd_result['total_qubits']
            }
        
        # Step 2: Run classical post-quantum key exchange
        if peer_public_key:
            classical_key = self.pq_channel.derive_shared_key(peer_public_key)
            keys['classical'] = {
                'key_length': len(classical_key) * 8  # in bits
            }
        
        # Step 3: Combine keys
        if quantum_key and classical_key:
            # Ensure both keys are the same length before combining
            shared_key = self.key_processor.combine_keys(quantum_key, classical_key)
            keys['method'] = 'hybrid'
        elif quantum_key:
            shared_key = quantum_key
            keys['method'] = 'quantum'
        elif classical_key:
            shared_key = classical_key
            keys['method'] = 'classical'
        else:
            raise ValueError("No key exchange method succeeded")
        
        # Store the shared key for this peer
        self.shared_keys[peer_id] = shared_key
        
        keys['final_key_length'] = len(shared_key) * 8  # in bits
        return keys
    
    def get_public_key(self):
        """Get the public key for the classical exchange."""
        return self.pq_channel.get_public_key_bytes()
    
    def send_message(self, peer_id, message):
        """Encrypt a message for a specific peer."""
        if peer_id not in self.shared_keys:
            raise ValueError(f"No secure connection established with peer {peer_id}")
        
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        return self.pq_channel.encrypt(message, self.shared_keys[peer_id])
    
    def receive_message(self, peer_id, encrypted_data):
        """Decrypt a message from a specific peer."""
        if peer_id not in self.shared_keys:
            raise ValueError(f"No secure connection established with peer {peer_id}")
        
        decrypted = self.pq_channel.decrypt(encrypted_data, self.shared_keys[peer_id])
        
        try:
            # Try to decode as UTF-8 if it's text
            return decrypted.decode('utf-8')
        except UnicodeDecodeError:
            # Return raw bytes if it's binary data
            return decrypted

# ===============================
# Part 5: Server Implementation
# ===============================

class User:
    def __init__(self, username, password_hash):
        self.id = str(uuid.uuid4())
        self.username = username
        self.password_hash = password_hash
        self.public_key = None
        self.online = False
        self.last_seen = time.time()

class QuantumChatServer:
    def __init__(self, host='0.0.0.0', port=8000):
        self.host = host
        self.port = port
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
        self.users = {}  # username -> User object
        self.user_connections = {}  # user_id -> connection
        self.connection_users = {}  # connection -> user_id
        self.pending_messages = {}  # user_id -> [messages]
        self.secure_system = SecureMessagingSystem(use_qkd=True, qkd_qubits=100)
        self.lock = threading.Lock()
        
    def start(self):
        self.socket.bind((self.host, self.port))
        self.socket.listen(100)  # Allow up to 100 pending connections
        print(f"Server started on {self.host}:{self.port}")
        
        # Start the main server loop
        accept_thread = threading.Thread(target=self.accept_connections)
        accept_thread.daemon = True
        accept_thread.start()
        
        # Start maintenance thread
        maintenance_thread = threading.Thread(target=self.maintenance_loop)
        maintenance_thread.daemon = True
        maintenance_thread.start()
        
        try:
            # Keep the main thread alive
            while True:
                time.sleep(1)
        except KeyboardInterrupt:
            print("Server shutting down...")
            self.socket.close()
    
    def accept_connections(self):
        while True:
            client_socket, address = self.socket.accept()
            print(f"New connection from {address}")
            
            # Start a new thread to handle client
            client_thread = threading.Thread(target=self.handle_client, args=(client_socket,))
            client_thread.daemon = True
            client_thread.start()
    
    def handle_client(self, client_socket):
        user_id = None
        
        try:
            while True:
                # Receive message
                data = client_socket.recv(16384)
                if not data:
                    break  # Client disconnected
                
                try:
                    # Decode message
                    message = json.loads(data.decode('utf-8'))
                    message_type = message.get('type')
                    
                    # Process message based on type
                    if message_type == 'register':
                        response = self.handle_registration(message)
                    elif message_type == 'login':
                        response, user_id = self.handle_login(message, client_socket)
                    elif message_type == 'key_exchange':
                        response = self.handle_key_exchange(message, user_id)
                    elif message_type == 'message':
                        response = self.handle_message(message, user_id)
                    elif message_type == 'get_users':
                        response = self.handle_get_users(user_id)
                    elif message_type == 'logout':
                        response = self.handle_logout(user_id)
                        user_id = None
                    else:
                        response = {'status': 'error', 'message': 'Unknown message type'}
                    
                    # Send response
                    client_socket.send(json.dumps(response).encode('utf-8'))
                    
                except json.JSONDecodeError:
                    response = {'status': 'error', 'message': 'Invalid JSON format'}
                    client_socket.send(json.dumps(response).encode('utf-8'))
        
        except Exception as e:
            print(f"Error handling client: {e}")
        
        finally:
            # Clean up if the client disconnects
            if user_id:
                with self.lock:
                    if user_id in self.user_connections:
                        del self.user_connections[user_id]
                    if client_socket in self.connection_users:
                        del self.connection_users[client_socket]
                    
                    for user in self.users.values():
                        if user.id == user_id:
                            user.online = False
                            user.last_seen = time.time()
                            break
            
            client_socket.close()
    
    def handle_registration(self, message):
        username = message.get('username')
        password = message.get('password')
        
        if not username or not password:
            return {'status': 'error', 'message': 'Username and password required'}
        
        with self.lock:
            if username in self.users:
                return {'status': 'error', 'message': 'Username already exists'}
            
            # Hash the password
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            
            # Create new user
            user = User(username, password_hash)
            self.users[username] = user
            self.pending_messages[user.id] = []
            
            return {'status': 'success', 'message': 'Registration successful', 'user_id': user.id}
    
    def handle_login(self, message, connection):
        username = message.get('username')
        password = message.get('password')
        
        if not username or not password:
            return {'status': 'error', 'message': 'Username and password required'}, None
        
        with self.lock:
            if username not in self.users:
                return {'status': 'error', 'message': 'User not found'}, None
            
            user = self.users[username]
            
            # Verify password
            password_hash = hashlib.sha256(password.encode()).hexdigest()
            if password_hash != user.password_hash:
                return {'status': 'error', 'message': 'Invalid password'}, None
            
            # Mark user as online
            user.online = True
            user.last_seen = time.time()
            
            # Associate connection with user
            self.user_connections[user.id] = connection
            self.connection_users[connection] = user.id
            
            # Get server's public key
            server_public_key = self.secure_system.get_public_key()
            
            # Send any pending messages
            pending = self.pending_messages.get(user.id, [])
            
            return {
                'status': 'success', 
                'message': 'Login successful', 
                'user_id': user.id,
                'server_public_key': base64.b64encode(server_public_key).decode('utf-8'),
                'pending_messages': pending
            }, user.id
    
    def handle_key_exchange(self, message, user_id):
        if not user_id:
            return {'status': 'error', 'message': 'Not authenticated'}
        
        client_public_key = message.get('public_key')
        if not client_public_key:
            return {'status': 'error', 'message': 'Public key required'}
        
        try:
            # Decode the client's public key
            decoded_key = base64.b64decode(client_public_key)
            
            # Establish connection with client
            with self.lock:
                for user in self.users.values():
                    if user.id == user_id:
                        user.public_key = decoded_key
                        break
                
                # Perform key exchange
                key_info = self.secure_system.establish_connection(user_id, decoded_key)
                
                return {
                    'status': 'success', 
                    'message': 'Key exchange successful',
                    'key_info': key_info
                }
                
        except Exception as e:
            return {'status': 'error', 'message': f'Key exchange failed: {str(e)}'}
    
    def handle_message(self, message, user_id):
        if not user_id:
            return {'status': 'error', 'message': 'Not authenticated'}
        
        recipient_id = message.get('recipient_id')
        encrypted_content = message.get('content')
        
        if not recipient_id or not encrypted_content:
            return {'status': 'error', 'message': 'Recipient ID and content required'}
        
        # Create message object
        msg_obj = {
            'from': user_id,
            'content': encrypted_content,
            'timestamp': time.time()
        }
        
        # Find username of sender
        sender_username = None
        for username, user in self.users.items():
            if user.id == user_id:
                sender_username = username
                break
        
        if sender_username:
            msg_obj['sender_username'] = sender_username
        
        # Check if recipient is online
        with self.lock:
            if recipient_id in self.user_connections:
                # Recipient is online, send message directly
                try:
                    recipient_conn = self.user_connections[recipient_id]
                    response = {
                        'type': 'new_message',
                        'message': msg_obj
                    }
                    recipient_conn.send(json.dumps(response).encode('utf-8'))
                except Exception as e:
                    print(f"Error sending message to recipient: {e}")
                    # Store as pending message
                    if recipient_id in self.pending_messages:
                        self.pending_messages[recipient_id].append(msg_obj)
            else:
                # Recipient is offline, store message
                if recipient_id in self.pending_messages:
                    self.pending_messages[recipient_id].append(msg_obj)
        
        return {'status': 'success', 'message': 'Message sent'}
    
    def handle_get_users(self, user_id):
        if not user_id:
            return {'status': 'error', 'message': 'Not authenticated'}
        
        with self.lock:
            # Get all users except the requesting user
            user_list = []
            for username, user in self.users.items():
                if user.id != user_id:
                    user_list.append({
                        'id': user.id,
                        'username': username,
                        'online': user.online
                    })
            
            return {'status': 'success', 'users': user_list}
    
    def handle_logout(self, user_id):
        if not user_id:
            return {'status': 'error', 'message': 'Not authenticated'}
        
        with self.lock:
            for user in self.users.values():
                if user.id == user_id:
                    user.online = False
                    user.last_seen = time.time()
                    break
            
            if user_id in self.user_connections:
                del self.user_connections[user_id]
        
        return {'status': 'success', 'message': 'Logout successful'}
    
    def maintenance_loop(self):
        """Periodic maintenance tasks like cleaning up inactive connections."""
        while True:
            time.sleep(60)  # Run every minute
            
            current_time = time.time()
            with self.lock:
                # Check for inactive users (offline for more than 1 hour)
                for username, user in list(self.users.items()):
                    if not user.online and (current_time - user.last_seen) > 3600:
                        # Clear pending messages older than 7 days
                        if user.id in self.pending_messages:
                            self.pending_messages[user.id] = [
                                msg for msg in self.pending_messages[user.id]
                                if (current_time - msg.get('timestamp', 0)) < 604800  # 7 days
                            ]

# ===============================
# Part 6: Client Implementation
# ===============================

class QuantumChatClient:
    def __init__(self, server_host='localhost', server_port=8000):
        self.server_host = server_host
        self.server_port = server_port
        self.socket = None
        self.user_id = None
        self.secure_system = SecureMessagingSystem(use_qkd=True, qkd_qubits=100)
        self.connected = False
        self.message_callback = None
        self.users_list = []
        self.receiver_thread = None
        self.username = None
    
    def connect(self):
        """Connect to the server."""
        try:
            self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
            self.socket.connect((self.server_host, self.server_port))
            self.connected = True
            return True
        except Exception as e:
            print(f"Connection error: {e}")
            return False
    
    def register(self, username, password):
        """Register a new user account."""
        if not self.connected:
            return False, "Not connected to server"
        
        message = {
            'type': 'register',
            'username': username,
            'password': password
        }
        
        try:
            self.socket.send(json.dumps(message).encode('utf-8'))
            response = json.loads(self.socket.recv(4096).decode('utf-8'))
            
            if response.get('status') == 'success':
                return True, response.get('message')
            else:
                return False, response.get('message')
        except Exception as e:
            return False, f"Registration error: {e}"
    
    def login(self, username, password):
        """Login to the server."""
        if not self.connected:
            return False, "Not connected to server"
        
        message = {
            'type': 'login',
            'username': username,
            'password': password
        }
        
        try:
            self.socket.send(json.dumps(message).encode('utf-8'))
            response = json.loads(self.socket.recv(4096).decode('utf-8'))
            
            if response.get('status') == 'success':
                self.user_id = response.get('user_id')
                self.username = username
                
                # Get server's public key
                server_public_key = base64.b64decode(response.get('server_public_key'))
                
                # Perform key exchange
                client_public_key = self.secure_system.get_public_key()
                
                # Send client's public key to the server
                key_exchange_msg = {
                    'type': 'key_exchange',
                    'public_key': base64.b64encode(client_public_key).decode('utf-8')
                }
                self.socket.send(json.dumps(key_exchange_msg).encode('utf-8'))
                key_response = json.loads(self.socket.recv(4096).decode('utf-8'))
                
                if key_response.get('status') == 'success':
                    # Establish connection with server
                    self.secure_system.establish_connection('server', server_public_key)
                    
                    # Start message receiver thread
                    self.start_receiver()
                    
                    # Process any pending messages
                    pending_messages = response.get('pending_messages', [])
                    for msg in pending_messages:
                        if self.message_callback:
                            self.message_callback(msg)
                    
                    return True, "Login successful"
                else:
                    return False, "Key exchange failed"
            else:
                return False, response.get('message')
        except Exception as e:
            return False, f"Login error: {e}"
    
    def logout(self):
        """Logout from the server."""
        if not self.connected or not self.user_id:
            return False, "Not logged in"
        
        message = {
            'type': 'logout'
        }
        
        try:
            self.socket.send(json.dumps(message).encode('utf-8'))
            response = json.loads(self.socket.recv(4096).decode('utf-8'))
            
            if response.get('status') == 'success':
                self.user_id = None
                self.username = None
                return True, response.get('message')
            else:
                return False, response.get('message')
        except Exception as e:
            return False, f"Logout error: {e}"
    
    def get_users(self):
        """Get a list of all users."""
        if not self.connected or not self.user_id:
            return False, "Not logged in"
        
        message = {
            'type': 'get_users'
        }
        
        try:
            self.socket.send(json.dumps(message).encode('utf-8'))
            response = json.loads(self.socket.recv(4096).decode('utf-8'))
            
            if response.get('status') == 'success':
                self.users_list = response.get('users', [])
                return True, self.users_list
        except Exception as e:
            return False, f"Error getting users: {e}"
    
    def send_message(self, recipient_id, message_text):
        """Send an encrypted message to a recipient."""
        if not self.connected or not self.user_id:
            return False, "Not logged in"
        
        try:
            # Encrypt the message
            encrypted_data = self.secure_system.send_message('server', message_text)
            
            # Create message object
            message = {
                'type': 'message',
                'recipient_id': recipient_id,
                'content': encrypted_data
            }
            
            # Send to server
            self.socket.send(json.dumps(message).encode('utf-8'))
            response = json.loads(self.socket.recv(4096).decode('utf-8'))
            
            if response.get('status') == 'success':
                return True, "Message sent"
            else:
                return False, response.get('message')
        except Exception as e:
            return False, f"Error sending message: {e}"
    
    def start_receiver(self):
        """Start the message receiver thread."""
        if self.receiver_thread and self.receiver_thread.is_alive():
            return  # Already running
        
        self.receiver_thread = threading.Thread(target=self._receive_messages)
        self.receiver_thread.daemon = True
        self.receiver_thread.start()
    
    def _receive_messages(self):
        """Background thread to receive messages."""
        while self.connected and self.user_id:
            try:
                data = self.socket.recv(16384)
                if not data:
                    break  # Connection closed
                
                message = json.loads(data.decode('utf-8'))
                
                if message.get('type') == 'new_message':
                    # Process incoming message
                    msg_data = message.get('message', {})
                    
                    # Decrypt the message
                    if 'content' in msg_data:
                        try:
                            decrypted_content = self.secure_system.receive_message('server', msg_data['content'])
                            msg_data['decrypted_content'] = decrypted_content
                        except Exception as e:
                            msg_data['decrypted_content'] = f"[Error decrypting: {e}]"
                    
                    # Call the callback function
                    if self.message_callback:
                        self.message_callback(msg_data)
            
            except json.JSONDecodeError:
                print("Received invalid JSON")
            except Exception as e:
                print(f"Error in message receiver: {e}")
                break
        
        # If we get here, the connection has been lost
        self.connected = False
    
    def set_message_callback(self, callback):
        """Set the callback function for new messages."""
        self.message_callback = callback
    
    def disconnect(self):
        """Disconnect from the server."""
        if self.connected:
            try:
                if self.user_id:
                    self.logout()
                self.socket.close()
            except:
                pass
            finally:
                self.connected = False
                self.user_id = None
                self.username = None

# ===============================
# Part 7: Main Server Execution
# ===============================

if __name__ == "__main__":
    # Start the server
    server = QuantumChatServer(host='0.0.0.0', port=8000)
    server.start()