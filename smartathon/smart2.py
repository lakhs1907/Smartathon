import numpy as np
import qutip as qt
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64
import hashlib
import time
import json
import argparse
import threading
from datetime import datetime
import uuid
import getpass
import signal
import sys

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
# Part 4: Enhanced Secure Communication System
# ===============================

class SecureMessagingSystem:
    def __init__(self, username, use_qkd=True, qkd_qubits=100, simulate_eavesdropper=False, 
                 channel_noise=0.01, seed=None, simulation_mode=False):
        self.username = username
        self.use_qkd = use_qkd
        self.simulation_mode = simulation_mode
        self.connected_users = {}  # Map of username -> shared_key
        self.message_history = {}  # Store message history by user
        self.online = False
        self.current_chat_user = None
        
        # In simulation mode, use the same seed for all random generators
        # to ensure Alice and Bob get matching keys for demo purposes
        self.seed = seed if simulation_mode else None
        
        self.qkd_simulation = BB84Simulation(
            num_qubits=qkd_qubits,
            eavesdropper=simulate_eavesdropper,
            error_rate=channel_noise,
            seed=self.seed
        )
        self.pq_channel = PostQuantumSecureChannel(seed=self.seed)
        self.key_processor = KeyProcessor()
        
        # For simulation, we can use this shortcut key
        self.simulation_key = None
        
        # Session identifier
        self.session_id = str(uuid.uuid4())
        
        # Key rotation settings
        self.key_rotation_interval = 3600  # 1 hour by default
        self.last_key_rotation = time.time()
        
        # Message sequence number for detecting missing messages
        self.sequence_numbers = {}  # username -> next expected sequence number
    
    def establish_connection(self, username, peer_public_key=None):
        """Establish a secure connection with another user using QKD and/or post-quantum key exchange."""
        keys = {}
        quantum_key = None
        classical_key = None
        
        # For simulation mode, use a deterministic key (in real world, this would be a security risk)
        if self.simulation_mode:
            # Generate a deterministic key for demo purposes
            combined_names = ''.join(sorted([self.username, username]))
            self.simulation_key = hashlib.sha256(f"simulation_key_for_{combined_names}".encode()).digest()
        
        # Step 1: Run QKD protocol if enabled
        if self.use_qkd:
            print(f"Running QKD protocol with {username}...")
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
            print(f"Deriving shared key with {username}...")
            classical_key = self.pq_channel.derive_shared_key(peer_public_key)
            keys['classical'] = {
                'key_length': len(classical_key) * 8  # in bits
            }
        
        # Step 3: Combine keys or use simulation key
        shared_key = None
        if self.simulation_mode:
            shared_key = self.simulation_key
            keys['method'] = 'simulation'
        elif quantum_key and classical_key:
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
        
        # Store the shared key for this user
        self.connected_users[username] = {
            'shared_key': shared_key,
            'established_at': time.time(),
            'last_message': None
        }
        
        # Initialize message history
        if username not in self.message_history:
            self.message_history[username] = []
        
        # Initialize sequence numbers
        self.sequence_numbers[username] = 0
        
        keys['final_key_length'] = len(shared_key) * 8  # in bits
        return keys
    
    def get_public_key(self):
        """Get the public key for the classical exchange."""
        return self.pq_channel.get_public_key_bytes()
    
    def check_key_rotation(self, username):
        """Check if key rotation is needed and perform it if necessary."""
        if username not in self.connected_users:
            return False
        
        user_data = self.connected_users[username]
        current_time = time.time()
        
        if current_time - user_data['established_at'] > self.key_rotation_interval:
            print(f"Rotating keys for session with {username}...")
            # In a real system, we would initiate a new key exchange here
            # For demo purposes, we'll just derive a new key from the old one
            old_key = user_data['shared_key']
            new_key = hashlib.sha256(old_key + str(current_time).encode()).digest()
            
            self.connected_users[username] = {
                'shared_key': new_key,
                'established_at': current_time,
                'last_message': user_data['last_message']
            }
            return True
        
        return False
    
    def encrypt_message(self, recipient, message_text):
        """Encrypt a message for a specific recipient."""
        if recipient not in self.connected_users:
            raise ValueError(f"No secure connection established with {recipient}")
        
        # Check if we need to rotate keys
        self.check_key_rotation(recipient)
        
        # Get the shared key for this recipient
        shared_key = self.connected_users[recipient]['shared_key']
        
        # Update the last message time
        self.connected_users[recipient]['last_message'] = time.time()
        
        # Prepare the message
        message_data = {
            'sender': self.username,
            'recipient': recipient,
            'timestamp': datetime.now().isoformat(),
            'text': message_text,
            'sequence': self.sequence_numbers.get(recipient, 0)
        }
        
        # Increment sequence number
        self.sequence_numbers[recipient] = self.sequence_numbers.get(recipient, 0) + 1
        
        # Serialize and encrypt
        message_bytes = json.dumps(message_data).encode('utf-8')
        encrypted = self.pq_channel.encrypt(message_bytes, shared_key)
        
        # Add metadata
        encrypted['sender'] = self.username
        encrypted['recipient'] = recipient
        encrypted['session_id'] = self.session_id
        encrypted['timestamp'] = datetime.now().isoformat()
        
        return encrypted
    
    def decrypt_message(self, encrypted_data):
        """Decrypt a received message."""
        sender = encrypted_data.get('sender')
        if not sender or sender not in self.connected_users:
            raise ValueError(f"No secure connection established with sender {sender}")
        
        # Get the shared key for this sender
        shared_key = self.connected_users[sender]['shared_key']
        
        # Remove metadata before decryption
        decrypt_data = {k: encrypted_data[k] for k in ['iv', 'ciphertext', 'tag']}
        
        try:
            # Decrypt the message
            decrypted_bytes = self.pq_channel.decrypt(decrypt_data, shared_key)
            message_data = json.loads(decrypted_bytes.decode('utf-8'))
            
            # Verify sequence number to detect missed messages
            expected_seq = self.sequence_numbers.get(sender, 0)
            actual_seq = message_data.get('sequence', 0)
            
            if actual_seq > expected_seq:
                print(f"Warning: Missed {actual_seq - expected_seq} messages from {sender}")
            
            # Update sequence number
            self.sequence_numbers[sender] = actual_seq + 1
            
            # Update message history
            self.message_history.setdefault(sender, []).append(message_data)
            
            return message_data
        except Exception as e:
            print(f"Error decrypting message: {e}")
            return None
    
    def get_message_history(self, username):
        """Get message history with a specific user."""
        return self.message_history.get(username, [])
    
    def simulate_network_transmission(self, encrypted_message, recipient_system):
        """Simulate sending a message over a network to another user's system."""
        # In a real application, this would involve actual network transmission
        # For our demo, we'll just directly pass the message to the recipient
        return recipient_system.receive_message(encrypted_message)
    
    def receive_message(self, encrypted_message):
        """Handle receiving an encrypted message."""
        # In a real app, this would be called by a network listener
        if not self.online:
            print("Cannot receive messages while offline")
            return False
        
        try:
            decrypted = self.decrypt_message(encrypted_message)
            if decrypted:
                sender = decrypted['sender']
                timestamp = datetime.fromisoformat(decrypted['timestamp']).strftime('%H:%M:%S')
                text = decrypted['text']
                
                # Display the message if it's from the current chat partner
                if self.current_chat_user and sender == self.current_chat_user:
                    print(f"\r[{timestamp}] {sender}: {text}")
                else:
                    print(f"\r\nNew message from {sender}")
                
                return True
            return False
        except Exception as e:
            print(f"Error processing received message: {e}")
            return False
    
    def go_online(self):
        """Set the system to online mode."""
        self.online = True
        print(f"{self.username} is now online.")
    
    def go_offline(self):
        """Set the system to offline mode."""
        self.online = False
        self.current_chat_user = None
        print(f"{self.username} is now offline.")

# ===============================
# Part 5: User Interface
# ===============================

class SecureMessengerCLI:
    def __init__(self):
        self.user_system = None
        self.other_users = {}  # Dictionary of other users' systems for simulation
        self.running = False
        self.message_thread = None
        
        # Set up signal handlers for clean exit
        signal.signal(signal.SIGINT, self.handle_interrupt)
    
    def handle_interrupt(self, sig, frame):
        """Handle Ctrl+C interrupt."""
        print("\nShutting down messenger...")
        self.running = False
        if self.user_system:
            self.user_system.go_offline()
        sys.exit(0)
    
    def create_user(self, username, is_main_user=False):
        """Create a user system."""
        system = SecureMessagingSystem(
            username=username,
            use_qkd=True,
            qkd_qubits=200,
            channel_noise=0.02,
            simulation_mode=True
        )
        
        if is_main_user:
            self.user_system = system
        else:
            self.other_users[username] = system
        
        return system
    
    def establish_connections(self):
        """Establish connections between the main user and other users."""
        if not self.user_system:
            print("Main user not created yet.")
            return
        
        for username, system in self.other_users.items():
            print(f"\nEstablishing connection with {username}...")
            
            # Exchange public keys
            main_public_key = self.user_system.get_public_key()
            other_public_key = system.get_public_key()
            
            # Establish connections
            main_connection = self.user_system.establish_connection(username, other_public_key)
            other_connection = system.establish_connection(self.user_system.username, main_public_key)
            
            print(f"Connection established using {main_connection['method']} key exchange")
            print(f"Final key length: {main_connection['final_key_length']} bits")
            
            if 'qkd' in main_connection:
                print("\nQKD Statistics:")
                print(f"- Total qubits exchanged: {main_connection['qkd']['total_qubits']}")
                print(f"- Matching measurement bases: {main_connection['qkd']['matching_bases']}")
                print(f"- Quantum bit error rate: {main_connection['qkd']['error_rate']:.2%}")
                print(f"- Raw key bits from QKD: {main_connection['qkd']['raw_key_length']}")
    
    def message_listener(self):
        """Background thread to simulate receiving messages."""
        while self.running and self.user_system and self.user_system.online:
            # In a real app, this would be listening for incoming network messages
            # For simulation, we'll just sleep to avoid consuming CPU
            time.sleep(0.1)
    
    def send_message(self, recipient, message):
        """Send a message to a recipient."""
        if not self.user_system:
            print("You must log in first.")
            return False
        
        if not self.user_system.online:
            print("You are offline. Go online to send messages.")
            return False
        
        if recipient not in self.other_users:
            print(f"User {recipient} not found.")
            return False
        
        # Encrypt the message
        encrypted = self.user_system.encrypt_message(recipient, message)
        
        # Update the chat display for the sender
        timestamp = datetime.now().strftime('%H:%M:%S')
        print(f"[{timestamp}] You: {message}")
        
        # Simulate network transmission
        recipient_system = self.other_users[recipient]
        if recipient_system.online:
            success = self.user_system.simulate_network_transmission(encrypted, recipient_system)
            if not success:
                print("Failed to deliver message.")
            return success
        else:
            print(f"{recipient} is offline. Message not delivered.")
            return False
    
    def display_chat(self, username):
        """Display chat history with a user."""
        if not self.user_system:
            print("You must log in first.")
            return
        
        history = self.user_system.get_message_history(username)
        print(f"\n===== Chat with {username} =====")
        
        if not history:
            print("No messages yet.")
        else:
            for msg in history:
                sender = msg['sender']
                timestamp = datetime.fromisoformat(msg['timestamp']).strftime('%H:%M:%S')
                text = msg['text']
                
                if sender == self.user_system.username:
                    print(f"[{timestamp}] You: {text}")
                else:
                    print(f"[{timestamp}] {sender}: {text}")
        
        print("=" * 30)
    
    def interactive_session(self):
        """Run an interactive messaging session."""
        print("\n===== Quantum-Classical Secure Messenger =====")
        print("Welcome to QC-SecureChat!")
        
        # Log in
        username = input("Enter your username: ")
        self.create_user(username, is_main_user=True)
        self.user_system.go_online()
        
        # Create some sample users
        sample_users = ["Alice", "Bob", "Charlie"]
        for user in sample_users:
            if user != username:
                system = self.create_user(user)
                system.go_online()
        
        # Establish connections
        self.establish_connections()
        
        # Start message listener
        self.running = True
        self.message_thread = threading.Thread(target=self.message_listener)
        self.message_thread.daemon = True
        self.message_thread.start()
        
        while self.running:
            print("\nAvailable commands:")
            print("1. List users")
            print("2. Chat with user")
            print("3. View connection status")
            print("4. Rotate keys")
            print("5. Go offline")
            print("6. Exit")
            
            choice = input("\nEnter choice (1-6): ")
            
            if choice == "1":
                print("\nConnected Users:")
                for i, user in enumerate(self.other_users.keys(), 1):
                    online_status = "online" if self.other_users[user].online else "offline"
                    print(f"{i}. {user} ({online_status})")
            
            elif choice == "2":
                print("\nSelect a user to chat with:")
                users = list(self.other_users.keys())
                for i, user in enumerate(users, 1):
                    print(f"{i}. {user}")
                
                try:
                    idx = int(input("\nEnter user number: ")) - 1
                    if 0 <= idx < len(users):
                        chat_user = users[idx]
                        self.user_system.current_chat_user = chat_user
                        
                        # Display chat history
                        self.display_chat(chat_user)
                        
                        print(f"\nChatting with {chat_user} (type 'exit' to return to menu)")
                        while self.running:
                            message = input("> ")
                            if message.lower() == 'exit':
                                self.user_system.current_chat_user = None
                                break
                            
                            self.send_message(chat_user, message)
                    else:
                        print("Invalid user number.")
                except ValueError:
                    print("Please enter a valid number.")
            
            elif choice == "3":
                print("\nConnection Status:")
                for user, data in self.user_system.connected_users.items():
                    established = datetime.fromtimestamp(data['established_at']).strftime('%Y-%m-%d %H:%M:%S')
                    if data['last_message']:
                        last_msg = datetime.fromtimestamp(data['last_message']).strftime('%Y-%m-%d %H:%M:%S')
                    else:
                        last_msg = "Never"
                    
                    print(f"User: {user}")
                    print(f"  - Connection established: {established}")
                    print(f"  - Last message: {last_msg}")
                    print(f"  - Key age: {int(time.time() - data['established_at'])} seconds")
                    print(f"  - Next key rotation in: {self.user_system.key_rotation_interval - int(time.time() - data['established_at'])} seconds")
            
            elif choice == "4":
                print("\nForce key rotation for which user?")
                users = list(self.user_system.connected_users.keys())
                for i, user in enumerate(users, 1):
                    print(f"{i}. {user}")
                
                try:
                    idx = int(input("\nEnter user number (0 for all): ")) - 1
                    if idx == -1:
                        for user in users:
                            rotated = self.user_system.check_key_rotation(user)
                            if not rotated:
                                # Force rotation
                                user_data = self.user_system.connected_users[user]
                                old_key = user_data['shared_key']
                                new_key = hashlib.sha256(old_key + b"forced_rotation").digest()
                                
                                self.user_system.connected_users[user] = {
                                    'shared_key': new_key,
                                    'established_at': time.time(),
                                    'last_message': user_data['last_message']
                                }
                            print(f"Rotated key for {user}")
                    elif 0 <= idx < len(users):
                        user = users[idx]
                        rotated = self.user_system.check_key_rotation(user)
                        if not rotated:
                            # Force rotation
                            user_data = self.user_system.connected_users[user]
                            old_key = user_data['shared_key']
                            new_key = hashlib.sha256(old_key + b"forced_rotation").digest()
                            
                            self.user_system.connected_users[user] = {
                                'shared_key': new_key,
                                'established_at': time.time(),
                                'last_message': user_data['last_message']
                            }
                        print(f"Rotated key for {user}")
                    else:
                        print("Invalid user number.")
                except ValueError:
                    print("Please enter a valid number.")
            
            elif choice == "5":
                self.user_system.go_offline()
                input("Press Enter to go back online...")
                self.user_system.go_online()
            
            elif choice == "6":
                self.running = False
                break
            
            else:
                
                self.running = True
                break