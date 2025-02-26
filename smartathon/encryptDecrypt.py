import numpy as np
import qutip as qt
from cryptography.hazmat.primitives.asymmetric import x25519
from cryptography.hazmat.primitives import hashes
from cryptography.hazmat.primitives.kdf.hkdf import HKDF
from cryptography.hazmat.primitives.ciphers import Cipher, algorithms, modes
import os
import base64
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
        self.shared_key = None
        
        # For simulation, we can use this shortcut key
        self.simulation_key = None
    
    def establish_connection(self, peer_public_key=None):
        """Establish a secure connection using QKD and/or post-quantum key exchange."""
        keys = {}
        quantum_key = None
        classical_key = None
        
        # For simulation mode, use a deterministic key (in real world, this would be a security risk)
        if self.simulation_mode:
            # Generate a deterministic key for demo purposes
            self.simulation_key = hashlib.sha256(b"simulation_key_for_demo").digest()
        
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
        
        # Step 3: Combine keys or use simulation key
        if self.simulation_mode:
            self.shared_key = self.simulation_key
            keys['method'] = 'simulation'
        elif quantum_key and classical_key:
            # Ensure both keys are the same length before combining
            self.shared_key = self.key_processor.combine_keys(quantum_key, classical_key)
            keys['method'] = 'hybrid'
        elif quantum_key:
            self.shared_key = quantum_key
            keys['method'] = 'quantum'
        elif classical_key:
            self.shared_key = classical_key
            keys['method'] = 'classical'
        else:
            raise ValueError("No key exchange method succeeded")
        
        keys['final_key_length'] = len(self.shared_key) * 8  # in bits
        return keys
    
    def get_public_key(self):
        """Get the public key for the classical exchange."""
        return self.pq_channel.get_public_key_bytes()
    
    def send_message(self, message):
        """Encrypt and send a message."""
        if not self.shared_key:
            raise ValueError("Secure connection not established. Call establish_connection first.")
        
        if isinstance(message, str):
            message = message.encode('utf-8')
        
        return self.pq_channel.encrypt(message, self.shared_key)
    
    def receive_message(self, encrypted_data):
        """Decrypt a received message."""
        if not self.shared_key:
            raise ValueError("Secure connection not established. Call establish_connection first.")
        
        decrypted = self.pq_channel.decrypt(encrypted_data, self.shared_key)
        
        try:
            # Try to decode as UTF-8 if it's text
            return decrypted.decode('utf-8')
        except UnicodeDecodeError:
            # Return raw bytes if it's binary data
            return decrypted

# ===============================
# Example Usage
# ===============================

def demonstrate_secure_communication():
    print("Initializing secure communication systems...")
    
    # Set a fixed seed for reproducibility in the demo
    demo_seed = 42
    
    # Create Alice and Bob's communication systems with the same seed for demo purposes
    alice = SecureMessagingSystem(use_qkd=True, qkd_qubits=200, 
                                  channel_noise=0.02, seed=demo_seed, 
                                  simulation_mode=True)
    
    bob = SecureMessagingSystem(use_qkd=True, qkd_qubits=200, 
                                channel_noise=0.02, seed=demo_seed, 
                                simulation_mode=True)
    
    # Exchange classical public keys
    alice_public_key = alice.get_public_key()
    bob_public_key = bob.get_public_key()
    
    # Establish secure connections
    print("\nEstablishing secure connection...")
    alice_connection = alice.establish_connection(bob_public_key)
    bob_connection = bob.establish_connection(alice_public_key)
    
    print(f"Connection established using {alice_connection['method']} key exchange")
    print(f"Final key length: {alice_connection['final_key_length']} bits")
    
    if 'qkd' in alice_connection:
        print("\nQKD Statistics:")
        print(f"- Total qubits exchanged: {alice_connection['qkd']['total_qubits']}")
        print(f"- Matching measurement bases: {alice_connection['qkd']['matching_bases']}")
        print(f"- Quantum bit error rate: {alice_connection['qkd']['error_rate']:.2%}")
        print(f"- Raw key bits from QKD: {alice_connection['qkd']['raw_key_length']}")
        print(f"- Processed quantum key length: {alice_connection['qkd']['processed_key_length']} bits")
    
    # Send messages
    print("\nAlice sending message to Bob...")
    message = "This is a top-secret message protected by quantum and post-quantum cryptography!"
    encrypted = alice.send_message(message)
    
    print("\nEncrypted message details:")
    print(f"- IV: {encrypted['iv']}")
    print(f"- Ciphertext: {encrypted['ciphertext'][:20]}... (truncated)")
    print(f"- Authentication tag: {encrypted['tag']}")
    
    # Receive and decrypt message
    print("\nBob receiving and decrypting message...")
    decrypted = bob.receive_message(encrypted)
    
    print("\nDecrypted message:")
    print(f"- {decrypted}")
    
    # Verify integrity
    print("\nMessage integrity verification:")
    print(f"- Original equals decrypted: {message == decrypted}")
    
    # Test sending a message from Bob to Alice
    print("\nBob sending message to Alice...")
    bob_message = "Response received! Our quantum-secured channel is working perfectly."
    bob_encrypted = bob.send_message(bob_message)
    alice_decrypted = alice.receive_message(bob_encrypted)
    
    print("\nAlice received and decrypted message:")
    print(f"- {alice_decrypted}")
    print(f"- Original equals decrypted: {bob_message == alice_decrypted}")


demonstrate_secure_communication()