
// File: src/App.js
import React, { useState, useEffect, useRef } from 'react';
import io from 'socket.io-client';
import './App.css';
//import LoginRegister from './components/LoginRegister';
//const LoginRegister = require("./components/LoginRegister");
import ChatRoom from './components/ChatRoom';
import RoomList from './components/RoomList';
//import { encryptMessage, decryptMessage, generateNewKeys } from './encryption';

const API_URL = 'http://localhost:5000';
const socket = io(API_URL);

export const generateNewKeys = async () => {
  try {
    // In a real PQC implementation, you would use:
    // - Kyber for key encapsulation mechanism (KEM)
    // - Dilithium for digital signatures
    // For this demo, we're using RSA as a placeholder

    // Generate a key pair
    const keyPair = await window.crypto.subtle.generateKey(
      {
        name: "RSA-OAEP",
        modulusLength: 2048,
        publicExponent: new Uint8Array([1, 0, 1]),
        hash: "SHA-256",
      },
      true,
      ["encrypt", "decrypt"]
    );

    // Export the public key
    const publicKeyBuffer = await window.crypto.subtle.exportKey(
      "spki",
      keyPair.publicKey
    );

    // Export the private key
    const privateKeyBuffer = await window.crypto.subtle.exportKey(
      "pkcs8",
      keyPair.privateKey
    );

    // Convert to Base64
    const publicKey = btoa(
      String.fromCharCode(...new Uint8Array(publicKeyBuffer))
    );
    const privateKey = btoa(
      String.fromCharCode(...new Uint8Array(privateKeyBuffer))
    );

    return { publicKey, privateKey };
  } catch (error) {
    console.error('Error generating keys:', error);
    throw new Error('Failed to generate encryption keys');
  }
};

export const encryptMessage = async (message, publicKeyBase64) => {
  try {
    // Convert Base64 public key to buffer
    const publicKeyBytes = Uint8Array.from(atob(publicKeyBase64), c => c.charCodeAt(0));

    // Import the public key
    const publicKey = await window.crypto.subtle.importKey(
      "spki",
      publicKeyBytes.buffer,
      {
        name: "RSA-OAEP",
        hash: "SHA-256"
      },
      false,
      ["encrypt"]
    );

    // Encrypt the message
    const messageBuffer = new TextEncoder().encode(message);
    const encryptedBuffer = await window.crypto.subtle.encrypt(
      {
        name: "RSA-OAEP"
      },
      publicKey,
      messageBuffer
    );

    // Convert to Base64
    return btoa(String.fromCharCode(...new Uint8Array(encryptedBuffer)));
  } catch (error) {
    console.error('Error encrypting message:', error);
    throw new Error('Failed to encrypt message');
  }
};

export const decryptMessage = async (encryptedBase64, privateKeyBase64) => {
  try {
    // Convert Base64 private key to buffer
    const privateKeyBytes = Uint8Array.from(atob(privateKeyBase64), c => c.charCodeAt(0));

    // Import the private key
    const privateKey = await window.crypto.subtle.importKey(
      "pkcs8",
      privateKeyBytes.buffer,
      {
        name: "RSA-OAEP",
        hash: "SHA-256"
      },
      false,
      ["decrypt"]
    );

    // Convert Base64 encrypted message to buffer
    const encryptedBytes = Uint8Array.from(atob(encryptedBase64), c => c.charCodeAt(0));

    // Decrypt the message
    const decryptedBuffer = await window.crypto.subtle.decrypt(
      {
        name: "RSA-OAEP"
      },
      privateKey,
      encryptedBytes.buffer
    );

    // Convert to string
    return new TextDecoder().decode(decryptedBuffer);
  } catch (error) {
    console.error('Error decrypting message:', error);
    throw new Error('Failed to decrypt message');
  }
};


function App() {
  const [user, setUser] = useState(null);
  const [rooms, setRooms] = useState([]);
  const [activeRoom, setActiveRoom] = useState(null);
  const [messages, setMessages] = useState([]);
  const [publicKeys, setPublicKeys] = useState({});
  const [keyPair, setKeyPair] = useState(null);
  const [connected, setConnected] = useState(false);
  const [error, setError] = useState(null);

  // Set up socket event listeners
  useEffect(() => {
    socket.on('connect', () => {
      console.log('Connected to WebSocket server');
      setConnected(true);
    });

    socket.on('disconnect', () => {
      console.log('Disconnected from WebSocket server');
      setConnected(false);
    });

    socket.on('error', (data) => {
      console.error('Socket error:', data.message);
      setError(data.message);
    });

    socket.on('message', (message) => {
      setMessages((prevMessages) => [...prevMessages, message]);
    });

    socket.on('room_joined', (data) => {
      console.log('Joined room:', data.room);
    });

    socket.on('public_key', (data) => {
      setPublicKeys((prevKeys) => ({
        ...prevKeys,
        [data.username]: data.public_key
      }));
    });

    return () => {
      socket.off('connect');
      socket.off('disconnect');
      socket.off('error');
      socket.off('message');
      socket.off('room_joined');
      socket.off('public_key');
    };
  }, []);

  // Fetch rooms when user is set
  useEffect(() => {
    if (user) {
      fetchRooms();
    }
  }, [user]);

  // Fetch messages when active room changes
  useEffect(() => {
    if (activeRoom) {
      fetchMessages(activeRoom.id);
      joinRoom(activeRoom.id);
    }
  }, [activeRoom]);

  // Fetch all available rooms
  const fetchRooms = async () => {
    try {
      const response = await fetch(`${API_URL}/api/rooms`);
      const data = await response.json();
      setRooms(data.rooms);
    } catch (error) {
      console.error('Error fetching rooms:', error);
      setError('Failed to fetch rooms');
    }
  };

  // Fetch messages for a specific room
  const fetchMessages = async (roomId) => {
    try {
      const response = await fetch(`${API_URL}/api/rooms/${roomId}/messages`);
      const data = await response.json();
      setMessages(data.messages);
    } catch (error) {
      console.error('Error fetching messages:', error);
      setError('Failed to fetch messages');
    }
  };

  // Join a chat room
  const joinRoom = (roomId) => {
    socket.emit('join_room', {
      room_id: roomId,
      username: user.username
    });
  };

  // Create a new chat room
  const createRoom = async (roomName) => {
    try {
      const response = await fetch(`${API_URL}/api/rooms`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({
          name: roomName,
          created_by: user.username
        })
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Failed to create room');
      }

      const data = await response.json();
      setRooms((prevRooms) => [...prevRooms, data.room]);
      setActiveRoom(data.room);
    } catch (error) {
      console.error('Error creating room:', error);
      setError(error.message || 'Failed to create room');
    }
  };

  // Get public key for a user
  const getPublicKey = (username) => {
    if (!publicKeys[username]) {
      socket.emit('get_public_key', { username });
    }
    return publicKeys[username];
  };

  // Send a message in the active room
  const sendMessage = async (content, recipientUsername) => {
    if (!activeRoom || !user || !content.trim()) return;

    try {
      // Get recipient's public key
      const recipientPublicKey = getPublicKey(recipientUsername);

      if (!recipientPublicKey) {
        throw new Error(`Public key for ${recipientUsername} not available`);
      }

      // Encrypt message with recipient's public key
      const encryptedContent = await encryptMessage(content, recipientPublicKey);

      // Send the encrypted message
      socket.emit('send_message', {
        room_id: activeRoom.id,
        sender: user.username,
        content: encryptedContent,
        recipient: recipientUsername
      });

    } catch (error) {
      console.error('Error sending message:', error);
      setError('Failed to send message: ' + error.message);
    }
  };

  // Handle user login
  const handleLogin = async (username) => {
    try {
      const response = await fetch(`${API_URL}/api/login`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username })
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Login failed');
      }

      const data = await response.json();
      setUser(data.user);
      setKeyPair({
        publicKey: data.public_key,
        privateKey: localStorage.getItem(`private_key_${username}`)
      });

      // Store public key
      setPublicKeys((prevKeys) => ({
        ...prevKeys,
        [username]: data.public_key
      }));

    } catch (error) {
      console.error('Error logging in:', error);
      setError(error.message || 'Login failed');
    }
  };

  // Handle user registration
  const handleRegister = async (username) => {
    try {
      // First, generate client-side keys
      const clientKeys = await generateNewKeys();

      const response = await fetch(`${API_URL}/api/register`, {
        method: 'POST',
        headers: {
          'Content-Type': 'application/json'
        },
        body: JSON.stringify({ username })
      });

      if (!response.ok) {
        const data = await response.json();
        throw new Error(data.error || 'Registration failed');
      }

      const data = await response.json();
      setUser(data.user);

      // Save server-provided keys plus client-side keys
      setKeyPair({
        publicKey: data.public_key,
        privateKey: clientKeys.privateKey
      });

      // Store private key in local storage (in production, use a more secure method)
      localStorage.setItem(`private_key_${username}`, clientKeys.privateKey);

      // Store public key in our state
      setPublicKeys((prevKeys) => ({
        ...prevKeys,
        [username]: data.public_key
      }));

    } catch (error) {
      console.error('Error registering:', error);
      setError(error.message || 'Registration failed');
    }
  };

  // Handle logout
  const handleLogout = () => {
    setUser(null);
    setActiveRoom(null);
    setMessages([]);
    setKeyPair(null);
  };

  return (
    <div className="app-container">
      {error && (
        <div className="error-banner">
          <p>{error}</p>
          <button onClick={() => setError(null)}>Dismiss</button>
        </div>
      )}

    </div>
    {
    !user ? (
      <LoginRegister onLogin={handleLogin} onRegister={handleRegister} />
    ) : (
      <div className="chat-container">
        <div className="sidebar">
          <div className="user-info">
            <h3>Welcome, {user.username}</h3>
            <button onClick={handleLogout}>Logout</button>
          </div >

          <RoomList
            rooms={rooms}
            activeRoom={activeRoom}
            onSelectRoom={setActiveRoom}
            onCreateRoom={createRoom}
          />
        </div >

        {
          activeRoom ? (
            <ChatRoom
              room={activeRoom}
              messages={messages}
              currentUser={user}
              onSendMessage={sendMessage}
              keyPair={keyPair}
              publicKeys={publicKeys}
              getPublicKey={getPublicKey}
            />
          ) : (
            <div className="empty-chat">
              <h2>Select a room to start chatting</h2>
            </div >
          )
        }
      </div >
    )
  }
    </div >
  );
}

export default App;





// File: src/utils/encryption.js
// Note: In a real implementation, use a proper PQC library
// This is a simplified version for demonstration purposes

// Simulate Post-Quantum Cryptography operations

// File: src/App.css
/* Main App Styles */
