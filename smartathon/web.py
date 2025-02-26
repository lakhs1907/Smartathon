


import React from 'react';
import ReactDOM from 'react-dom';
import './styles.css';
import App from './App';

ReactDOM.render(
  <React.StrictMode>
    <App />
  </React.StrictMode>,
  document.getElementById('root')
);

// src/App.js
import React from 'react';
import { ChatProvider } from './contexts/ChatContext';
import Sidebar from './components/Sidebar';
import Chat from './components/Chat';

function App() {
  return (
    <ChatProvider>
      <div className="app">
        <div className="app__body">
          <Sidebar />
          <Chat />
        </div>
      </div>
    </ChatProvider>
  );
}

export default App;

// src/contexts/ChatContext.js
import React, { createContext, useState, useContext, useEffect } from 'react';
import useLocalStorage from '../hooks/useLocalStorage';

const ChatContext = createContext();

export const useChat = () => useContext(ChatContext);

export const ChatProvider = ({ children }) => {
  const [activeChat, setActiveChat] = useState(null);
  const [contacts, setContacts] = useLocalStorage('contacts', [
    { id: 1, name: 'John Doe', avatar: 'https://via.placeholder.com/40', lastSeen: '10:30 AM' },
    { id: 2, name: 'Jane Smith', avatar: 'https://via.placeholder.com/40', lastSeen: 'Yesterday' },
    { id: 3, name: 'Alice Johnson', avatar: 'https://via.placeholder.com/40', lastSeen: 'Online' },
    { id: 4, name: 'Bob Brown', avatar: 'https://via.placeholder.com/40', lastSeen: '2 days ago' },
    { id: 5, name: 'Work Group', avatar: 'https://via.placeholder.com/40', isGroup: true, members: [1, 2, 3] },
  ]);

  const [chats, setChats] = useLocalStorage('chats', [
    {
      id: 1,
      contactId: 1,
      messages: [
        { id: 1, text: 'Hey there!', sender: 1, timestamp: '10:00 AM', status: 'read' },
        { id: 2, text: 'How are you?', sender: 'me', timestamp: '10:01 AM', status: 'read' },
        { id: 3, text: 'Good, thanks!', sender: 1, timestamp: '10:02 AM', status: 'read' },
      ],
    },
    {
      id: 2,
      contactId: 2,
      messages: [
        { id: 1, text: 'Hi Jane!', sender: 'me', timestamp: '9:30 AM', status: 'read' },
        { id: 2, text: 'Hello! How is your project going?', sender: 2, timestamp: '9:35 AM', status: 'read' },
        { id: 3, text: 'It\'s going well, almost finished!', sender: 'me', timestamp: '9:40 AM', status: 'sent' },
      ],
    },
    {
      id: 3,
      contactId: 3,
      messages: [
        { id: 1, text: 'Alice, can you send me the document?', sender: 'me', timestamp: 'Yesterday', status: 'read' },
        { id: 2, text: 'Sure, here it is!', sender: 3, timestamp: 'Yesterday', status: 'read' },
        { id: 3, text: '[Document attached]', sender: 3, timestamp: 'Yesterday', status: 'read' },
      ],
    },
    {
      id: 4,
      contactId: 4,
      messages: [
        { id: 1, text: 'Meeting at 3 PM?', sender: 4, timestamp: '2 days ago', status: 'read' },
        { id: 2, text: 'Yes, I\'ll be there', sender: 'me', timestamp: '2 days ago', status: 'read' },
      ],
    },
    {
      id: 5,
      contactId: 5,
      messages: [
        { id: 1, text: 'Team meeting tomorrow at 10 AM', sender: 1, timestamp: 'Yesterday', status: 'read' },
        { id: 2, text: 'I\'ll prepare the slides', sender: 2, timestamp: 'Yesterday', status: 'read' },
        { id: 3, text: 'Sounds good', sender: 'me', timestamp: 'Yesterday', status: 'read' },
      ],
    }
  ]);

  const [user, setUser] = useLocalStorage('user', {
    id: 'me',
    name: 'Me',
    avatar: 'https://via.placeholder.com/40',
    about: 'Available',
    phone: '+1 234 5678 90',
  });

  const sendMessage = (text) => {
    if (!activeChat || !text.trim()) return;

    const newMessage = {
      id: Date.now(),
      text,
      sender: 'me',
      timestamp: new Date().toLocaleTimeString([], { hour: '2-digit', minute: '2-digit' }),
      status: 'sent',
    };

    const updatedChats = chats.map(chat => {
      if (chat.id === activeChat) {
        return {
          ...chat,
          messages: [...chat.messages, newMessage],
        };
      }
      return chat;
    });

    setChats(updatedChats);
  };

  const getContactById = (id) => {
    return contacts.find(contact => contact.id === id);
  };

  const getChatById = (id) => {
    return chats.find(chat => chat.id === id);
  };

  const createNewChat = (contactId) => {
    // Check if chat already exists for this contact
    const existingChat = chats.find(chat => chat.contactId === contactId);
    if (existingChat) {
      setActiveChat(existingChat.id);
      return;
    }

    // Create new chat
    const newChat = {
      id: chats.length + 1,
      contactId,
      messages: [],
    };

    setChats([...chats, newChat]);
    setActiveChat(newChat.id);
  };

  const value = {
    activeChat,
    setActiveChat,
    contacts,
    setContacts,
    chats,
    setChats,
    user,
    setUser,
    sendMessage,
    getContactById,
    getChatById,
    createNewChat,
  };

  return <ChatContext.Provider value={value}>{children}</ChatContext.Provider>;
};

// src/hooks/useLocalStorage.js
import { useState, useEffect } from 'react';

function useLocalStorage(key, initialValue) {
  // State to store our value
  const [storedValue, setStoredValue] = useState(() => {
    try {
      // Get from local storage by key
      const item = window.localStorage.getItem(key);
      // Parse stored json or if none return initialValue
      return item ? JSON.parse(item) : initialValue;
    } catch (error) {
      // If error also return initialValue
      console.log(error);
      return initialValue;
    }
  });


  const setValue = (value) => {
    try {
      // Allow value to be a function so we have same API as useState
      const valueToStore =
        value instanceof Function ? value(storedValue) : value;
      // Save state
      setStoredValue(valueToStore);
      // Save to local storage
      window.localStorage.setItem(key, JSON.stringify(valueToStore));
    } catch (error) {
      // A more advanced implementation would handle the error case
      console.log(error);
    }
  };

  return [storedValue, setValue];
}

export default useLocalStorage;

// src/components/Sidebar.js
import React, { useState } from 'react';
import { useChat } from '../contexts/ChatContext';
import ChatList from './ChatList';
import ContactList from './ContactList';
import UserProfile from './UserProfile';

function Sidebar() {
  const { user } = useChat();
  const [activeTab, setActiveTab] = useState('chats');
  const [showProfile, setShowProfile] = useState(false);

  return (
    <div className="sidebar">
      {showProfile ? (
        <UserProfile onClose={() => setShowProfile(false)} />
      ) : (
        <>
          <div className="sidebar__header">
            <div className="sidebar__avatar" onClick={() => setShowProfile(true)}>
              <img src={user.avatar} alt="avatar" />
            </div>
            <div className="sidebar__headerRight">
              <button onClick={() => setActiveTab('contacts')}>
                <i className="fas fa-users"></i>
              </button>
              <button onClick={() => setActiveTab('chats')}>
                <i className="fas fa-comment-alt"></i>
              </button>
              <button>
                <i className="fas fa-ellipsis-v"></i>
              </button>
            </div>
          </div>

          <div className="sidebar__search">
            <div className="sidebar__searchContainer">
              <i className="fas fa-search"></i>
              <input placeholder="Search or start new chat" type="text" />
            </div>
          </div>

          {activeTab === 'chats' ? <ChatList /> : <ContactList />}
        </>
      )}
    </div>
  );
}

export default Sidebar;

// src/components/ChatList.js
import React from 'react';
import { useChat } from '../contexts/ChatContext';

function ChatList() {
  const { chats, contacts, activeChat, setActiveChat, getContactById } = useChat();

  const getLastMessage = (chatId) => {
    const chat = chats.find(c => c.id === chatId);
    if (!chat || chat.messages.length === 0) return null;
    return chat.messages[chat.messages.length - 1];
  };

  const formatTime = (timestamp) => {
    if (!timestamp) return '';
    if (timestamp.includes('Yesterday') || timestamp.includes('days ago')) {
      return timestamp;
    }
    return timestamp;
  };

  return (
    <div className="chatList">
      {chats.map(chat => {
        const contact = getContactById(chat.contactId);
        const lastMessage = getLastMessage(chat.id);
        
        return (
          <div
            key={chat.id}
            className={`chatList__chat ${activeChat === chat.id ? 'active' : ''}`}
            onClick={() => setActiveChat(chat.id)}
          >
            <div className="chatList__avatar">
              <img src={contact?.avatar} alt={contact?.name} />
            </div>
            <div className="chatList__chatInfo">
              <h2>{contact?.name}</h2>
              <p>{lastMessage?.text || 'Start a conversation'}</p>
            </div>
            <div className="chatList__chatMeta">
              <span className="chatList__timestamp">{formatTime(lastMessage?.timestamp)}</span>
              {lastMessage?.sender !== 'me' && lastMessage?.status !== 'read' && (
                <span className="chatList__unread">1</span>
              )}
            </div>
          </div>
        );
      })}
    </div>
  );
}

export default ChatList;

// src/components/ContactList.js
import React from 'react';
import { useChat } from '../contexts/ChatContext';

function ContactList() {
  const { contacts, createNewChat } = useChat();

  return (
    <div className="contactList">
      <h2 className="contactList__title">Contacts</h2>
      {contacts.map(contact => (
        <div
          key={contact.id}
          className="contactList__contact"
          onClick={() => createNewChat(contact.id)}
        >
          <div className="contactList__avatar">
            <img src={contact.avatar} alt={contact.name} />
          </div>
          <div className="contactList__info">
            <h2>{contact.name}</h2>
            <p>{contact.about || contact.lastSeen}</p>
          </div>
        </div>
      ))}
    </div>
  );
}

export default ContactList;

// src/components/Chat.js
import React, { useEffect, useRef } from 'react';
import { useChat } from '../contexts/ChatContext';
import Message from './Message';
import ChatInput from './ChatInput';

function Chat() {
  const { activeChat, chats, contacts, getContactById, getChatById } = useChat();
  const messagesEndRef = useRef(null);

  const currentChat = getChatById(activeChat);
  const contact = currentChat ? getContactById(currentChat.contactId) : null;

  const scrollToBottom = () => {
    messagesEndRef.current?.scrollIntoView({ behavior: 'smooth' });
  };

  useEffect(() => {
    scrollToBottom();
  }, [currentChat?.messages]);

  if (!activeChat) {
    return (
      <div className="chat">
        <div className="chat__empty">
          <div className="chat__emptyContent">
            <i className="fas fa-comments chat__emptyIcon"></i>
            <h1>WhatsApp Web Clone</h1>
            <p>Send and receive messages without keeping your phone online.</p>
            <p>Select a chat from the sidebar to start messaging.</p>
          </div>
        </div>
      </div>
    );
  }

  return (
    <div className="chat">
      <div className="chat__header">
        <div className="chat__headerLeft">
          <div className="chat__avatar">
            <img src={contact?.avatar} alt={contact?.name} />
          </div>
          <div className="chat__headerInfo">
            <h3>{contact?.name}</h3>
            <p>{contact?.lastSeen}</p>
          </div>
        </div>
        <div className="chat__headerRight">
          <button>
            <i className="fas fa-search"></i>
          </button>
          <button>
            <i className="fas fa-paperclip"></i>
          </button>
          <button>
            <i className="fas fa-ellipsis-v"></i>
          </button>
        </div>
      </div>

      <div className="chat__body">
        {currentChat?.messages.map(message => (
          <Message key={message.id} message={message} contact={contact} />
        ))}
        <div ref={messagesEndRef} />
      </div>

      <ChatInput />
    </div>
  );
}

export default Chat;

// src/components/Message.js
import React from 'react';

function Message({ message, contact }) {
  const isUser = message.sender === 'me';
  
  return (
    <div className={`message ${isUser ? 'message__user' : ''}`}>
      <span className="message__name">{isUser ? 'You' : contact?.name}</span>
      <div className="message__bubble">
        <p className="message__text">{message.text}</p>
        <span className="message__timestamp">{message.timestamp}</span>
        {isUser && (
          <span className="message__status">
            {message.status === 'sent' && <i className="fas fa-check"></i>}
            {message.status === 'delivered' && <i className="fas fa-check-double"></i>}
            {message.status === 'read' && <i className="fas fa-check-double message__read"></i>}
          </span>
        )}
      </div>
    </div>
  );
}

export default Message;

// src/components/ChatInput.js
import React, { useState } from 'react';
import { useChat } from '../contexts/ChatContext';

function ChatInput() {
  const [input, setInput] = useState('');
  const { sendMessage } = useChat();

  const handleSubmit = (e) => {
    e.preventDefault();
    sendMessage(input);
    setInput('');
  };

  return (
    <div className="chatInput">
      <button>
        <i className="far fa-smile"></i>
      </button>
      <form onSubmit={handleSubmit}>
        <input
          value={input}
          onChange={(e) => setInput(e.target.value)}
          placeholder="Type a message"
          type="text"
        />
        <button type="submit">
          <i className="fas fa-paper-plane"></i>
        </button>
      </form>
      <button>
        <i className="fas fa-microphone"></i>
      </button>
    </div>
  );
}

export default ChatInput;

// src/components/UserProfile.js
import React, { useState } from 'react';
import { useChat } from '../contexts/ChatContext';

function UserProfile({ onClose }) {
  const { user, setUser } = useChat();
  const [editing, setEditing] = useState(false);
  const [name, setName] = useState(user.name);
  const [about, setAbout] = useState(user.about);

  const handleSave = () => {
    setUser({
      ...user,
      name,
      about,
    });
    setEditing(false);
  };

  return (
    <div className="userProfile">
      <div className="userProfile__header">
        <button onClick={onClose}>
          <i className="fas fa-arrow-left"></i>
        </button>
        <h2>Profile</h2>
      </div>

      <div className="userProfile__info">
        <div className="userProfile__avatar">
          <img src={user.avatar} alt={user.name} />
          <div className="userProfile__avatarOverlay">
            <i className="fas fa-camera"></i>
          </div>
        </div>

        {editing ? (
          <div className="userProfile__form">
            <div className="userProfile__inputGroup">
              <label>Name</label>
              <input
                type="text"
                value={name}
                onChange={(e) => setName(e.target.value)}
              />
            </div>
            <div className="userProfile__inputGroup">
              <label>About</label>
              <input
                type="text"
                value={about}
                onChange={(e) => setAbout(e.target.value)}
              />
            </div>
            <div className="userProfile__buttons">
              <button onClick={() => setEditing(false)}>Cancel</button>
              <button onClick={handleSave}>Save</button>
            </div>
          </div>
        ) : (
          <div className="userProfile__details">
            <div className="userProfile__field">
              <label>Name</label>
              <div className="userProfile__value">
                <p>{user.name}</p>
                <button onClick={() => setEditing(true)}>
                  <i className="fas fa-pencil-alt"></i>
                </button>
              </div>
            </div>

            <div className="userProfile__field">
              <label>About</label>
              <div className="userProfile__value">
                <p>{user.about}</p>
                <button onClick={() => setEditing(true)}>
                  <i className="fas fa-pencil-alt"></i>
                </button>
              </div>
            </div>

            <div className="userProfile__field">
              <label>Phone</label>
              <div className="userProfile__value">
                <p>{user.phone}</p>
              </div>
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

export default UserProfile;

// src/styles.css
* {
  margin: 0;
  padding: 0;
  box-sizing: border-box;
}

body {
  font-family: -apple-system, BlinkMacSystemFont, 'Segoe UI', 'Roboto', 'Oxygen',
    'Ubuntu', 'Cantarell', 'Fira Sans', 'Droid Sans', 'Helvetica Neue',
    sans-serif;
  -webkit-font-smoothing: antialiased;
  -moz-osx-font-smoothing: grayscale;
  background-color: #dadbd3;
    css_code = """
  body {
      height: 100vh;
      /* other styles */
  }
  """

}

.app {
  display: flex;
  background-color: #ededed;
    css_code = """
  body {
      height: 100vh;
      /* other styles */
  }
  """

  width: 100%;
}

.app__body {
  display: flex;
  background-color: #ededed;
    css_code = """
  body {
      height: 90vh;
      width=90vw;
      /* other styles */
  }
  """

  
  margin: auto;
    css_code = """
  .element {
      box-shadow: -1px 4px 20px -6px rgba(0, 0, 0, 0.7);
      /* other styles */
  }
  """

}

/* Sidebar Styles */
.sidebar {
  display: flex;
  flex-direction: column;
  flex: 0.35;
  background-color: #ffffff;
    css_code = """
  .element {
      border-right: 1px solid black;
      /* other styles */
  }
  """
}



.sidebar__header {
  display: flex;
  justify-content: space-between;
    css_code = """
  .element {
      padding: 10px;
      border-bottom: 1px solid #dadbd3;
      /* other styles */
  }
  """

  background-color: #ededed;
}

.sidebar__avatar {
  cursor: pointer;
}

.sidebar__avatar img {
    css_code = """
  .element {
      width: 40px;
      height: 40px;
      /* other styles */
  }
  """

  border-radius: 50%;
}

.sidebar__headerRight {
  display: flex;
  align-items: center;
    css_code = """
  .element {
      min-width: 100px;
      /* other styles */
  }
  """

  justify-content: space-between;
}

.sidebar__headerRight button {
  background: none;
  border: none;
  cursor: pointer;
    css_code = """
  .element {
      font-size: 18px;
      /* other styles */
  }
  """

  color: #54656f;
}

  css_code = """
  .sidebar__search {
    display: flex;
    align-items: center;
    background-color: #f6f6f6;
    height: 50px;
    padding: 10px;
  }

  .sidebar__searchContainer {
    display: flex;
    align-items: center;
    background-color: white;
    width: 100%;
    height: 35px;
    border-radius: 20px;
    padding: 0 10px;
  }

  .sidebar__searchContainer i {
    color: gray;
    padding: 10px;
  }

  .sidebar__searchContainer input {
    border: none;
    outline: none;
    margin-left: 10px;
    width: 100%;
  }
  """


/* Chat List Styles */
.chatList {
  flex: 1;
  background-color: white;
  overflow-y: auto;
}

  css_code = """
  .chatList__chat {
    display: flex;
    align-items: center;
    padding: 10px;
    cursor: pointer;
    border-bottom: 1px solid #f6f6f6;
  }

  .chatList__chat.active {
    background-color: #ebebeb;
  }

  .chatList__chat:hover {
    background-color: #f5f5f5;
  }

  .chatList__avatar {
    margin-right: 15px;
  }

  .chatList__avatar img {
    width: 45px;
    height: 45px;
    border-radius: 50%;
  }
  """


.chatList__chatInfo {
  flex: 1;
}

  css_code = """
  .chatList__chatInfo h2 {
    font-size: 16px;
    margin-bottom: 3px;
  }

  .chatList__chatInfo p {
    font-size: 14px;
    color: gray;
    overflow: hidden;
    text-overflow: ellipsis;
    white-space: nowrap;
    width: 205px;
  }

  .chatList__chatMeta {
    display: flex;
    flex-direction: column;
    align-items: flex-end;
  }

  .chatList__timestamp {
    font-size: 12px;
    color: gray;
    margin-bottom: 5px;
  }

  .chatList__unread {
    background-color: #25d366;
    color: white;
    width: 18px;
    height: 18px;
    border-radius: 50%;
    display: flex;
    justify-content: center;
    align-items: center;
    font-size: 12px;
  }
  """


/* Contact List Styles */
.contactList {
  flex: 1;
  background-color: white;
  overflow-y: auto;
}

css_code = """
.contactList__title {
  padding: 10px;
  font-size: 16px;
  color: #54656f;
  background-color: #f6f6f6;
}

.contactList__contact {
  display: flex;
  align-items: center;
  padding: 10px;
  cursor: pointer;
  border-bottom: 1px solid #f6f6f6;
}

.contactList__contact:hover {
  background-color: #f5f5f5;
}

.contactList__avatar {
  margin-right: 15px;
}

.contactList__avatar img {
  width: 45px;
  height: 45px;
  border-radius: 50%;
}

.contactList__info {
  flex: 1;
}
"""

  css_code = """
  .contactList__info h2 {
    font-size: 16px;
    margin-bottom: 3px;
  }

  .contactList__info p {
    font-size: 14px;
    color: gray;
  }

  /* Chat Styles */
  .chat {
    display: flex;
    flex-direction: column;
    flex: 0.65;
    background-color: #e5ddd5;
    background-image: url("https://web.whatsapp.com/img/bg-chat-tile-dark_a4be512e74dab747b51b76e82c99f5f1.png");
    background-repeat: repeat;
  }

  .chat__header {
    display: flex;
    justify-content: space-between;
    padding: 10px;
    border-bottom: 1px solid #dadbd3;
    background-color: #ededed;
  }

  .chat__headerLeft {
    display: flex;
    align-items: center;
  }
  """


css_code = """
.chat__avatar {
  margin-right: 15px;
}

.chat__avatar img {
  width: 40px;
  height: 40px;
  border-radius: 50%;
}

.chat__headerInfo {
  flex: 1;
}

.chat__headerInfo h3 {
  font-size: 16px;
  font-weight: 500;
  margin-bottom: 3px;
}

.chat__headerInfo p {
  font-size: 13px;
  color: gray;
}

.chat__headerRight {
  display: flex;
  align-items: center;
  min-width: 100px;
  justify-content: space-between;
}

.chat__headerRight button {
  background: none;
  border: none;
  cursor: pointer;
  font-size: 18px;
  color: #54656f;
}
"""

css_code = """
.chat__body {
  flex: 1;
  background-color: transparent;
  overflow-y: auto;
  padding: 20px;
}

.chat__empty {
  display: flex;
  flex: 1;
  justify-content: center;
  align-items: center;
  background-color: #f8f9fa;
}

.chat__emptyContent {
  text-align: center;
  max-width: 500px;
  padding: 20px;
}

.chat__emptyIcon {
  font-size: 80px;
  color: #25d366;
  margin-bottom: 20px;
}

.chat__emptyContent h1 {
  font-size: 32px;
  font-weight: 300;
  color: #525252;
  margin-bottom: 20px;
}

.chat__emptyContent p {
  font-size: 14px;
  color: #777;
  line-height: 20px;
  margin-bottom: 10px;
}
"""

/* Message Styles */
css_code = """
.message {
  position: relative;
  padding: 10px;
  width: fit-content;
  max-width: 60%;
  border-radius: 10px;
  background-color: white;
  margin-bottom: 15px;
}

.message__user {
  margin-left: auto;
  background-color: #dcf8c6;
}

.message__name {
  position: absolute;
  top: -15px;
  font-size: 11px;
  font-weight: 500;
  color: gray;
}

.message__text {
  margin-bottom: 5px;
  word-wrap: break-word;
}
"""


css_code = """
.message__timestamp {
  font-size: 11px;
  color: gray;
  margin-left: 5px;
}

.message__status {
  margin-left: 5px;
  font-size: 11px;
}

.message__read {
  color: #53bdeb;
}

/* Chat Input Styles */
.chatInput {
  display: flex;
  align-items: center;
  padding: 10px;
  background-color: #f0f0f0;
}

.chatInput form {
  flex: 1;
  display: flex;
  margin: 0 10px;
}
"""


css_code = """
.chatInput input {
  flex: 1;
  padding: 10px;
  border: none;
  border-radius: 20px;
  outline: none;
}

.chatInput button {
  background: none;
  border: none;
  cursor: pointer;
  font-size: 18px;
  color: #54656f;
  padding: 0 10px;
}

/* User Profile Styles */
.userProfile {
  flex: 1;
  background-color: #f0f0f0;
  overflow-y: auto;
}

.userProfile__header {
  display: flex;
  align-items: center;
  padding: 20px;
  background-color: #00a884;
  color: white;
}

.userProfile__header button {
  background: none;
  border: none;
  cursor: pointer;
  color: white;
  font-size: 20px;
  margin-right: 20px;
}
"""

css_code="""
.userProfile__header h2 {
  font-size: 19px;
  font-weight: 500;
}

.userProfile__info {
  padding: 20px;
  background-color: white;
}

.userProfile__avatar {
  position: relative;
  width: 200px;
  height: 200px;
  margin: 0 auto 20px;
}

.userProfile__avatar img {
"""