document.addEventListener('DOMContentLoaded', function() {
    // DOM Elements
    const chatMessages = document.getElementById('chatMessages');
    const messageInput = document.getElementById('messageInput');
    const sendBtn = document.getElementById('sendBtn');
    const voiceBtn = document.getElementById('voiceBtn');
    const chatItems = document.querySelectorAll('.chat-item');
    
    // Toggle active chat
    chatItems.forEach(item => {
        item.addEventListener('click', function() {
            // Remove active class from all chat items
            chatItems.forEach(chat => chat.classList.remove('active'));
            
            // Add active class to clicked item
            this.classList.add('active');
            
            // Get chat name from clicked item
            const chatName = this.querySelector('h4').textContent;
            
            // Update chat header
            document.querySelector('.chat-info h4').textContent = chatName;
            
            // Remove unread count
            const unreadCount = this.querySelector('.unread-count');
            if (unreadCount) {
                unreadCount.remove();
            }
        });
    });
    
    // Handle sending messages
    function sendMessage() {
        const message = messageInput.value.trim();
        
        if (message) {
            // Create message element
            const messageElement = document.createElement('div');
            messageElement.className = 'message sent';
            
            // Get current time
            const now = new Date();
            const hours = now.getHours();
            const minutes = now.getMinutes();
            const formattedTime = `${hours}:${minutes < 10 ? '0' + minutes : minutes}`;
            
            // Add message content
            messageElement.innerHTML = `
                <div class="message-content">
                    <p>${message}</p>
                    <span class="message-time">${formattedTime} <i class="fas fa-check-double"></i></span>
                </div>
            `;
            
            // Add message to chat
            chatMessages.appendChild(messageElement);
            
            // Clear input
            messageInput.value = '';
            
            // Toggle send button color
            sendBtn.classList.remove('active');
            
            // Scroll to bottom
            chatMessages.scrollTop = chatMessages.scrollHeight;
            
            // Simulate response after delay (demo only)
            setTimeout(simulateResponse, 1000);
        }
    }
    
    // Simulate receiving a response
    function simulateResponse() {
        const responses = [
            "Ok, I'll check it out.",
            "Sure, that works for me!",
            "Can we talk about this later?",
            "Thanks for letting me know!",
            "I'll be there in 10 minutes."
        ];
        
        const randomResponse = responses[Math.floor(Math.random() * responses.length)];
        
        // Create message element
        const messageElement = document.createElement('div');
        messageElement.className = 'message received';
        
        // Get current time
        const now = new Date();
        const hours = now.getHours();
        const minutes = now.getMinutes();
        const formattedTime = `${hours}:${minutes < 10 ? '0' + minutes : minutes}`;
        
        // Add message content
        messageElement.innerHTML = `
            <div class="message-content">
                <p>${randomResponse}</p>
                <span class="message-time">${formattedTime}</span>
            </div>
        `;
        
        // Add message to chat
        chatMessages.appendChild(messageElement);
        
        // Update last message in chat list
        document.querySelector('.chat-item.active .chat-message p').textContent = randomResponse;
        document.querySelector('.chat-item.active .time').textContent = 'Just now';
        
        // Scroll to bottom
        chatMessages.scrollTop = chatMessages.scrollHeight;
    }
    
    // Event listener for send button
    sendBtn.addEventListener('click', sendMessage);
    
    // Event listener for Enter key
    messageInput.addEventListener('keypress', function(e) {
        if (e.key === 'Enter') {
            sendMessage();
        }
    });
    
    // Toggle send button when input has text
    messageInput.addEventListener('input', function() {
        if (this.value.trim()) {
            sendBtn.classList.add('active');
            voiceBtn.style.display = 'none';
            sendBtn.style.display = 'block';
        } else {
            sendBtn.classList.remove('active');
            voiceBtn.style.display = 'block';
            sendBtn.style.display = 'none';
        }
    });
    
    // Toggle voice/send button initially
    sendBtn.style.display = 'none';
    
    // Scroll to bottom of chat initially
    chatMessages.scrollTop = chatMessages.scrollHeight;
});