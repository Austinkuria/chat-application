# Chat Application

## Overview
This is a real-time chat application built with Flask, Socket.IO, and JavaScript. It allows users to register, log in, and participate in a group chat room. The application features a modern, responsive UI and supports real-time message updates.

## Features
- User registration and authentication
- Real-time group chat using WebSockets (Socket.IO)
- Responsive design for desktop and mobile
- User-friendly interface with message highlighting and timestamps
- Error handling and connection status feedback

## Codebase Structure
- `app.py`: Main Flask application, routes, and Socket.IO event handling
- `static/style.css`: CSS for styling the chat interface and forms
- `templates/`: HTML templates for the chat room, login, and registration pages
- `instance/`: Contains the SQLite database file (`chatapp.db`)
- `requirements.txt`: Python dependencies

## How It Works
- Users register and log in to access the chat room.
- Messages are sent and received in real time using Socket.IO.
- The chat interface updates instantly for all connected users.
- The application uses Flask sessions to manage user authentication.

## Getting Started
1. Install dependencies: `pip install -r requirements.txt`
2. Run the application: `python app.py`
3. Open your browser and go to `http://localhost:5000`

---
Feel free to explore the codebase and customize the application to your needs!
