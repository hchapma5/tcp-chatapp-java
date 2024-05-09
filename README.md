# Network Messaging System

## Overview

This Network Messaging System is a secure communication platform that uses TCP sockets for network communication, employs AES-GCM for message encryption, and ensures secure user storage with SHA-256 plus salt hashing for passwords. The system facilitates a Diffie-Hellman key exchange to securely establish session keys between clients and the server.

## Features

- **Secure User Registration and Login**: Uses SHA-256 with salt hashing to securely store user passwords.
- **Unique Usernames**: Each user must register with a unique username that is used for login and messaging.
- **End-to-End Encryption**: Utilizes AES-GCM encryption to ensure that messages are securely transmitted over the network. Keys are established through a Diffie-Hellman key exchange at the start of each session.
- **Message Sending/Receiving**: After successful login, users can send and receive messages from other registered users.
- **Secure Disconnection**: Users can disconnect from the server securely, ensuring that all session data is properly cleaned up.

## Getting started

- To start a server, run the following: `./startServer <port>`
- To start a client, run the following: `./startClient <hostname> <port>`
- Example:

```bash
./startServer.sh 1234
```

```bash
./startClient.sh localhost 1234
```
