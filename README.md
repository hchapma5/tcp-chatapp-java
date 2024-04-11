# Network Messaging System

## Overview
This project implements a network messaging system enabling users to leave messages for others. It leverages TCP sockets to facilitate a server capable of storing and retrieving messages, alongside a client for user interaction.

## Features
- **User Login:** Secure login system using unique usernames without spaces.
- **Message Composition:** Users can compose and send messages to other users.
- **Message Retrieval:** Users can read messages sent to them, which are then removed from the server.
- **Connection Management:** Supports user exit commands and connection termination on protocol errors.

## Protocol
The system uses a text-based protocol where each command and response comprises ASCII strings terminated by a line feed (ASCII code 10). The protocol is case sensitive and supports the following commands:

- **LOGIN `<username>`:** Initiates a session for the user. The server replies with the number of stored messages.
- **COMPOSE `<username>`:** Followed by a `<message>`, it sends a message to the specified user. Responses include `MESSAGE SENT` or `MESSAGE FAILED`.
- **READ:** Retrieves the earliest unread message for the user. Possible responses are the message details or `READ ERROR`.
- **EXIT:** Ends the session and disconnects from the server.

## Error Handling
Any deviation from the above commands results in an immediate connection drop by the receiving party.

## Examples

### Example 1: Error Handling
- **Client:** `LOGIN my username contains the space character`
- **Server drops the connection.**

### Example 2: Successful Messaging
- **Client:** `LOGIN bob`
- **Server:** `0`
- **Client:** `COMPOSE alice`
- **Client:** `Hi Alice!`
- **Server:** `MESSAGE SENT`
- ...

### Example 3: Message Storage Limit
- **Client:** `LOGIN alice`
- **Server:** `1024`
- **Client:** `COMPOSE alice`
- **Server:** `MESSAGE FAILED`
- ...

### Example 4: Protocol Error
- **Client:** `LOGIN carol`
- **Server:** `1`
- **Client:** `read`
- **Server drops the connection.**
