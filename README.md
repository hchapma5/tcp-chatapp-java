# Network Messaging System

## UPDATE:

- To compile : `javac -d bin -sourcepath src src/client/*.java src/server/*.java src/util/*.java`
- To run : `java -cp bin src/folder/classFile`

## Overview

This project implements a network messaging system enabling users to leave messages for others. It leverages TCP sockets to facilitate a server capable of storing and retrieving messages, alongside a client for user interaction.

## Features

- **User Login:** Secure login system using unique usernames without spaces.
- **Message Composition:** Users can compose and send messages to other users.
- **Message Retrieval:** Users can read messages sent to them, which are then removed from the server.
- **Connection Management:** Supports user exit commands and connection termination on protocol errors.

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
