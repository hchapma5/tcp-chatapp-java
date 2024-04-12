#!/bin/bash

# Check if a port number is provided
if [ "$#" -ne 1 ]; then
  echo "Usage: $0 <port>"
  exit 1
fi

# Compile the Java files
javac Server.java ClientHandler.java
if [ $? -ne 0 ]; then
  echo "Error: Failed to compile the Java files."
  exit 1
fi

# Start the server
java Server "$1"
if [ $? -ne 0 ]; then
  echo "Error: Failed to start the server on port $1. This port may be already in use."
  exit 1
fi
