#!/bin/bash

# Check if hostname and port number are provided
if [ "$#" -ne 2 ]; then
  echo "Usage: $0 <hostname> <port>"
  exit 1
fi

# Compile the Java files
javac Client.java
if [ $? -ne 0 ]; then
  echo "Error: Failed to compile the Java files."
  exit 1
fi

# Start the client
java Client "$1" "$2"
if [ $? -ne 0 ]; then
  echo "Error: Failed to connect to the server at $1 on port $2."
  exit 1
fi
