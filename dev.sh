#!/bin/bash

# Simple development script for i6.shark that watches for changes and restarts the server
# This is a fallback for environments where Air can't be installed

echo "Starting i6.shark in development mode..."
echo "Watching for changes in src/ directory"

# Function to build and run the server
run_server() {
  echo "Building and starting server..."
  go run src/main.go
}

# Run the server initially
run_server &
PID=$!

# Watch for changes and restart server
while true; do
  # Use find to check for file modifications
  find src -name "*.go" -type f -mtime -1s 2>/dev/null
  
  if [ $? -eq 0 ]; then
    echo "Change detected, restarting server..."
    # Kill the previous server process
    kill $PID 2>/dev/null
    wait $PID 2>/dev/null
    
    # Run the server again
    run_server &
    PID=$!
  fi
  
  # Sleep briefly to prevent CPU overuse
  sleep 1
done 