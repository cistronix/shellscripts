#!/bin/bash

# Get the list of tmux sessions
sessions=$(tmux list-sessions -F "#{session_name}" 2>/dev/null)

# Display the list of sessions or prompt to create a new one if none exists
if [ -z "$sessions" ]; then
  echo "No tmux sessions found."
  read -p "Enter the name of the new session to create: " new_session
  tmux new-session -s "$new_session"
  exit 0
fi

# Display the list of sessions
echo "Available tmux sessions:"
i=1
for session in $sessions; do
  echo "$i) $session"
  i=$((i + 1))
done
echo "$i) Create a new session"

# Prompt the user to choose a session or create a new one
read -p "Enter the number of the session you want to attach to or create: " choice

# Validate the user's choice
if ! [[ "$choice" =~ ^[0-9]+$ ]] || [ "$choice" -lt 1 ] || [ "$choice" -gt "$i" ]; then
  echo "Invalid choice."
  exit 1
fi

# Attach to the chosen session or create a new one
if [ "$choice" -eq "$i" ]; then
  read -p "Enter the name of the new session to create: " new_session
  tmux new-session -s "$new_session"
else
  chosen_session=$(echo "$sessions" | sed -n "${choice}p")
  tmux attach-session -t "$chosen_session"
fi
