#!/bin/bash

SERVER_URL="YOUR_SERVER_ADDRESS"

interactive_mode() {
    while true; do
        read -p "Enter AS number, IP address, or domain (q to quit): " input
        if [[ $input == "q" ]]; then
            break
        fi
        send_request "$input"
    done
}

send_request() {
    local identifier=$1
    response=$(curl -s -X POST -d "identifier=$identifier" "$SERVER_URL")
    echo -e "$response\n"
}

if [[ $1 == "-i" ]]; then
    interactive_mode
else
    if [[ -z $1 ]]; then
        echo "AS number, IP address, or domain is required."
        exit 1
    fi
    send_request "$1"
fi
