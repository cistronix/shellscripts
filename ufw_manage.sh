#!/bin/bash

# Global variable for traffic type
TRAFFIC_TYPE="all"

# Function to display the menu
show_menu() {
    echo "1) Enable UFW"
    echo "2) Disable UFW"
    echo "3) Show UFW Status"
    echo "4) Allow Access"
    echo "5) Deny Access"
    echo "6) Delete Rule"
    echo "7) Reset UFW"
    echo "8) Exit"
    echo -n "Please enter your choice: "
}

# Function to set traffic type
set_traffic_type() {
    echo -n "Enter traffic type (tcp, udp, or all): "
    read traffic_type
    case $traffic_type in
        tcp|udp|all)
            TRAFFIC_TYPE=$traffic_type
            ;;
        *)
            echo "Invalid traffic type. Defaulting to 'all'."
            TRAFFIC_TYPE="all"
            ;;
    esac
}

# Function to allow access
allow_access() {
    local ip port
    echo -n "Enter the IP address/subnet or type 'all' to allow for all IPs: "
    read ip
    echo -n "Enter the port number: "
    read port
    set_traffic_type
    if [[ "$ip" == "all" ]]; then
        sudo ufw allow "$port/$TRAFFIC_TYPE"
    else
        sudo ufw allow from "$ip" to any port "$port" proto "$TRAFFIC_TYPE"
    fi
}

# Function to deny access
deny_access() {
    local ip port
    echo -n "Enter the IP address/subnet or type 'all' to deny for all IPs: "
    read ip
    echo -n "Enter the port number: "
    read port
    set_traffic_type
    if [[ "$ip" == "all" ]]; then
        sudo ufw deny "$port/$TRAFFIC_TYPE"
    else
        sudo ufw deny from "$ip" to any port "$port" proto "$TRAFFIC_TYPE"
    fi
}

# Function to delete a rule
delete_rule() {
    local rule_number
    sudo ufw status numbered
    echo -n "Enter the number of the rule you want to delete: "
    read rule_number
    sudo ufw delete "$rule_number"
}

# Main loop
while true
do
    show_menu
    read choice
    case $choice in
        1) sudo ufw enable
           ;;
        2) sudo ufw disable
           ;;
        3) sudo ufw status verbose
           ;;
        4) allow_access
           ;;
        5) deny_access
           ;;
        6) delete_rule
           ;;
        7) sudo ufw reset
           ;;
        8) echo "Exiting..."
           exit 0
           ;;
        *) echo "Invalid option, please try again."
           ;;
    esac
    echo "Press any key to continue..."
    read pause
    clear
done
