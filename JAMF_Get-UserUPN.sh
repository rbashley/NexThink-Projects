#!/bin/bash
#
# Company: Wayfair
# Author: Randall Ashley (rashley@wayfair.com)
# Date: 10/01/2024
# Version: 1.0
#
# Synopsis:
# This script checks the reachability of the Jamf server and retrieves an access token for API interaction. 
# It fetches the computer inventory by the currently logged-in user and extracts the most recent email 
# address associated with the user. The script updates the corresponding plist file with the extracted email
# and invalidates the access token after the operation is complete.
#

# Source the Nexthink output script
. "${NEXTHINK}/bash/nxt_ra_script_output.sh"

# Set URL, client ID, and client secret
# NXT_PARAMETERS_BEGIN
url=$1
client_id=$2
client_secret=$3
# NXT_PARAMETERS_END

# Configuration files and plist paths
configFile="/Library/Application Support/Nexthink/config.json"
svc="/Library/LaunchDaemons/com.nexthink.collector.driver.nxtsvc.plist"
cord="/Library/LaunchDaemons/com.nexthink.collector.nxtcoordinator.plist"
operation="Add :DisplayName string"

# Function to get the currently logged-in user
getCurrentUser() {
  # Determine the currently logged-in user
  current_user=$(stat -f "%Su" /dev/console)
  echo "Currently logged-in user: $current_user"
}

# Function to check if the Jamf server is reachable
checkServerReachability() {
  echo "Checking if the Jamf server is reachable..."
  if curl --silent --head --fail "$url" > /dev/null; then
    echo "Jamf server is reachable."
  else
    echo "Error: Jamf server is not reachable. Please check the URL and network connectivity."
    exit 1
  fi
}

# Function to get an access token
getAccessToken() {
  echo "Attempting to retrieve access token..."
  response=$(curl --silent --location --request POST "${url}/oauth/token" \
 	 	--header "Content-Type: application/x-www-form-urlencoded" \
 	 	--data-urlencode "client_id=${client_id}" \
 	 	--data-urlencode "grant_type=client_credentials" \
 	 	--data-urlencode "client_secret=${client_secret}")
 	
 	access_token=$(echo "$response" | plutil -extract access_token raw -)
 	token_expires_in=$(echo "$response" | plutil -extract expires_in raw -)
 	
 	# Check if token retrieval was successful
 	if [[ -z "$access_token" ]]; then
 	  echo "Error: Failed to retrieve access token. Please check the client ID, client secret, and server URL."
 	  exit 1
 	fi
 	
 	token_expiration_epoch=$(($(date +%s) + $token_expires_in - 1))
 	echo "Access token retrieved successfully."
}

# Function to check token expiration
checkTokenExpiration() {
  current_epoch=$(date +%s)
  if [[ $token_expiration_epoch -ge $current_epoch ]]
  then
    echo "Token is valid until the following epoch time: $token_expiration_epoch"
  else
    echo "No valid token available, attempting to retrieve a new token..."
    getAccessToken
  fi
}

# Function to invalidate the token
invalidateToken() {
  responseCode=$(curl -w "%{http_code}" -H "Authorization: Bearer ${access_token}" "$url/v1/auth/invalidate-token" -X POST -s -o /dev/null)
  if [[ $responseCode == 204 ]]
  then
    echo "Token successfully invalidated."
    access_token=""
    token_expiration_epoch="0"
  elif [[ $responseCode == 401 ]]
  then
    echo "Token already invalid."
  else
    echo "An unknown error occurred while invalidating the token."
  fi
}

# Function to get computer inventory by user and extract the most recent email
getComputerInventoryEmailsByUser() {
  local user_name=$1
  # echo "Fetching computer inventory for user: $user_name..."
  response=$(curl --silent -X 'GET' \
    "${url}/v1/computers-inventory?section=USER_AND_LOCATION&page=0&page-size=100&sort=general.name%3Aasc&filter=userAndLocation.username%3D%3D%22${user_name}%22" \
    -H 'accept: application/json' \
    -H "Authorization: Bearer ${access_token}")
  
  # Check if user data was successfully retrieved
  if echo "$response" | grep -q "totalCount"; then
    # echo "User data retrieved successfully."
    # Extract the most recent email using grep instead of jq
    recent_email=$(echo "$response" | grep '"email"' | head -n 1 | sed 's/.*"email" *: *"\([^"]*\)".*/\1/')
    echo "$recent_email"
  else
    # echo "Error: Failed to retrieve user data. Please check the username or server connection."
    exit 1
  fi
}

# Main execution starts here

# Get the currently logged-in user
getCurrentUser

# Set plist file path based on the current user
plist_file="/Users/${current_user}/Library/Preferences/com.jamf.connect.state.plist"

# Check if the Jamf server is reachable
checkServerReachability

# Check if the token is valid and retrieve a new one if necessary
checkTokenExpiration

# Call the getComputerInventoryEmailsByUser function and get the most recent email
most_recent_email=$(getComputerInventoryEmailsByUser "$current_user")

# Set the email in the plist file using PlistBuddy
/usr/libexec/PlistBuddy -c "${operation} $most_recent_email" "$plist_file" 2>&1

# Invalidate the token after use
invalidateToken