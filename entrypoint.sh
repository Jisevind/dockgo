#!/bin/sh

# Get the Group ID of the docker socket
SOCKET_GID=$(stat -c '%g' /var/run/docker.sock)

if [ -z "$SOCKET_GID" ]; then
    echo "Could not detemine GID of docker socket."
else
    # Check if a group with this GID already exists
    if ! getent group $SOCKET_GID > /dev/null 2>&1; then
        # Create a group with this GID
        addgroup -g $SOCKET_GID docker_sock_group
    fi
    
    # Get the group name (it might be 'docker' or the one we just created)
    GROUP_NAME=$(getent group $SOCKET_GID | cut -d: -f1)
    
    # Add dockgo user to this group
    addgroup dockgo $GROUP_NAME
fi

# Drop privileges and execute the command
exec su-exec dockgo "$@"
