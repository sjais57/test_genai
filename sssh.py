import subprocess
import time

SERVERS_FILE = "/path/to/servers.txt"
USERNAME = "your_ssh_user"
PASSWORD = "your_ssh_password"  # use ssh key instead for better security
SSH_TIMEOUT = 10

def check_ssh(server, username, password):
    cmd = [
        "sshpass", "-p", password,
        "ssh", "-o", "StrictHostKeyChecking=no",
        "-o", f"ConnectTimeout={SSH_TIMEOUT}",
        f"{username}@{server}", "echo success"
    ]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=SSH_TIMEOUT+5)
        output = result.stdout.decode()
        error = result.stderr.decode()
        if "success" in output:
            return True, "SSH OK"
        elif "Permission denied" in error:
            return False, "Access Denied"
        elif "Connection timed out" in error or "No route" in error:
            return False, "Timeout or Network Error"
        else:
            return False, error.strip()
    except Exception as e:
        return False, str(e)

def main():
    with open(SERVERS_FILE, "r") as f:
        servers = [line.strip() for line in f if line.strip()]
    
    print(f"Checking SSH connectivity to {len(servers)} servers...\n")
    for server in servers:
        success, message = check_ssh(server, USERNAME, PASSWORD)
        status = "✅" if success else "❌"
        print(f"{status} {server}: {message}")
        time.sleep(0.5)

if __name__ == "__main__":
    main()


===============================================

import subprocess
import time

SERVERS_FILE = "/path/to/servers.txt"
USERNAME = "your_ssh_user"
PASSWORD = "your_ssh_password"  # used only if prompted
SSH_TIMEOUT = 10

def ssh_try_key(server):
    """Try key-based login."""
    cmd = [
        "ssh", "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", f"ConnectTimeout={SSH_TIMEOUT}",
        f"{USERNAME}@{server}", "echo success"
    ]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=SSH_TIMEOUT+5)
        output = result.stdout.decode().strip()
        error = result.stderr.decode().strip()

        if output == "success":
            return True, "Key-based SSH OK"
        elif "Permission denied" in error:
            return False, "Needs password"
        else:
            return False, error
    except Exception as e:
        return False, str(e)

def ssh_with_password(server, password):
    """Try password-based login."""
    cmd = [
        "sshpass", "-p", password,
        "ssh", "-o", "StrictHostKeyChecking=no",
        "-o", f"ConnectTimeout={SSH_TIMEOUT}",
        f"{USERNAME}@{server}", "echo success"
    ]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=SSH_TIMEOUT+5)
        output = result.stdout.decode().strip()
        error = result.stderr.decode().strip()

        if output == "success":
            return True, "Password-based SSH OK"
        elif "Permission denied" in error:
            return False, "Access Denied"
        else:
            return False, error
    except Exception as e:
        return False, str(e)

def main():
    with open(SERVERS_FILE, "r") as f:
        servers = [line.strip() for line in f if line.strip()]
    
    print(f"Checking SSH connectivity to {len(servers)} servers...\n")

    for server in servers:
        success, message = ssh_try_key(server)
        if not success and message == "Needs password":
            # Try with password only once
            success, message = ssh_with_password(server, PASSWORD)
        
        status = "✅" if success else "❌"
        print(f"{status} {server}: {message}")
        time.sleep(0.5)

if __name__ == "__main__":
    main()


=================================================================

import subprocess
import time

SERVER_FILE = "/path/to/server_file.txt"
USERNAME = "your_ssh_user"
PASSWORD = "your_ssh_password"
SSH_TIMEOUT = 10

def parse_grouped_servers(file_path):
    grouped_servers = {}
    with open(file_path, "r") as f:
        for line in f:
            if '=' in line:
                group, nodes = line.strip().split("=", 1)
                node_list = [n.strip() for n in nodes.split(",") if n.strip()]
                grouped_servers[group] = node_list
    return grouped_servers

def ssh_try_key(server):
    cmd = [
        "ssh", "-o", "BatchMode=yes",
        "-o", "StrictHostKeyChecking=no",
        "-o", f"ConnectTimeout={SSH_TIMEOUT}",
        f"{USERNAME}@{server}", "echo success"
    ]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=SSH_TIMEOUT+5)
        output = result.stdout.decode().strip()
        error = result.stderr.decode().strip()
        if output == "success":
            return True, "Key-based SSH OK"
        elif "Permission denied" in error:
            return False, "Needs password"
        else:
            return False, error
    except Exception as e:
        return False, str(e)

def ssh_with_password(server, password):
    cmd = [
        "sshpass", "-p", password,
        "ssh", "-o", "StrictHostKeyChecking=no",
        "-o", f"ConnectTimeout={SSH_TIMEOUT}",
        f"{USERNAME}@{server}", "echo success"
    ]
    try:
        result = subprocess.run(cmd, stdout=subprocess.PIPE, stderr=subprocess.PIPE, timeout=SSH_TIMEOUT+5)
        output = result.stdout.decode().strip()
        error = result.stderr.decode().strip()
        if output == "success":
            return True, "Password-based SSH OK"
        elif "Permission denied" in error:
            return False, "Access Denied"
        else:
            return False, error
    except Exception as e:
        return False, str(e)

def main():
    grouped_servers = parse_grouped_servers(SERVER_FILE)

    for group, servers in grouped_servers.items():
        print(f"\n▶ Checking group: {group} ({len(servers)} nodes)")
        for server in servers:
            success, message = ssh_try_key(server)
            if not success and message == "Needs password":
                success, message = ssh_with_password(server, PASSWORD)
            status = "✅" if success else "❌"
            print(f"{status} {server}: {message}")
            time.sleep(0.5)

if __name__ == "__main__":
    main()

