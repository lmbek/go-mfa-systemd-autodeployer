Note: This project should be used with caution

# Service Deployment Automation

This Go application automates the deployment of a service to a remote server via SSH. The process includes building a production binary, generating a TOTP (Time-based One-Time Password) for secure authentication, transferring the binary to the remote server, and managing the service using `systemd`.

## Features

- **Build Local Binary**: Compiles a production-ready binary using `go build`.
- **TOTP Generation**: Generates a TOTP using a secret for secure authentication during SSH connection.
- **SSH Connectivity**: Connects to a remote server via SSH using either a private key or password.
- **Service Management**: Checks if the service is running, stops it if necessary, copies the binary to the remote server, ensures the service is configured as a systemd service, and starts the service.
- **Systemd Setup**: Ensures the service is enabled to start automatically on system boot.

## Requirements

- Go 1.18+ (to build and run the application)
- Access to a remote server with SSH enabled
- A valid Google TOTP secret (Base32 encoded)
- Configuration files containing secrets (paths, credentials, etc.)

## How to run
First set up the configuration files inside a new secrets directory. (see configuration files below this section)
then run the script to deploy to a server that needs to have same sshd_config as me (ask me for details)

    go run .

## Configuration Files

The following files must be configured for the deployment to work correctly:

- `known_hosts_path.txt`: Contains the path to the SSH known hosts file (typically `~/.ssh/known_hosts`).
- `server_ip.txt`: The IP address of the remote server.
- `server_user.txt`: The SSH username to use for the connection.
- `server_password.txt` (optional): The password for SSH login if not using a private key.
- `private_key_path.txt` (optional): The path to the private SSH key for authentication.
- `private_key_passphrase.txt` (optional): The passphrase for the SSH private key, if applicable.
- `server_port.txt`: The SSH port for the remote server (usually `22`).
- `service_name.txt`: The name of the service to manage.
- `service_path.txt`: The path where the service binary should be located on the server.
- `google_secret.txt`: The Google TOTP secret to generate authentication codes.
- `local_binary_path.txt`: The path to the locally built service binary.

## How It Works

1. **Build Local Binary**: The tool will first compile the service into a binary using `go build`. This binary is then transferred to the remote server for execution.

2. **Generate TOTP**: The application will generate a Time-based One-Time Password (TOTP) using the secret stored in `google_secret.txt` for secure authentication.

3. **SSH Connection**: The script connects to the remote server using SSH. It can use either a password or private key for authentication, depending on your setup.

4. **Service Management**:
   - The tool checks whether the service is running on the remote server.
   - If the service is running, it stops the service to allow for updating the binary.
   - The updated binary is copied to the remote server, replacing the old one.
   - The tool ensures that the service is correctly configured as a `systemd` service.
   - Finally, the tool starts the service and enables it to run automatically on system boot.

5. **Systemd Setup**: The script configures the service to be managed by `systemd`, ensuring it can be automatically started on boot and restarted in case of failure.

## License

This project is licensed under the MIT License - see the [LICENSE](LICENSE) file for details.
