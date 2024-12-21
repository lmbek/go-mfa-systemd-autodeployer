package main

import (
	"bytes"
	"context"
	"crypto/hmac"
	"crypto/sha1"
	_ "embed"
	"encoding/base32"
	"encoding/binary"
	"fmt"
	"golang.org/x/crypto/ssh"
	"io"
	"log"
	"os"
	"os/exec"
	"strings"
	"time"
)

// Embedded secrets

//go:embed secrets/known_hosts_path.txt
var knownHostsPath string

//go:embed secrets/server_ip.txt
var serverIp string

//go:embed secrets/server_user.txt
var serverUser string

//go:embed secrets/server_password.txt
var serverPassword string

//go:embed secrets/private_key_path.txt
var privateKeyPath string

//go:embed secrets/private_key_passphrase.txt
var privateKeyPassphrase string

//go:embed secrets/server_port.txt
var serverPort string

//go:embed secrets/service_name.txt
var serviceName string

//go:embed secrets/service_path.txt
var servicePath string

//go:embed secrets/google_secret.txt
var googleSecret string // Base32 encoded TOTP secret

//go:embed secrets/local_binary_path.txt
var localBinaryPath string

func main() {
	if err := DeployService(); err != nil {
		log.Fatalf("Deployment failed: %v", err)
	}
}

func DeployService() error {
	// Building production binary
	log.Println("Building the binary...")
	err := buildLocalBinary()
	if err != nil {
		return fmt.Errorf("failed to build binary: %w", err)
	}
	log.Println("Binary built successfully!")

	// Generate TOTP code
	totp, err := generateTOTP(googleSecret)
	if err != nil {
		return fmt.Errorf("failed to generate TOTP: %w", err)
	}
	log.Printf("Generated TOTP: %s", totp)

	// Connect to SSH server
	client, err := connectToSSH(totp)
	if err != nil {
		return fmt.Errorf("failed to connect to SSH server: %w", err)
	}
	defer client.Close()

	// Step 1: Check if the service is running and stop it if necessary
	output, err := executeCommand(client, fmt.Sprintf("sudo -S service %s status", serviceName), 5*time.Second)
	if err != nil {
		fmt.Println(output)
		return fmt.Errorf("failed to check service status: %w", err)
	}
	if strings.Contains(output, "running") {
		log.Println("Service is running. Stopping it...")
		log.Println("Stopping service (no matter if its already started or not)")
		_, err = executeCommand(client, fmt.Sprintf("sudo -S service %s stop", serviceName), 5*time.Second)
		if err != nil {
			return fmt.Errorf("failed to stop service: %w", err)
		}
	}

	// Step 2: Copy the binary to the remote server
	log.Println("Copying the binary to the server...")
	err = copyBinaryToServer(client)
	if err != nil {
		return fmt.Errorf("failed to copy binary to server: %w", err)
	}

	// Step 3: Check for systemd service and create it if it doesn't exist
	log.Println("Checking for systemd service...")
	err = checkAndCreateSystemdService(client)
	if err != nil {
		return fmt.Errorf("failed to check or create systemd service: %w", err)
	}

	// Step 4: Start the service
	log.Println("Starting the service...")
	_, err = executeCommand(client, fmt.Sprintf("sudo -S systemctl start %s", serviceName), 5*time.Second)
	if err != nil {
		return fmt.Errorf("failed to start service: %w", err)
	}

	// Step 5: Check the service status
	log.Println("Checking the service status...")
	output, err = executeCommand(client, fmt.Sprintf("sudo -S systemctl status %s", serviceName), 5*time.Second)
	if err != nil {
		fmt.Println(output)
		return fmt.Errorf("failed to check service status: %w", err)
	}
	if !strings.Contains(output, "active (running)") {
		return fmt.Errorf("service did not start successfully: %s", output)
	}

	// Step 6: Enable the service to run on startup
	log.Println("Enabling the service to run on startup...")
	_, err = executeCommand(client, fmt.Sprintf("sudo -S systemctl enable %s", serviceName), 5*time.Second)
	if err != nil {
		return fmt.Errorf("failed to enable service: %w", err)
	}

	log.Println("Deployment completed successfully!")
	return nil
}

func buildLocalBinary() error {
	cmd := exec.Command("go", "build", "-tags", "production", "-o", serviceName, ".")
	cmd.Env = append(os.Environ(),
		"CGO_ENABLED=0",
		"GOOS=linux",
		"GOARCH=amd64",
	)
	cmd.Dir = localBinaryPath // Set the working directory for the go build command

	var out, errOut bytes.Buffer
	cmd.Stdout = &out
	cmd.Stderr = &errOut
	err := cmd.Run()
	if err != nil {
		log.Printf("Build error: %s", errOut.String())
		return fmt.Errorf("failed to build binary: %w", err)
	}
	log.Printf("Build output: %s", out.String())
	return nil
}

func copyBinaryToServer(client *ssh.Client) error {
	// Open the local binary file
	localFilePath := localBinaryPath + serviceName
	binaryFile, err := os.Open(localFilePath)
	if err != nil {
		return fmt.Errorf("failed to open binary file: %w", err)
	}
	defer binaryFile.Close()

	// Get file info
	binaryInfo, err := binaryFile.Stat()
	if err != nil {
		return fmt.Errorf("failed to stat binary file: %w", err)
	}

	// Create an SSH session
	session, err := client.NewSession()
	if err != nil {
		return fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer session.Close()

	// SCP command to handle file transfer
	scpCmd := fmt.Sprintf("scp -t %s", servicePath)
	//scpCmd := fmt.Sprintf("scp -P %s -i %s %s %s@%s:%s", serverPort, privateKeyPath, serviceName, serverUser, serverIp, remoteBinaryPath)

	// Set up stdin pipe for the session
	stdin, err := session.StdinPipe()
	if err != nil {
		return fmt.Errorf("failed to create stdin pipe: %w", err)
	}
	defer stdin.Close()

	session.Stderr = os.Stderr

	// Channel to notify when the file transfer is complete
	done := make(chan struct{})

	// Start the SCP command in a goroutine
	go func() {
		// Start SCP command
		if err := session.Start(scpCmd); err != nil {
			log.Printf("failed to start SCP command: %v", err)
			close(done) // Close the channel to signal the main thread
			return
		}

		// Write SCP header (permissions, size, filename)
		metadata := fmt.Sprintf("C0644 %d %s\n", binaryInfo.Size(), serviceName)
		if _, err := stdin.Write([]byte(metadata)); err != nil {
			log.Printf("failed to write metadata: %v", err)
			close(done) // Close the channel to signal the main thread
			return
		}

		// Write the file content
		if _, err := io.Copy(stdin, binaryFile); err != nil {
			log.Printf("failed to copy file data: %v", err)
			close(done) // Close the channel to signal the main thread
			return
		}

		// Signal the end of the file transfer
		if _, err := stdin.Write([]byte("\x00")); err != nil {
			log.Printf("failed to signal end of transfer: %v", err)
			close(done) // Close the channel to signal the main thread
			return
		}

		close(done) // Close the channel when transfer is done
	}()

	// Wait for file transfer completion via the channel
	log.Println("File transfer initiated, waiting...")
	<-done // This will block until the goroutine sends the signal

	log.Println("File transfer complete!")

	return nil
}

func checkAndCreateSystemdService(client *ssh.Client) error {
	// Check if the service exists
	output, err := executeCommand(client, fmt.Sprintf("sudo -S systemctl is-enabled %s", serviceName), 5*time.Second)
	if err != nil && !strings.Contains(output, "not-found") {
		return fmt.Errorf("failed to check systemd service: %w", err)
	}

	// If service is not found, create a systemd service
	if strings.Contains(output, "not-found") {
		log.Println("Creating systemd service...")
		serviceFile := fmt.Sprintf("[Unit]\nDescription=%s\nAfter=network.target\n\n[Service]\nExecStart=%s/%s\nRestart=always\nUser=%s\n\n[Install]\nWantedBy=multi-user.target\n", serviceName, servicePath, serviceName, serverUser)
		// Create the systemd service file
		_, err := executeCommand(client, fmt.Sprintf("echo '%s' | sudo tee /etc/systemd/system/%s.service", serviceFile, serviceName), 5*time.Second)
		if err != nil {
			return fmt.Errorf("failed to create systemd service: %w", err)
		}

		// Reload systemd, enable and start the service
		_, err = executeCommand(client, "sudo -S systemctl daemon-reload", 5*time.Second)
		if err != nil {
			return fmt.Errorf("failed to reload systemd: %w", err)
		}

		_, err = executeCommand(client, fmt.Sprintf("sudo -S systemctl enable %s", serviceName), 5*time.Second)
		if err != nil {
			return fmt.Errorf("failed to enable service: %w", err)
		}
	}

	return nil
}

func executeCommand(client *ssh.Client, cmd string, timeout time.Duration) (string, error) {
	// Create a context with timeout
	ctx, cancel := context.WithTimeout(context.Background(), timeout)
	defer cancel()

	// Create a new SSH session
	session, err := client.NewSession()
	if err != nil {
		return "", fmt.Errorf("failed to create SSH session: %w", err)
	}
	defer session.Close()

	// Set up the buffers for stdout and stderr
	var stdout, stderr bytes.Buffer
	session.Stdout = &stdout
	session.Stderr = &stderr

	// Create stdin pipe for sending password if sudo is involved
	stdinPipe, err := session.StdinPipe()
	if err != nil {
		return "", fmt.Errorf("failed to create stdin pipe: %w", err)
	}

	// Start the command in a goroutine to avoid blocking
	done := make(chan error, 1)
	go func() {
		log.Printf("Executing command: %s", cmd)
		if err := session.Start(cmd); err != nil {
			done <- fmt.Errorf("failed to start command '%s': %w", cmd, err)
			return
		}

		// Send password if sudo requires it
		if strings.Contains(cmd, "sudo -S") {
			_, err := fmt.Fprintf(stdinPipe, "%s\n", serverPassword)
			if err != nil {
				done <- fmt.Errorf("failed to write to stdin pipe: %w", err)
				return
			}
			stdinPipe.Close() // Close stdin to signal EOF
		}

		if err := session.Wait(); err != nil {
			done <- fmt.Errorf("command '%s' failed: %s", cmd, stderr.String())
			return
		}
		done <- nil
	}()

	// Wait for the command to finish or timeout
	select {
	case <-ctx.Done():
		return "", fmt.Errorf("command '%s' timed out", cmd)
	case err := <-done:
		if err != nil {
			return "", err
		}
	}

	// Return the command output
	return stdout.String(), nil
}

func connectToSSH(totp string) (*ssh.Client, error) {
	// Read the private key from file
	key, err := os.ReadFile(privateKeyPath)
	if err != nil {
		return nil, fmt.Errorf("failed to read private key: %w", err)
	}

	// Parse the private key with passphrase
	signer, err := ssh.ParsePrivateKeyWithPassphrase(key, []byte(privateKeyPassphrase))
	if err != nil {
		return nil, fmt.Errorf("failed to parse private key with passphrase: %w", err)
	}

	// SSH client config
	config := &ssh.ClientConfig{
		User: serverUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
			ssh.KeyboardInteractive(func(user, instruction string, questions []string, correctAnswers []bool) ([]string, error) {
				log.Printf("Keyboard-interactive prompt: Instruction='%s', Questions=%v", instruction, questions)
				responses := make([]string, len(questions))
				for i, question := range questions {
					if strings.Contains(strings.ToLower(question), "verification") || strings.Contains(strings.ToLower(question), "code") {
						responses[i] = totp
						log.Printf("Responding with verification code: %v", responses)
					} else if strings.Contains(strings.ToLower(question), "password") {
						responses[i] = serverPassword
						log.Printf("Responding with password (secret): %v", "****************")
					} else {
						responses[i] = "" // Default response for unexpected questions
						log.Printf("Responding with: %v", responses)
					}
				}
				return responses, nil
			}),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(), // For simplicity; secure this in production!
	}

	// Try to connect to the SSH server
	log.Printf("Connecting to SSH server at %s:%s", serverIp, serverPort)
	client, err := ssh.Dial("tcp", fmt.Sprintf("%s:%s", strings.TrimSpace(serverIp), strings.TrimSpace(serverPort)), config)
	if err != nil {
		return nil, fmt.Errorf("failed to connect to SSH server: %w", err)
	}

	log.Println("Successfully connected to the SSH server!")
	return client, nil
}

func generateTOTP(secret string) (string, error) {
	secretBytes, err := base32.StdEncoding.DecodeString(secret)
	if err != nil {
		return "", fmt.Errorf("failed to decode secret: %w", err)
	}

	timestep := time.Now().Unix() / 30
	buffer := make([]byte, 8)
	binary.BigEndian.PutUint64(buffer, uint64(timestep))

	h := hmac.New(sha1.New, secretBytes)
	h.Write(buffer)
	hash := h.Sum(nil)

	offset := hash[len(hash)-1] & 0x0F
	code := (binary.BigEndian.Uint32(hash[offset:offset+4]) & 0x7FFFFFFF) % 1000000

	return fmt.Sprintf("%06d", code), nil
}
