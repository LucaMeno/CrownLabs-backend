// Copyright 2025-2030 Politecnico di Torino
//
// Licensed under the Apache License, Version 2.0 (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
//     http://www.apache.org/licenses/LICENSE-2.0
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.

// Package webssh provides a WebSocket-based SSH bridge for CrownLabs instances.
// It allows users to connect to their VMs via SSH using a web interface.
package webssh

import (
	"context"
	"encoding/json"
	"errors"
	"io"
	"log"
	"net/http"
	"os"
	"path/filepath"
	"strconv"
	"strings"
	"sync"
	"time"

	"github.com/golang-jwt/jwt/v4"
	"github.com/gorilla/websocket"
	"golang.org/x/crypto/ssh"
	metav1 "k8s.io/apimachinery/pkg/apis/meta/v1"
	"k8s.io/apimachinery/pkg/runtime/schema"
	"k8s.io/client-go/dynamic"
	"k8s.io/client-go/rest"
)

type config struct {
	SSHUser            string
	PrivateKeyPath     string
	TimeoutDuration    int // Duration in seconds
	MaxConnectionCount int
	WebsocketPort      string
	VMSSHPort          string // Default SSH port for VMs, can be overridden in the clientInitMessage
}

func loadConfig() *config {
	vmPort := os.Getenv("WEBSSH_VM_PORT")
	if vmPort == "" {
		vmPort = "22"
		log.Println("WEBSSH_VM_PORT environment variable is not set, using default value: ", vmPort)
	}

	maxConnStr := os.Getenv("WEBSSH_MAX_CONN_COUNT")
	if maxConnStr == "" {
		maxConnStr = "1000" // Default value if not set
		log.Println("WEBSSH_MAX_CONN_COUNT environment variable is not set, using default value: ", maxConnStr)
	}

	maxConn, err := strconv.Atoi(maxConnStr)
	if err != nil {
		maxConn = 1000
		log.Println("WEBSSH_MAX_CONN_COUNT is not a valid integer, using default value: ", maxConn)
	}

	timeoutStr := os.Getenv("WEBSSH_TIMEOUT_DURATION")
	timeout, err := strconv.Atoi(timeoutStr)
	if err != nil {
		timeout = 30
		log.Println("WEBSSH_TIMEOUT_DURATION is not a valid integer, using default value: ", timeout)
	}

	SSHUser := os.Getenv("WEBSSH_USER")
	if SSHUser == "" {
		SSHUser = "crownlabs"
		log.Println("WEBSSH_USER environment variable is not set, using default value: ", SSHUser)
	}

	privateKeyPath := os.Getenv("WEBSSH_PRIVATE_KEY_PATH")
	if privateKeyPath == "" {
		privateKeyPath = "/web-keys/ssh_web_bastion_master"
		log.Println("WEBSSH_PRIVATE_KEY_PATH environment variable is not set, using default value: ", privateKeyPath)
	}

	websocketPort := os.Getenv("WEBSSH_WEBSOCKET_PORT")
	if websocketPort == "" {
		websocketPort = "8085"
		log.Println("WEBSSH_WEBSOCKET_PORT environment variable is not set, using default value: ", websocketPort)
	}

	return &config{
		SSHUser:            SSHUser,
		PrivateKeyPath:     privateKeyPath,
		TimeoutDuration:    timeout * 60, // Convert minutes to seconds
		MaxConnectionCount: maxConn,
		WebsocketPort:      websocketPort,
		VMSSHPort:          vmPort,
	}
}

type sshConnInfo struct {
	conn     *ssh.Client
	lastUsed time.Time
}

var (
	upgrader = websocket.Upgrader{
		CheckOrigin: func(r *http.Request) bool {
			// TODO: Implement proper origin checking if needed
			_ = r // Ignore the request, we don't need to check the origin in this case
			return true
		},
	}

	activeConnections = make(map[string]*sshConnInfo)
	connMutex         sync.Mutex // Mutex to protect access to activeConnections
)

type clientInitMessage struct {
	Token  string `json:"token"`
	VMIP   string `json:"vmIp"`
	VMPort string `json:"vmPort"` // Optional, can be used to specify a different port
}

func extractUsernameFromToken(tokenString string) (string, error) {
	tokenString = strings.TrimPrefix(tokenString, "Bearer ")
	token, _, err := new(jwt.Parser).ParseUnverified(tokenString, jwt.MapClaims{})
	if err != nil {
		return "", err
	}
	if claims, ok := token.Claims.(jwt.MapClaims); ok {
		if username, ok := claims["preferred_username"].(string); ok {
			return username, nil
		}
	}
	return "", errors.New("username not found in token claims")
}

func getInstances(token, namespace string) (map[string]any, error) {
	// create the Kubernetes client configuration
	config := &rest.Config{
		Host:        "https://apiserver.crownlabs.polito.it",
		BearerToken: token,
		TLSClientConfig: rest.TLSClientConfig{
			Insecure: false, // TLS ??
		},
	}

	// Create a dynamic client to interact with custom resources
	dynamicClient, err := dynamic.NewForConfig(config)
	if err != nil {
		return nil, errors.New("failed to create dynamic client: " + err.Error())
	}

	gvr := schema.GroupVersionResource{
		Group:    "crownlabs.polito.it",
		Version:  "v1alpha2",
		Resource: "instances",
	}

	list, err := dynamicClient.Resource(gvr).Namespace(namespace).List(context.TODO(), metav1.ListOptions{})
	if err != nil {
		return nil, errors.New("failed to list instances: " + err.Error())
	}

	instances := make(map[string]any)
	for _, item := range list.Items {
		instanceName := item.GetName()
		instances[instanceName] = item.Object // Store the entire object or specific fields as needed
	}

	return instances, nil
}

func validateRequest(firstMsg []byte) (clientInitMessage, error) {
	var initMsg clientInitMessage
	if err := json.Unmarshal(firstMsg, &initMsg); err != nil {
		log.Println("Invalid JSON from client:", err)
		return initMsg, errors.New("invalid JSON format")
	}

	if initMsg.VMIP == "" || initMsg.Token == "" {
		log.Println("Missing required fields in the initialization message")
		return initMsg, errors.New("missing required fields in the initialization message")
	}

	// Extract username from the token
	username, err := extractUsernameFromToken(initMsg.Token)
	if err != nil {
		log.Println("Token decode error:", err)
		return initMsg, errors.New("invalid token format")
	}

	namespace := "tenant-" + username

	log.Printf("Validating request for user: %s, namespace: %s", username, namespace)

	// Get the list of instances for the user
	instances, err := getInstances(initMsg.Token, namespace)
	if err != nil {
		log.Println("Error retrieving instances:", err)
		return initMsg, errors.New("error retrieving instances")
	}

	// check if the requested VM IP is in the list of instances
	found := false
	for _, i := range instances {
		instanceMap, ok := i.(map[string]any)
		if !ok {
			log.Println("Instance data is not in the expected format")
			continue
		}
		status, ok := instanceMap["status"].(map[string]any)
		if !ok {
			continue
		}

		ip, ok := status["ip"].(string)
		if !ok {
			continue
		}

		log.Println("IP:", ip)

		if ip == initMsg.VMIP {
			found = true
			log.Printf("Found instance with IP: %s in namespace: %s", ip, namespace)
			break
		}
	}

	if !found {
		log.Printf("No instance found for VM IP: %s in namespace: %s", initMsg.VMIP, namespace)
		return initMsg, errors.New("no instance found for the provided VM IP")
	}

	return initMsg, nil
}

func loadPrivateKey(path string) (ssh.Signer, error) {
	cleanPath := filepath.Clean(path)
	keyPriv, err := os.ReadFile(cleanPath)
	if err != nil {
		log.Printf("Error reading private key file at %s: %v", cleanPath, err)
		return nil, err
	}

	return ssh.ParsePrivateKey(keyPriv)
}

func updateSSHConnectionLastUsed(vmIP string) {
	connMutex.Lock()
	defer connMutex.Unlock()
	if info, exists := activeConnections[vmIP]; exists {
		info.lastUsed = time.Now()
	}
}

func closeSSHConnection(vmIP string) {
	var connToClose *ssh.Client

	// Remove the connection from activeConnections map
	connMutex.Lock()
	if info, exists := activeConnections[vmIP]; exists {
		connToClose = info.conn
		delete(activeConnections, vmIP) // Remove from active connections
		log.Printf("Closed SSH connection to %s", vmIP)
	} else {
		log.Printf("No active SSH connection found for %s", vmIP)
	}
	connMutex.Unlock()

	// Close the SSH connection outside the lock to to slow down contention
	if connToClose != nil {
		if err := connToClose.Close(); err != nil {
			log.Printf("failed to close SSH connection: %v", err)
		}
	}
}

func getOrCreateSSHConnection(VmIP string, sshConfig *ssh.ClientConfig, maxConnCount int) (*ssh.Client, error) {
	connMutex.Lock()
	defer connMutex.Unlock()

	// Check if the connection already exists
	if info, exists := activeConnections[VmIP]; exists {
		info.lastUsed = time.Now()
		log.Printf("Reusing existing SSH connection to %s", VmIP)
		return info.conn, nil
	}

	// check if the number of active connections exceeds the limit
	if len(activeConnections) >= maxConnCount {
		log.Printf("Maximum number of SSH connections (%d) reached. Cannot create new connection.", maxConnCount)
		return nil, errors.New("maximum number of SSH connections reached")
	}

	// If not, create a new SSH connection
	conn, err := ssh.Dial("tcp", VmIP, sshConfig)
	if err != nil {
		return nil, err
	}

	// Save the new connection in the map
	activeConnections[VmIP] = &sshConnInfo{
		conn:     conn,
		lastUsed: time.Now(),
	}

	log.Printf("New SSH connection established to %s", VmIP)

	return conn, nil
}

func startConnectionCleanup(interval, timeout time.Duration) {
	go func() {
		for {
			time.Sleep(interval)
			connMutex.Lock()
			log.Println("Starting connection cleanup...")
			now := time.Now()
			for ip, info := range activeConnections {
				if now.Sub(info.lastUsed) > timeout {
					err := info.conn.Close()
					if err != nil {
						log.Printf("Error closing SSH connection to %s: %v", ip, err)
					} else {
						log.Printf("Closed idle SSH connection to %s", ip)
					}
					delete(activeConnections, ip)
				}
			}
			connMutex.Unlock()
		}
	}()
}

func returnError(ws *websocket.Conn, errMsg string) {
	if err := ws.WriteMessage(websocket.TextMessage, []byte(errMsg)); err != nil {
		log.Println("WebSocket write error:", err)
	}
}

func wsHandler(w http.ResponseWriter, r *http.Request, config *config) {
	// upgrade to the WebSocket
	ws, err := upgrader.Upgrade(w, r, nil)
	if err != nil {
		log.Println("WebSocket upgrade failed:", err)
		return
	}

	defer func() {
		if err := ws.Close(); err != nil {
			log.Printf("failed to close ws connection: %v", err)
		}
	}()

	// Validate the req
	// wait for the first message to get the token
	_, firstMsg, err := ws.ReadMessage()
	if err != nil {
		log.Println("ReadMessage error:", err)
		returnError(ws, "Error reading initial message")
		return
	}

	initMsg, err := validateRequest(firstMsg)
	if err != nil {
		log.Println("Request validation failed:", err)
		returnError(ws, "Invalid request")
		return
	}

	// Construct the SSH connection string
	port := initMsg.VMPort
	if port == "" {
		port = config.VMSSHPort // Default port if not specified
	}
	connString := initMsg.VMIP + ":" + port // ip:port

	// Load the private key for SSH authentication
	signer, err := loadPrivateKey(config.PrivateKeyPath)
	if err != nil {
		log.Println("Failed to load private key:", err)
		returnError(ws, "Interal server error")
		return
	}

	sshConfig := &ssh.ClientConfig{
		User: config.SSHUser,
		Auth: []ssh.AuthMethod{
			ssh.PublicKeys(signer),
		},
		HostKeyCallback: ssh.InsecureIgnoreHostKey(),
		Timeout:         10 * time.Second,
	}

	sshConn, err := getOrCreateSSHConnection(connString, sshConfig, config.MaxConnectionCount)
	if err != nil {
		log.Println("Failed to get or create SSH connection:", err)
		returnError(ws, "Failed to connect to the SSH server")
		return
	}

	session, err := sshConn.NewSession()
	if err != nil {
		log.Println("Failed to create SSH session:", err)
		returnError(ws, "Internal server error")
		return
	}

	defer func() {
		if err := session.Close(); err != nil {
			log.Printf("failed to close SSH session: %v", err)
		}
	}()

	modes := ssh.TerminalModes{
		ssh.ECHO:          1,
		ssh.TTY_OP_ISPEED: 14400,
		ssh.TTY_OP_OSPEED: 14400,
	}

	if err := session.RequestPty("xterm", 40, 80, modes); err != nil {
		log.Println("Request for pseudo terminal failed:", err)
		returnError(ws, "Internal server error")
		return
	}

	stdin, err := session.StdinPipe()
	if err != nil {
		log.Println("Unable to setup stdin for session:", err)
		returnError(ws, "Internal server error")
		return
	}
	stdout, err := session.StdoutPipe()
	if err != nil {
		log.Println("Unable to setup stdout for session:", err)
		returnError(ws, "Internal server error")
		return
	}

	if err := session.Shell(); err != nil {
		log.Println("Failed to start shell:", err)
		returnError(ws, "Internal server error")
		return
	}

	// Start a goroutine to read from SSH stdout and write to WebSocket
	go func() {
		buf := make([]byte, 1024)
		for {
			n, err := stdout.Read(buf)
			if err != nil {
				if err != io.EOF {
					log.Println("SSH stdout read error:", err)
				}
				break
			}
			updateSSHConnectionLastUsed(connString) // reset timer on shell output
			if err := ws.WriteMessage(websocket.TextMessage, buf[:n]); err != nil {
				log.Println("WebSocket write error:", err)
				break
			}
		}
	}()

	// Read messages from WebSocket and write to SSH stdin
	for {
		_, msg, err := ws.ReadMessage()
		if err != nil {
			log.Println("Closing SSH session, WebSocket read error:", err)
			closeSSHConnection(connString)
			break
		}
		updateSSHConnectionLastUsed(connString) // reset timer on user input
		if _, err := stdin.Write(msg); err != nil {
			log.Println("SSH stdin write error:", err)
			break
		}
	}
}

func wsHandlerWrapper(config *config) http.HandlerFunc {
	return func(w http.ResponseWriter, r *http.Request) {
		wsHandler(w, r, config)
	}
}

// StartWebSSH initializes the WebSocket SSH bridge server.
// It loads the configuration, sets up the HTTP server, and starts listening for WebSocket connections.
func StartWebSSH() {
	// Load configuration from environment variables
	config := loadConfig()

	// automatic Cleanup
	startConnectionCleanup(2*time.Minute, time.Duration(config.TimeoutDuration)*time.Second)

	mux := http.NewServeMux()
	mux.HandleFunc("/ws", wsHandlerWrapper(config))

	log.Println("WebSocket SSH bridge running on :" + config.WebsocketPort)

	server := &http.Server{
		Addr:         ":" + config.WebsocketPort,
		Handler:      mux,
		ReadTimeout:  5 * time.Second,
		WriteTimeout: 10 * time.Second,
		IdleTimeout:  120 * time.Second,
	}

	if err := server.ListenAndServe(); err != nil && err != http.ErrServerClosed {
		log.Fatalf("HTTP server failed: %v", err)
	}
}
