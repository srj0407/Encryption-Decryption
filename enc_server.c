// enc_server.c

#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> // For inet_ntoa (I had to figure otu what this was and it hurts my brain) function
#include <signal.h>    // For signal handling
#include <errno.h>     // For errno during error handling
#include <sys/wait.h>  // For handling child process cleanup
#include <sys/time.h>  // For timeval structure

// Define constants for buffer size, character count, maximum connections, and allowed characters
#define BUFFER_SIZE 1024
#define CHAR_COUNT 27
#define MAX_CONNECTIONS 5
#define ALLOWED_CHARS "ABCDEFGHIJKLMNOPQRSTUVWXYZ "

// Utility function to print an error message and exit the program
void error(const char *msg) {
    perror(msg);
    exit(1);
}

// Function to encrypt plaintext using the key
void encrypt_text(const char *plaintext, const char *key, char *ciphertext) {
    int i;
    // Iterate through each character in the plaintext
    for (i = 0; plaintext[i] != '\0'; i++) {
        // Map characters to a range (0-26) based on the alphabet or space
        int plain_char = (plaintext[i] == ' ') ? 26 : plaintext[i] - 'A';
        int key_char = (key[i] == ' ') ? 26 : key[i] - 'A';
        // Compute encrypted character using modular addition
        int encrypted_char = (plain_char + key_char) % CHAR_COUNT;
        // Map back to alphabet or space and store in ciphertext
        ciphertext[i] = (encrypted_char == 26) ? ' ' : 'A' + encrypted_char;
    }
    // Null-terminate the ciphertext string
    ciphertext[i] = '\0';
}

// Function to handle communication with a client
void handle_client(int connection_socket, struct sockaddr_in client_addr) {
    char buffer[BUFFER_SIZE], verification[BUFFER_SIZE];
    char plaintext[BUFFER_SIZE], key[BUFFER_SIZE], ciphertext[BUFFER_SIZE];

    // Log the client's IP address for debugging
    printf("DEBUG: Client connected from %s\n", inet_ntoa(client_addr.sin_addr));

    // Read handshake message from client
    memset(verification, 0, BUFFER_SIZE);
    int n = read(connection_socket, verification, BUFFER_SIZE - 1);
    if (n < 0) error("ERROR reading verification from socket");

    // Verify that the handshake message matches expected value
    if (strcmp(verification, "ENC_CLIENT") != 0) {
        fprintf(stderr, "ERROR: Invalid client handshake: '%s'\n", verification);
        close(connection_socket); // Close connection if handshake fails
        return;
    }

    // Send handshake acknowledgment to the client
    char *response = "ENC_SERVER";
    n = write(connection_socket, response, strlen(response));
    if (n < 0) error("ERROR writing handshake response to socket");

    // Read the length of plaintext from the client
    int plaintext_len;
    n = read(connection_socket, &plaintext_len, sizeof(int));
    if (n <= 0) {
        perror("ERROR reading plaintext length");
        close(connection_socket);
        return;
    }

    // Read the plaintext data from the client
    memset(plaintext, 0, BUFFER_SIZE);
    n = read(connection_socket, plaintext, plaintext_len);
    if (n < 0) error("ERROR reading plaintext from socket");
    plaintext[plaintext_len] = '\0'; // Ensure null-termination

    // Read the key data from the client
    memset(key, 0, BUFFER_SIZE);
    n = read(connection_socket, key, plaintext_len);
    if (n < 0) error("ERROR reading key from socket");
    key[plaintext_len] = '\0'; // Ensure null-termination

    // Validate that the key is at least as long as the plaintext
    if (strlen(key) < strlen(plaintext)) {
        fprintf(stderr, "ERROR: Key is too short\n");
        close(connection_socket);
        return;
    }

    // Encrypt the plaintext using the provided key
    encrypt_text(plaintext, key, ciphertext);

    // Send the encrypted ciphertext back to the client
    n = write(connection_socket, ciphertext, strlen(ciphertext));
    if (n < 0) error("ERROR writing ciphertext to socket");

    // Close the client connection
    close(connection_socket);
}

// Function to clean up zombie processes from child processes
void cleanup_zombies() {
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

// Main function to set up and run the encryption server
int main(int argc, char *argv[]) {
    if (argc < 2) {
        fprintf(stderr, "Usage: %s port\n", argv[0]);
        exit(1);
    }

    int listen_socket, connection_socket, port_number;
    socklen_t client_len;
    struct sockaddr_in server_addr, client_addr;

    // Create a socket for the server
    listen_socket = socket(AF_INET, SOCK_STREAM, 0);
    if (listen_socket < 0) error("ERROR opening socket");

    // Allow socket reuse to avoid address binding issues
    int yes = 1;
    if (setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
        error("ERROR on setsockopt");
    }

    // Configure server address structure
    memset((char *)&server_addr, 0, sizeof(server_addr));
    port_number = atoi(argv[1]);
    server_addr.sin_family = AF_INET;
    server_addr.sin_addr.s_addr = INADDR_ANY; // Bind to all available interfaces
    server_addr.sin_port = htons(port_number); // Set the port number

    // Bind the socket to the specified port
    if (bind(listen_socket, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0) 
        error("ERROR on binding");

    // Start listening for incoming connections
    listen(listen_socket, MAX_CONNECTIONS);
    client_len = sizeof(client_addr);

    // Set up signal handler to clean up zombie processes
    signal(SIGCHLD, cleanup_zombies);

    // Main server loop to accept and handle client connections
    while (1) {
        // Accept a new client connection
        connection_socket = accept(listen_socket, (struct sockaddr *)&client_addr, &client_len);
        if (connection_socket < 0) {
            if (errno == EINTR) {
                // Retry if interrupted by a signal
                continue;
            } else {
                error("ERROR on accept");
            }
        }

        // Fork a new process to handle the client
        pid_t pid = fork();
        if (pid < 0) {
            error("ERROR on fork");
        } else if (pid == 0) {
            // In child process: close the listening socket and handle the client
            close(listen_socket);
            handle_client(connection_socket, client_addr);
            exit(0); // Exit child process after handling the client
        } else {
            // In parent process: close the client socket
            close(connection_socket);
        }
    }

    // Close the listening socket (unreachable in this design)
    close(listen_socket);
    return 0;
}
