// dec_server.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h> // For inet_ntoa (Again, brain hurts) to display IP addresses
#include <signal.h>    // For handling signals like SIGCHLD
#include <errno.h>     // For error handling with errno
#include <sys/wait.h>  // For cleaning up child processes

// Define constants for buffer size, the alphabet, and maximum connections
#define BUFFER_SIZE 1024
#define ALPHABET "ABCDEFGHIJKLMNOPQRSTUVWXYZ "
#define ALPHABET_SIZE 27
#define MAX_CONNECTIONS 5

// Utility function to print error messages and terminate the program
void error(const char *msg) {
    perror(msg);
    exit(1);
}

// Function to decrypt a ciphertext using the provided key
void decrypt_message(const char *ciphertext, const char *key, char *plaintext) {
    int cipher_len = strlen(ciphertext);

    // Iterate through each character in the ciphertext
    for (int i = 0; i < cipher_len; i++) {
        // Get the index of the ciphertext character and the key character
        int cipher_index = strchr(ALPHABET, ciphertext[i]) - ALPHABET;
        int key_index = strchr(ALPHABET, key[i]) - ALPHABET;

        // Calculate the plaintext index using modular subtraction
        int plain_index = (cipher_index - key_index + ALPHABET_SIZE) % ALPHABET_SIZE;

        // Map back to a character in the alphabet
        plaintext[i] = ALPHABET[plain_index];
    }

    // Null-terminate the resulting plaintext string
    plaintext[cipher_len] = '\0';
}

// Function to handle communication with a single client
void handle_client(int connection_socket, struct sockaddr_in client_addr) {
    char buffer[BUFFER_SIZE], verification[BUFFER_SIZE];
    char ciphertext[BUFFER_SIZE], key[BUFFER_SIZE], plaintext[BUFFER_SIZE];

    // Log the client’s IP address for debugging
    printf("DEBUG: Client connected from %s\n", inet_ntoa(client_addr.sin_addr));

    // Read and verify the handshake message from the client
    memset(verification, 0, BUFFER_SIZE);
    int n = read(connection_socket, verification, BUFFER_SIZE - 1);
    if (n < 0) {
        error("ERROR reading verification from socket");
    }
    printf("DEBUG: Received handshake: '%s'\n", verification);

    // Validate the handshake matches "DEC_CLIENT"
    if (strcmp(verification, "DEC_CLIENT") != 0) {
        fprintf(stderr, "Invalid client connection\n");
        close(connection_socket); // Close the connection on failure
        return;
    }

    // Send a handshake acknowledgment back to the client
    char *response = "DEC_SERVER";
    n = write(connection_socket, response, strlen(response));
    if (n < 0) error("ERROR writing handshake response to socket");
    printf("DEBUG: Sent handshake response: '%s'\n", response);

    // Read the ciphertext length from the client
    int ciphertext_len;
    n = read(connection_socket, &ciphertext_len, sizeof(int));
    if (n <= 0) {
        perror("ERROR reading ciphertext length");
        close(connection_socket);
        return;
    }
    printf("DEBUG: Received ciphertext length: %d\n", ciphertext_len);

    // Read the ciphertext data
    memset(ciphertext, 0, BUFFER_SIZE);
    n = read(connection_socket, ciphertext, ciphertext_len);
    if (n < 0) error("ERROR reading ciphertext from socket");
    ciphertext[ciphertext_len] = '\0'; // Null-terminate the ciphertext
    printf("DEBUG: Received ciphertext: '%s'\n", ciphertext);

    // Read the key data
    memset(key, 0, BUFFER_SIZE);
    n = read(connection_socket, key, ciphertext_len);
    if (n < 0) error("ERROR reading key from socket");
    key[ciphertext_len] = '\0'; // Null-terminate the key
    printf("DEBUG: Received key: '%s'\n", key);

    // Validate the key length matches or exceeds the ciphertext length
    if (strlen(key) < strlen(ciphertext)) {
        fprintf(stderr, "ERROR: Key is too short\n");
        close(connection_socket);
        return;
    }

    // Decrypt the ciphertext into plaintext
    decrypt_message(ciphertext, key, plaintext);
    printf("DEBUG: Decrypted plaintext: '%s'\n", plaintext);

    // Send the decrypted plaintext back to the client
    n = write(connection_socket, plaintext, strlen(plaintext));
    if (n < 0) error("ERROR writing plaintext to socket");

    // Close the connection with the client
    close(connection_socket);
}

// Function to clean up zombie processes left by child processes
void cleanup_zombies() {
    while (waitpid(-1, NULL, WNOHANG) > 0);
}

// Main function to set up and run the decryption server
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

    // Allow socket reuse to avoid binding issues
    int yes = 1;
    if (setsockopt(listen_socket, SOL_SOCKET, SO_REUSEADDR, &yes, sizeof(int)) == -1) {
        error("ERROR on setsockopt");
    }

    // Configure the server address structure
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

    // Set up a signal handler to clean up zombie processes
    signal(SIGCHLD, cleanup_zombies);

    // Main server loop to accept and handle client connections
    while (1) {
        // Accept a new client connection
        connection_socket = accept(listen_socket, (struct sockaddr *)&client_addr, &client_len);
        if (connection_socket < 0) {
            if (errno == EINTR) {
                // Retry if interrupted by a signal (You might this is is unneeded... but sadly... no :( )
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
            exit(0); // Exit the child process after handling the client
        } else {
            // In parent process: close the client socket
            close(connection_socket);
        }
    }

    // Close the listening socket (unreachable in this design)
    close(listen_socket);
    return 0;
}
