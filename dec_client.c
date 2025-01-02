// dec_client.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> // For hostname resolution and server connection

#define BUFFER_SIZE 1024 // Define the maximum size for data buffers
#define ALLOWED_CHARS "ABCDEFGHIJKLMNOPQRSTUVWXYZ " // Define allowed characters for validation

// Function to handle errors by displaying a message and exiting
void error(const char *msg) {
    perror(msg);
    exit(1);
}

// Function to validate that a text contains only allowed characters
void validate_input(const char *text) {
    for (int i = 0; text[i] != '\0'; i++) {
        if (strchr(ALLOWED_CHARS, text[i]) == NULL) { // Check if character is not in allowed set
            fprintf(stderr, "Error: input contains bad characters\n");
            exit(1);
        }
    }
}

// Function to read the content of a file and return it as a string
char* read_file(const char *filename) {
    FILE *file = fopen(filename, "r"); // Open the file in read mode
    if (!file) {
        fprintf(stderr, "Error: could not open file %s\n", filename);
        exit(1);
    }

    char *content = malloc(BUFFER_SIZE); // Allocate memory for file content
    if (!content) {
        fprintf(stderr, "Error: memory allocation failed\n");
        fclose(file);
        exit(1);
    }

    memset(content, 0, BUFFER_SIZE); // Initialize buffer to zero
    fread(content, 1, BUFFER_SIZE - 1, file); // Read file content into buffer

    fclose(file); // Close the file

    // Remove trailing newline character, if present
    size_t len = strlen(content);
    if (len > 0 && content[len - 1] == '\n') {
        content[len - 1] = '\0';
    }

    return content; // Return the file content
}

int main(int argc, char *argv[]) {
    // Validate command-line arguments
    if (argc != 4) {
        fprintf(stderr, "Usage: %s ciphertext_file key_file port\n", argv[0]);
        exit(1);
    }

    int sockfd, port_number;
    struct sockaddr_in server_addr; // Structure for server address
    struct hostent *server; // Pointer to server information
    char buffer[BUFFER_SIZE]; // Buffer for communication
    char hostname[] = "localhost"; // Hostname for the server

    // Read the ciphertext and key from files
    char *ciphertext = read_file(argv[1]);
    char *key = read_file(argv[2]);

    // Validate the ciphertext to ensure it contains allowed characters
    validate_input(ciphertext);

    // Ensure the key is at least as long as the ciphertext
    if (strlen(key) < strlen(ciphertext)) {
        fprintf(stderr, "Error: key is too short\n");
        free(ciphertext);
        free(key);
        exit(1);
    }

    port_number = atoi(argv[3]); // Convert port argument to integer

    // Create a socket for communication
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) error("Error opening socket");

    // Resolve hostname to obtain server address information
    server = gethostbyname(hostname);
    if (!server) {
        fprintf(stderr, "Error: no such host\n");
        free(ciphertext);
        free(key);
        exit(1);
    }

    // Initialize server address structure
    memset((char *)&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET; // Use IPv4
    memcpy((char *)&server_addr.sin_addr.s_addr, server->h_addr_list[0], server->h_length);
    server_addr.sin_port = htons(port_number); // Convert port number to network byte order

    // Establish connection to the server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        error("Error connecting to server");

    // Send handshake message to identify as decryption client
    char *handshake = "DEC_CLIENT";
    if (write(sockfd, handshake, strlen(handshake)) < 0)
        error("Error sending handshake");

    // Read the server's handshake response
    memset(buffer, 0, BUFFER_SIZE);
    if (read(sockfd, buffer, BUFFER_SIZE - 1) <= 0)
        error("Error reading handshake response");

    // Debugging: Print received handshake response
    fprintf(stderr, "DEBUG: Received handshake response: '%s'\n", buffer);

    // Verify the handshake response matches "DEC_SERVER"
    if (strcmp(buffer, "DEC_SERVER") != 0) {
        fprintf(stderr, "Error: invalid server response during handshake: '%s'\n", buffer);
        free(ciphertext);
        free(key);
        close(sockfd);
        exit(1);
    }

    // Send the length of the ciphertext to the server
    int ciphertext_len = strlen(ciphertext);
    if (write(sockfd, &ciphertext_len, sizeof(int)) < 0)
        error("Error sending ciphertext length");

    // Send the ciphertext to the server
    if (write(sockfd, ciphertext, ciphertext_len) < 0)
        error("Error sending ciphertext");

    // Send the key to the server
    if (write(sockfd, key, ciphertext_len) < 0)
        error("Error sending key");

    // Receive the plaintext response from the server
    memset(buffer, 0, BUFFER_SIZE);
    if (read(sockfd, buffer, BUFFER_SIZE - 1) < 0)
        error("Error reading plaintext");

    // Output the decrypted plaintext
    printf("%s\n", buffer);

    // Free allocated memory and close the socket
    free(ciphertext);
    free(key);
    close(sockfd);
    return 0;
}
