// enc_client.c
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netinet/in.h>
#include <netdb.h> // For gethostbyname and host information

#define BUFFER_SIZE 1024 // Define the maximum buffer size for data
#define ALLOWED_CHARS "ABCDEFGHIJKLMNOPQRSTUVWXYZ " // Define valid characters for plaintext

// Function to handle errors and terminate the program
void error(const char *msg) {
    perror(msg);
    exit(1);
}

// Function to validate that the input text contains only allowed characters
void validate_input(const char *text) {
    for (int i = 0; text[i] != '\0'; i++) {
        // If a character is not in the allowed set, print an error and terminate
        if (strchr(ALLOWED_CHARS, text[i]) == NULL) {
            fprintf(stderr, "Error: input contains bad characters\n");
            exit(1);
        }
    }
}

// Function to read the contents of a file and return it as a string
char* read_file(const char *filename) {
    FILE *file = fopen(filename, "r"); // Open the file in read mode
    if (!file) {
        fprintf(stderr, "Error: could not open file %s\n", filename);
        exit(1);
    }

    char *content = malloc(BUFFER_SIZE); // Allocate memory for the file content
    if (!content) {
        fprintf(stderr, "Error: memory allocation failed\n");
        fclose(file);
        exit(1);
    }

    memset(content, 0, BUFFER_SIZE); // Initialize the buffer to zeros
    fread(content, 1, BUFFER_SIZE - 1, file); // Read the file into the buffer

    fclose(file); // Close the file after reading

    // Remove the trailing newline character if it exists
    size_t len = strlen(content);
    if (len > 0 && content[len - 1] == '\n') {
        content[len - 1] = '\0';
    }

    return content; // Return the file content as a string
}

int main(int argc, char *argv[]) {
    // Check for proper usage with the required number of arguments
    if (argc != 4) {
        fprintf(stderr, "Usage: %s plaintext_file key_file port\n", argv[0]);
        exit(1);
    }

    int sockfd, port_number;
    struct sockaddr_in server_addr; // Structure to store server address information
    struct hostent *server; // Host information
    char buffer[BUFFER_SIZE]; // Buffer for reading and writing data
    char hostname[] = "localhost"; // Define the hostname

    // Read the plaintext and key files
    char *plaintext = read_file(argv[1]);
    char *key = read_file(argv[2]);

    // Validate that the plaintext contains only allowed characters
    validate_input(plaintext);

    // Ensure the key is at least as long as the plaintext
    if (strlen(key) < strlen(plaintext)) {
        fprintf(stderr, "Error: key is too short\n");
        free(plaintext);
        free(key);
        exit(1);
    }

    port_number = atoi(argv[3]); // Parse the port number from the arguments

    // Create a socket for communication
    sockfd = socket(AF_INET, SOCK_STREAM, 0);
    if (sockfd < 0) error("Error opening socket");

    // Retrieve host information
    server = gethostbyname(hostname);
    if (!server) {
        fprintf(stderr, "Error: no such host\n");
        free(plaintext);
        free(key);
        exit(1);
    }

    // Set up the server address structure
    memset((char *)&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    memcpy((char *)&server_addr.sin_addr.s_addr, server->h_addr_list[0], server->h_length);
    server_addr.sin_port = htons(port_number);

    // Connect to the server
    if (connect(sockfd, (struct sockaddr *)&server_addr, sizeof(server_addr)) < 0)
        error("Error connecting to server");

    // Send a handshake message to identify as the encryption client
    char *handshake = "ENC_CLIENT";
    if (write(sockfd, handshake, strlen(handshake)) < 0)
        error("Error sending handshake");

    // Read and verify the handshake response from the server
    memset(buffer, 0, BUFFER_SIZE);
    if (read(sockfd, buffer, BUFFER_SIZE - 1) <= 0)
        error("Error reading handshake response");

    if (strcmp(buffer, "ENC_SERVER") != 0) {
        fprintf(stderr, "Error: invalid server response during handshake\n");
        free(plaintext);
        free(key);
        close(sockfd);
        exit(1);
    }

    // Send the length of the plaintext to the server
    int plaintext_len = strlen(plaintext);
    if (write(sockfd, &plaintext_len, sizeof(int)) < 0)
        error("Error sending plaintext length");

    // Send the plaintext to the server
    if (write(sockfd, plaintext, plaintext_len) < 0)
        error("Error sending plaintext");

    // Send the key to the server
    if (write(sockfd, key, plaintext_len) < 0)
        error("Error sending key");

    // Read the ciphertext returned by the server
    memset(buffer, 0, BUFFER_SIZE);
    if (read(sockfd, buffer, BUFFER_SIZE - 1) < 0)
        error("Error reading ciphertext");

    // Print the ciphertext to standard output
    printf("%s\n", buffer);

    // Clean up allocated memory and close the socket
    free(plaintext);
    free(key);
    close(sockfd);
    return 0;
}
