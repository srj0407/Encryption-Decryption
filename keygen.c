#include <stdio.h>
#include <stdlib.h>
#include <time.h>

// Define the allowed characters for the key and their count (This is inefficient but I'm lazy)
#define ALLOWED_CHARS "ABCDEFGHIJKLMNOPQRSTUVWXYZ "
#define CHAR_COUNT 27

// Function to generate a random key of specified length
void generate_key(int length) {
    // Seed the random number generator with the current time
    srand((unsigned int)time(NULL));

    for (int i = 0; i < length; i++) {
        // Generate a random index within the range of allowed characters
        int random_index = rand() % CHAR_COUNT;
        // Print the corresponding character from the allowed set
        printf("%c", ALLOWED_CHARS[random_index]);
    }

    // Add a newline character at the end for proper formatting
    printf("\n");
}

int main(int argc, char *argv[]) {
    // Check if the user provided exactly one argument for key length (Don't do more than one >:( )
    if (argc != 2) {
        fprintf(stderr, "Usage: %s key_length\n", argv[0]);
        exit(EXIT_FAILURE); // Exit with failure if the usage is incorrect
    }

    // Parse the key length from the command-line argument
    int key_length = atoi(argv[1]);
    // Validate that the key length is a positive integer
    if (key_length <= 0) {
        fprintf(stderr, "Error: key_length must be a positive integer.\n");
        exit(EXIT_FAILURE); // Exit with failure if the input is invalid
    }

    // Call the function to generate and print the key
    generate_key(key_length);

    // Exit the program successfully
    return 0;
}
