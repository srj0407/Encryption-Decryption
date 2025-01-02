# Encryption-Decryption
# README

## Overview
This project implements an encryption and decryption system using client to server communication lines. Below details how to compile and run the project.

# Compile the servers
gcc -o enc_server enc_server.c -std=c99
gcc -o dec_server dec_server.c -std=c99

# Compile the clients
gcc -o enc_client enc_client.c -std=c99
gcc -o dec_client dec_client.c -std=c99

# Compile the keygen utility
gcc -o keygen keygen.c -std=c99



### Key Generation
To generate a key of a specified length, run:
./keygen <length> > keyfile

Example:
./keygen 20 > key20
./keygen 70000 > key70000

### Running the Servers
Run the encryption and decryption servers on different ports:
./enc_server <port> &
./dec_server <port> &


The script performs the following tests:
1. Key generation validation.
2. Encryption validation.
3. Decryption validation.
4. Concurrent encryption and decryption tests.
