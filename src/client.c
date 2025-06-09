
#include <openssl/evp.h>
#include <openssl/pem.h>

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>

#include <stdlib.h>
#include <stdio.h>
#include <errno.h>

#include "security.h"
#include "common.h"

EVP_PKEY *server_signature_pubkey = NULL;

/* Socket used to communicate with the server */
int sd;

uint8_t AEAD_keys[AEAD_KEY_LENGTH * 2];
uint8_t *server2client_key = AEAD_keys;
uint8_t *client2server_key = AEAD_keys + AEAD_KEY_LENGTH;

union Counter counter; /* Automatically zero-initialized */

/**
 * Loads the server's public key for digital signatures.
 * Exits the program with code EXIT_FAILURE in case of error
 */
int load_server_signature_pubkey(void)
{
    log_msg(INFO, "Loading server_signature_pubkey.pem...");

    FILE *fp = fopen("server_signature_pubkey.pem", "r");
    CHECK(fp == NULL, CRITICAL, errno, "Unable to open server_signature_pubkey.pem");

    server_signature_pubkey = PEM_read_PUBKEY(fp, NULL, NULL, NULL);
    fclose(fp);
    CHECK(server_signature_pubkey == NULL, CRITICAL, 0, "Unable to parse server_signature_pubkey.pem");
    CHECK(EVP_PKEY_size(server_signature_pubkey) > SIGNATURE_LENGTH_MAX, CRITICAL, 0, 
        "SIGNATURE_LENGTH_MAX (%i) is too small for the specified key (%i)",
        SIGNATURE_LENGTH_MAX, EVP_PKEY_size(server_signature_pubkey));

    log_msg(INFO, "Successfully loaded the server's public key");
    return 0;
}

/**
 * Creates a socket to communicate with the specified server and port.
 * Exits the program with code EXIT_FAILURE in case of error
 */
int connect_to_server(void) 
{
    log_msg(INFO, "Connecting to " SERVER_IP ":%i...", SERVER_PORT);

    sd = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(sd == -1, CRITICAL, errno, "Unable to create the socket");

    struct sockaddr_in server_addr;
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    inet_pton(AF_INET, SERVER_IP, &server_addr.sin_addr);

    int ret = connect(sd, (struct sockaddr*)&server_addr, sizeof(server_addr));
    CHECK(ret == -1, CRITICAL, errno, "Unable to connect to the server");

    log_msg(INFO, "Successfully connected to the server");
    return 0;
}

/**
 * Estabilishes a secure channel with the server.
 * Exits the program with code EXIT_FAILURE in case of error
 *  (this implies that, in case of error, there is no need to free the keypairs)
 */
int handshake(void)
{
    log_msg(INFO, "Initiating the handshake...");
    int ret = -1;

    int handshake_len = ECDHE_KEY_LENGTH + ECDHE_NONCE_LENGTH + ECDHE_KEY_LENGTH + ECDHE_NONCE_LENGTH;
    CHECK(handshake_len > NETWORK_BUFFER_LENGTH, CRITICAL, 0, 
        "NETWORK_BUFFER_LENGTH (%i) is too small for the handshake (%i)",
        NETWORK_BUFFER_LENGTH, handshake_len);

    uint8_t network_buffer[NETWORK_BUFFER_LENGTH];
    uint8_t *server_pubkey = network_buffer;
    uint8_t *server_nonce  = network_buffer + ECDHE_KEY_LENGTH;
    uint8_t *client_pubkey = network_buffer + ECDHE_KEY_LENGTH + ECDHE_NONCE_LENGTH;
    uint8_t *client_nonce  = network_buffer + ECDHE_KEY_LENGTH + ECDHE_NONCE_LENGTH + ECDHE_KEY_LENGTH;

    /* Generate the ECDHE key pair */
    EVP_PKEY *client_keypair = NULL;
    ret = generate_ECDHE_keypair(&client_keypair);
    CHECK(ret == -1, CRITICAL, 0, "Unable to generate the ECDHE key pair");

    ret = serialize_ECDHE_pubkey(client_keypair, client_pubkey);
    CHECK(ret == -1, CRITICAL, 0, "Unable to extract the ECDHE raw public key");

    log_msg(DEBUG, "Generated the ECDHE public key (length = %i):", ECDHE_KEY_LENGTH);
    debug_bytes(client_pubkey, ECDHE_KEY_LENGTH);

    /* Generate the nonce */
    ret = generate_nonce(client_nonce, ECDHE_NONCE_LENGTH);
    CHECK(ret == -1, CRITICAL, 0, "Unable to generate the nonce");

    log_msg(DEBUG, "Generated the nonce (length = %i):", ECDHE_NONCE_LENGTH);
    debug_bytes(client_nonce, ECDHE_NONCE_LENGTH);

    /* Send client's ECDHE pubkey to the server */
    ret = send_msg(sd, client_pubkey, ECDHE_KEY_LENGTH);
    CHECK(ret == -1, CRITICAL, 0, "Unable to send the ECDHE public key to the server");
    log_msg(DEBUG, "Sent the ECDHE public key to the server");

    /* Send client's nonce to the server */
    ret = send_msg(sd, client_nonce, ECDHE_NONCE_LENGTH);
    CHECK(ret == -1, CRITICAL, 0, "Unable to send the nonce to the server");
    log_msg(DEBUG, "Sent the nonce to the server");

    /* Receive servers's ECDHE public key */
    ret = recv_msg_known_len(sd, server_pubkey, ECDHE_KEY_LENGTH);
    CHECK(ret != 0, CRITICAL, 0, "Unable to receive server's ECDHE public key");
    
    log_msg(DEBUG, "Received server's ECDHE public key (length = %i):", ECDHE_KEY_LENGTH);
    debug_bytes(server_pubkey, ECDHE_KEY_LENGTH);
    
    /* Receive server's nonce */
    ret = recv_msg_known_len(sd, server_nonce, ECDHE_NONCE_LENGTH);
    CHECK(ret != 0, CRITICAL, 0, "Unable to receive server's nonce");
    
    log_msg(DEBUG, "Received server's nonce (length = %i):", ECDHE_NONCE_LENGTH);
    debug_bytes(server_nonce, ECDHE_NONCE_LENGTH);

    /* Receive server's signature of the handshake */
    int sig_len;
    uint8_t signature[SIGNATURE_LENGTH_MAX];
    ret = recv_msg(sd, signature, SIGNATURE_LENGTH_MAX, &sig_len);
    CHECK(ret != 0, CRITICAL, 0, "Unable to receive server's signature of the handshake");

    log_msg(DEBUG, "Handshake buffer (length = %i):", handshake_len);
    debug_bytes(network_buffer, handshake_len);

    log_msg(DEBUG, "Received server's signature of the handshake (length = %u):", sig_len);
    debug_bytes(signature, sig_len);
    
    /* Verify the handshake against the received signature */
    ret = verify(network_buffer, handshake_len, server_signature_pubkey, signature, sig_len);
    CHECK(ret == -1, CRITICAL, 0, "Unable to verify server's signature of the handshake");
    log_msg(DEBUG, "Successfully verified server's signature of the handshake");

    /* De-serialize server's pubkey */
    EVP_PKEY *server_keypair = NULL;
    ret = deserialize_ECDHE_pubkey(server_pubkey, &server_keypair);
    CHECK(ret == -1, CRITICAL, 0, "Unable to de-serialize the server's pubkey");

    /* Derive the ECDHE master secret */
    uint8_t master_secret[MASTER_SECRET_LENGTH];
    ret = derive_ECDHE_master_secret(client_keypair, server_keypair, master_secret);
    CHECK(ret == -1, CRITICAL, 0, "Unable to derive the master secret");

    log_msg(DEBUG, "Derived the master secret (length = %i):", MASTER_SECRET_LENGTH);
    debug_bytes(master_secret, MASTER_SECRET_LENGTH);

    /* Derive the AEAD keys */
    ret = derive_AEAD_keys(master_secret, server_nonce, client_nonce, server2client_key, client2server_key);
    CHECK(ret == -1, CRITICAL, 0, "Unable to derive the AEAD keys");

    log_msg(DEBUG, "Derived the AEAD server -> client key (length = %i):", AEAD_KEY_LENGTH);
    debug_bytes(server2client_key, AEAD_KEY_LENGTH);

    log_msg(DEBUG, "Derived the AEAD client -> server key (length = %i):", AEAD_KEY_LENGTH);
    debug_bytes(client2server_key, AEAD_KEY_LENGTH);

    EVP_PKEY_free(client_keypair);
    EVP_PKEY_free(server_keypair);

    log_msg(INFO, "Handshake completed");
    return 0;
}

/**
 * Authenticates the client to the server by means of the couple (user_id, password).
 * Exits the program with code EXIT_FAILURE in case of error
 */
int authenticate(void)
{
    log_msg(INFO, "Initiating the authentication process...");
    int ret = -1;
    
    uint8_t parameters[NETWORK_BUFFER_LENGTH];

    /**
     * Structure of the authentication message:
     * - 1st byte: user_id
     * - 2nd byte onwards (MAX_PASSWORD_LENGTH bytes): password, null-terminated
     */

    /* Toy example: assuming 1 character is enough to hold any user id */
    printf("Enter your user id: ");
    ret = fgetc(stdin);
    parameters[0] = ret - '0';

    fgetc(stdin); /* Reads '\\n' */

    printf("Enter your password: ");
    ret = fgetsnn((char *)parameters + 1, MAX_PASSWORD_LENGTH, stdin);

    /* The client always sends the whole MAX_PASSWORD_LENGTH bytes to avoid leaking the password length */
    ret = send_secure_msg(sd, &counter, AUTH_REQUEST, parameters, MAX_PASSWORD_LENGTH + 1, client2server_key);
    CHECK(ret == -1, CRITICAL, 0, "Unable to send the authentication request to the server");

    uint8_t action;
    ret = recv_secure_msg(sd, &counter, &action, NULL, 0, NULL, server2client_key);
    CHECK(ret != 0, CRITICAL, 0, "Unable to receive the authentication response from the server");
    CHECK(action != OK && action != PASSWORD_CHANGE_REQUIRED, CRITICAL, 0, "Authentication failed");

    if (action == OK)
    {
        log_msg(INFO, "Authentication completed");
        return 0;    
    }

    /* Password change required */
    printf("You are required to change your password.\nEnter the new password: ");
    ret = fgetsnn((char *)parameters, MAX_PASSWORD_LENGTH, stdin);

    ret = send_secure_msg(sd, &counter, NEW_PASSWORD, parameters, MAX_PASSWORD_LENGTH, client2server_key);
    CHECK(ret == -1, CRITICAL, 0, "Unable to send the new password to the server");

    ret = recv_secure_msg(sd, &counter, &action, NULL, 0, NULL, server2client_key);
    CHECK(ret != 0, CRITICAL, 0, "Unable to receive the authentication response from the server");
    CHECK(action != OK, CRITICAL, 0, "Password change failed");

    log_msg(INFO, "Authentication completed");
    return 0;
}

/**
 * Front-end for the CMD_CREATE_KEYS command
 */
int create_keys(void)
{
    int ret = -1;

    ret = send_secure_msg(sd, &counter, CMD_CREATE_KEYS, NULL, 0, client2server_key);
    CHECK(ret == -1, ERROR, 0, "Unable to send the CMD_CREATE_KEYS command to the server");

    uint8_t action;
    ret = recv_secure_msg(sd, &counter, &action, NULL, 0, NULL, server2client_key);
    CHECK(ret != 0, ERROR, 0, "Unable to receive the response from the server");
    CHECK(action == TIMED_OUT, CRITICAL, 0, "The session has expired. Please reconnect");

    if (action == KEYS_ALREADY_EXIST)
    {
        printf("You already own a key pair\n");
        return 0;
    }

    if (action == NO_KEYS)
    {
        printf("Offline authentication required\n");
        return 0;
    }

    if (action != OK)
    {
        printf("Something went wrong on the server\n");
        return 0;
    }

    printf("Keys created!\n");
    return 0;
}

/**
 * Front-end for the CMD_SIGN_DOC command
 */
int sign_document(void)
{
    int ret = -1;

    printf("Enter the name of the document to sign: ");
    const int filename_len_max = 128;
    char filename[filename_len_max];
    int filename_len = fgetsnn(filename, filename_len_max - strlen("_signed.bin"), stdin);

    FILE *file = fopen(filename, "rb");
    CHECK(file == NULL, ERROR, errno, "Unable to open %s", filename);

    uint8_t hash[DOCUMENT_HASH_LENGTH];
    ret = compute_hash(hash, file);
    fclose(file);
    CHECK(ret == -1, ERROR, 0, "Unable to compute the hash of %s", filename);    

    ret = send_secure_msg(sd, &counter, CMD_SIGN_DOC, hash, DOCUMENT_HASH_LENGTH, client2server_key);
    CHECK(ret == -1, ERROR, 0, "Unable to send the CMD_SIGN_DOC command to the server");

    uint8_t action;
    uint8_t signature[SIGNATURE_LENGTH_MAX];
    int sig_len;
    ret = recv_secure_msg(sd, &counter, &action, signature, SIGNATURE_LENGTH_MAX, &sig_len, server2client_key);
    CHECK(ret != 0, ERROR, 0, "Unable to receive the response from the server");
    CHECK(action == TIMED_OUT, CRITICAL, 0, "The session has expired. Please reconnect");

    if (action == NO_KEYS)
    {
        printf("You must generate a key pair first\n");
        return 0;
    }
    
    if (action != OK)
    {
        printf("Something went wrong on the server\n");
        return 0;
    }

    /* Remove the file extension */
    int dot_position = filename_len;
    while (dot_position >= 0 && filename[dot_position] != '.')
    {
        dot_position--;
    }
    if (dot_position > 0)
    {
        filename[dot_position] = '\0';
    }

    snprintf(filename, filename_len_max, "%s_signed.bin", filename);

    FILE *signed_file = fopen(filename, "wb");
    CHECK(signed_file == NULL, ERROR, errno, "Unable to open %s", filename);
    
    int written = fwrite(signature, 1, sig_len, signed_file);
    ret = fclose(signed_file);

    CHECK(written != sig_len, ERROR, 0, "Unable to write the signature to %s", filename);
    CHECK(ret != 0, ERROR, errno, "Unable to flush %s to disk", filename);

    printf("Signature saved to %s\n", filename);
    
    return 0;
}

/**
 * Front-end for the CMD_GET_PUBKEY command
 */
int get_public_key(void)
{
    int ret = -1;

    printf("Enter id of the user whose public key you are interested in: ");
    ret = fgetc(stdin);
    uint8_t user_id = ret - '0';

    fgetc(stdin); /* Reads '\\n' */

    ret = send_secure_msg(sd, &counter, CMD_GET_PUBKEY, &user_id, 1, client2server_key);
    CHECK(ret == -1, ERROR, 0, "Unable to send the CMD_GET_PUBKEY command to the server");

    uint8_t action;
    uint8_t requested_key[SIGNATURE_KEY_LENGTH_MAX];
    int key_len;
    ret = recv_secure_msg(sd, &counter, &action, requested_key, SIGNATURE_KEY_LENGTH_MAX, &key_len, server2client_key);
    CHECK(ret != 0, ERROR, 0, "Unable to receive the response from the server");
    CHECK(action == TIMED_OUT, CRITICAL, 0, "The session has expired. Please reconnect");

    if (action == BAD_PARAMETERS)
    {
        printf("The specified user id does not exist\n");
        return 0;
    }
    
    if (action == NO_KEYS)
    {
        printf("The specified user does not own a key pair\n");
        return 0;
    }
    
    if (action != OK)
    {
        printf("Something went wrong on the server\n");
        return 0;
    }

    char filename[64];
    snprintf(filename, sizeof(filename), "public_key_%i.pem", user_id);

    FILE *key_file = fopen(filename, "w");
    CHECK(key_file == NULL, ERROR, errno, "Unable to open %s", filename);

    int written = fwrite(requested_key, 1, key_len, key_file);
    CHECK(written != key_len, ERROR, 0, "Unable to write the key to %s", filename);
    
    ret = fclose(key_file);
    CHECK(ret != 0, ERROR, errno, "Unable to flush %s to disk", filename);

    printf("Public key of user %i saved to %s\n", user_id, filename);
    
    return 0;
}

/**
 * Front-end for the CMD_DELETE_KEYS command
 */
int delete_keys(void)
{
    int ret = -1;    

    ret = send_secure_msg(sd, &counter, CMD_DELETE_KEYS, NULL, 0, client2server_key);
    CHECK(ret == -1, ERROR, 0, "Unable to send the CMD_DELETE_KEYS command to the server");

    uint8_t action;
    ret = recv_secure_msg(sd, &counter, &action, NULL, 0, NULL, server2client_key);
    CHECK(ret != 0, ERROR, 0, "Unable to receive the response from the server");
    CHECK(action == TIMED_OUT, CRITICAL, 0, "The session has expired. Please reconnect");
    
    if (action == NO_KEYS)
    {
        printf("You already deleted your keys\n");
        return 0;
    }
    
    if (action != OK) 
    {
        printf("Something went wrong on the server\n");
        return 0;
    }

    printf("Keys deleted\n");
    return 0;
}

/**
 * Verifies the signature of a document
 */
int verify_signature(void)
{
    int ret = -1;
    const int filename_len_max = 128;
    char filename[filename_len_max];
    
    /* Get the document to verify */

    printf("Enter the name of the document to verify: ");
    fgetsnn(filename, filename_len_max, stdin);

    FILE *document_file = fopen(filename, "rb");
    CHECK(document_file == NULL, ERROR, errno, "Unable to open %s", filename);

    uint8_t hash[DOCUMENT_HASH_LENGTH];
    ret = compute_hash(hash, document_file);
    CHECK_GOTO(ret == -1, ERROR, 0, close_document, "Unable to compute the hash of %s", filename);

    /* Get the signature to verify against */

    printf("Enter the name of the file containing the signature: ");
    fgetsnn(filename, filename_len_max, stdin);

    FILE *signature_file = fopen(filename, "rb");
    CHECK(signature_file == NULL, ERROR, errno, "Unable to open %s", filename);

    fseek(signature_file, 0, SEEK_END);
    long signature_len = ftell(signature_file);
    rewind(signature_file);

    CHECK_GOTO(signature_len > SIGNATURE_LENGTH_MAX, ERROR, 0, close_signature,
        "The length of the selected signature (%i) is greater than the maximum allowed (%i)",
        signature_len, SIGNATURE_LENGTH_MAX);

    uint8_t signature[SIGNATURE_LENGTH_MAX];
    ret = fread(signature, 1, signature_len, signature_file);
    CHECK_GOTO(ret != signature_len, ERROR, 0, close_signature, "Unable to read the signature from %s", filename);

    /* Get the sender's public key */

    printf("Enter the name of the file containing the sender's public key: ");
    fgetsnn(filename, filename_len_max, stdin);

    FILE *pubkey_file = fopen(filename, "rb");
    CHECK(pubkey_file == NULL, ERROR, errno, "Unable to open the specified file");

    fseek(pubkey_file, 0, SEEK_END);
    long pubkey_len = ftell(pubkey_file);
    rewind(pubkey_file);
    
    CHECK_GOTO(pubkey_len > SIGNATURE_KEY_LENGTH_MAX, ERROR, 0, close_key, 
        "The length of the selected key (%i) is greater than the maximum allowed (%i)",
        pubkey_len, SIGNATURE_KEY_LENGTH_MAX);

    uint8_t pubkey_data[SIGNATURE_KEY_LENGTH_MAX];
    ret = fread(pubkey_data, 1, pubkey_len, pubkey_file);
    CHECK_GOTO(ret != pubkey_len, ERROR, 0, close_key, "Unable to read the public key from %s", filename);
    
    EVP_PKEY *pubkey = NULL;
    ret = deserialize_ECDSA_pubkey(pubkey_data, pubkey_len, &pubkey);
    CHECK(ret == -1, ERROR, 0, "Unable to deserialize the public key");

    /* Verify the signature */

    ret = verify(hash, DOCUMENT_HASH_LENGTH, pubkey, signature, signature_len);
    if (ret == -1)
    {
        printf("The signature is NOT valid (or something went wrong)!\n");
    }
    else 
    {
        printf("The signature is valid!\n");
    }

    ret = 0;
    
    EVP_PKEY_free(pubkey);
close_key:
    fclose(pubkey_file);
close_signature:
    fclose(signature_file);
close_document:
    fclose(document_file);

    return ret;
}

void print_commands(void)
{
    printf("\nThe available commands are:\n");
    printf(" 0) Exit\n");
    printf(" 1) Create the keys\n");
    printf(" 2) Sign a document\n");
    printf(" 3) Get the public key of any user\n");
    printf(" 4) Delete the keys\n");
    printf(" 5) Verify a signature\n");
    printf(" 9) Print the list of commands again\n");
}

int main(void)
{
    printf("\n########################### DIGITAL SIGNATURE CLIENT ###########################\n\n");    

    load_server_signature_pubkey();
    connect_to_server();
    handshake();
    authenticate();
    print_commands();

    while(1)
    {
        printf("\n > ");
        int choice = fgetc(stdin);
        choice -= '0';

        fgetc(stdin); /* Reads '\\n' */

        switch (choice)
        {
            case 0:
                printf("Bye!\n");
                exit(EXIT_SUCCESS);
                break;
            case 1:
                create_keys();
                break;
            case 2:
                sign_document();
                break;
            case 3:
                get_public_key();
                break;
            case 4:
                delete_keys();
                break;
            case 5:
                verify_signature();
                break;
            case 9:
                print_commands();
                break;
            default:
                printf("Invalid choice\n");
                break;
        }
    }

    return 0;
}
