
/**
 * The server's private-public keypair was generated using the following openssl commands:
 * openssl genpkey -algorithm EC -pkeyopt ec_paramgen_curve:P-256 -aes128 -out server_encrypted_signature_privkey.pem
 * openssl pkey -in server_encrypted_signature_privkey.pem -pubout -out server_signature_pubkey.pem
 * 
 * The password of the private key is "server"
 */

#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>

#include <openssl/evp.h>
#include <openssl/pem.h>

#include "security.h"
#include "common.h"
#include "database.h"

#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <errno.h>
#include <time.h>

/* 
 * Maximum number of incoming connections (i.e., waiting
 *  for "accept") that the system is able to handle
 */
#define LISTEN_SOCKET_QUEUE_LENGTH 128

extern struct User *users[USERS];
extern struct Session *sessions[MAX_SESSIONS];

EVP_PKEY *server_signature_privkey = NULL;

/**
 * Loads the server's private key for digital signatures.
 * Exits the program with code EXIT_FAILURE in case of error
 */
int load_server_signature_privkey(void)
{
    log_msg(INFO, "Loading server_encrypted_signature_privkey.pem...");
    
    FILE *fp = fopen("server_encrypted_signature_privkey.pem", "r");
    CHECK(fp == NULL, CRITICAL, 0, "Unable to open the server's encrypted private key pem file");

    server_signature_privkey = PEM_read_PrivateKey(fp, NULL, NULL, NULL);
    fclose(fp);
    CHECK(server_signature_privkey == NULL, CRITICAL, 0, 
        "Unable to parse the server's encrypted private key pem file");
    CHECK(EVP_PKEY_size(server_signature_privkey) > SIGNATURE_LENGTH_MAX, CRITICAL, 0, 
        "SIGNATURE_LENGTH_MAX (%i) is too small for the specified key (%i)",
        SIGNATURE_LENGTH_MAX, EVP_PKEY_size(server_signature_privkey));

    log_msg(INFO, "Successfully loaded the server's private key");
    return 0;
}

/**
 * Accepts a new connection on the given socket.
 * Returns the socket for communicating with the client,
 *  or -1 in case of error
 */ 
int accept_connection(int sd) 
{
    struct sockaddr_in client_addr;
    socklen_t client_len = sizeof(client_addr);
    int new_sd = accept(sd, (struct sockaddr*)&client_addr, &client_len);
    CHECK(new_sd == -1, WARNING, errno, "Unable to accept an incoming connection");

    char client_ip[INET_ADDRSTRLEN];
    const char* ret = inet_ntop(AF_INET, (void *)&client_addr.sin_addr, client_ip, INET_ADDRSTRLEN);
    CHECK(ret == NULL, ERROR, errno, "Unable to get the client's IP");
    
    int client_port = ntohs(client_addr.sin_port);

    log_msg(INFO, "Client %s:%i connected using socket %i", client_ip, client_port, new_sd);  

    return new_sd;
}

/**
 * Estabilishes a secure channel with the client.
 * "server2client_key" and "client2server_key" must be 
 *  large enough to hold AEAD_KEY_LENGTH bytes each.
 * Returns 0 on success, -1 on failure
 */
int handshake(int sd, uint8_t *server2client_key, uint8_t *client2server_key)
{
    int ret = -1;

    int handshake_len = ECDHE_KEY_LENGTH + ECDHE_NONCE_LENGTH + ECDHE_KEY_LENGTH + ECDHE_NONCE_LENGTH;
    CHECK(handshake_len > NETWORK_BUFFER_LENGTH, ERROR, 0, 
        "NETWORK_BUFFER_LENGTH (%i) is too small for the handshake (%i)", NETWORK_BUFFER_LENGTH, handshake_len);

    uint8_t network_buffer[NETWORK_BUFFER_LENGTH];
    uint8_t *server_pubkey = network_buffer;
    uint8_t *server_nonce  = network_buffer + ECDHE_KEY_LENGTH;
    uint8_t *client_pubkey = network_buffer + ECDHE_KEY_LENGTH + ECDHE_NONCE_LENGTH;
    uint8_t *client_nonce  = network_buffer + ECDHE_KEY_LENGTH + ECDHE_NONCE_LENGTH + ECDHE_KEY_LENGTH;

    /* Generate the ECDHE key pair */
    EVP_PKEY *server_keypair = NULL;
    ret = generate_ECDHE_keypair(&server_keypair);
    CHECK(ret == -1, ERROR, 0, "Unable to generate the ECDHE key pair");

    ret = serialize_ECDHE_pubkey(server_keypair, server_pubkey);
    CHECK_GOTO(ret == -1, ERROR, 0, free_server_keys, "Unable to extract the ECDHE raw public key");

    log_msg(DEBUG, "Generated the ECDHE public key (length = %i):", ECDHE_KEY_LENGTH);
    debug_bytes(server_pubkey, ECDHE_KEY_LENGTH);
    
    /* Generate the nonce */
    ret = generate_nonce(server_nonce, ECDHE_NONCE_LENGTH);
    CHECK_GOTO(ret == -1, ERROR, 0, free_server_keys, "Unable to generate the nonce");
    
    log_msg(DEBUG, "Generated the nonce (length = %i):", ECDHE_NONCE_LENGTH);
    debug_bytes(server_nonce, ECDHE_NONCE_LENGTH);
    
    /* Receive client's ECDHE public key */
    ret = recv_msg_known_len(sd, client_pubkey, ECDHE_KEY_LENGTH);
    CHECK_GOTO(ret == -1, WARNING, 0, free_server_keys, "Unable to receive client's ECDHE public key");
    CHECK_GOTO(ret == 1, WARNING, 0, free_server_keys, "Client unexpectedly disconnected");
    
    log_msg(DEBUG, "Received client's ECDHE public key (length = %i):", ECDHE_KEY_LENGTH);
    debug_bytes(client_pubkey, ECDHE_KEY_LENGTH);
    
    /* Receive client's nonce */
    ret = recv_msg_known_len(sd, client_nonce, ECDHE_NONCE_LENGTH);
    CHECK_GOTO(ret == -1, WARNING, 0, free_server_keys, "Unable to receive client's nonce");
    CHECK_GOTO(ret == 1, WARNING, 0, free_server_keys, "Client unexpectedly disconnected");
    
    log_msg(DEBUG, "Received client's nonce (length = %i):", ECDHE_NONCE_LENGTH);
    debug_bytes(client_nonce, ECDHE_NONCE_LENGTH);

    /* Send server's ECDHE public key to the client */
    ret = send_msg(sd, server_pubkey, ECDHE_KEY_LENGTH);
    CHECK_GOTO(ret == -1, WARNING, 0, free_server_keys, "Unable to send the ECDHE public key to the client");
    log_msg(DEBUG, "Sent the ECDHE public key");

    /* Send server's nonce to the client */
    ret = send_msg(sd, server_nonce, ECDHE_NONCE_LENGTH);
    CHECK_GOTO(ret == -1, WARNING, 0, free_server_keys, "Unable to send the nonce to the client");
    log_msg(DEBUG, "Sent the nonce");

    /* Sign the handshake */
    int sig_len;
    uint8_t signature[SIGNATURE_LENGTH_MAX];
    ret = sign(network_buffer, handshake_len, server_signature_privkey, signature, &sig_len);
    CHECK_GOTO(ret == -1, ERROR, 0, free_server_keys, "Unable to sign the handshake");

    log_msg(DEBUG, "Handshake buffer (length = %i):", handshake_len);
    debug_bytes(network_buffer, handshake_len);

    log_msg(DEBUG, "Generated the signature of the handshake (length = %i):", sig_len);
    debug_bytes(signature, sig_len);

    /* Send the signature of the handshake to the client */
    ret = send_msg(sd, signature, sig_len);
    CHECK_GOTO(ret == -1, WARNING, 0, free_server_keys, "Unable to send the signature of the handshake to the client");
    log_msg(DEBUG, "Sent the signature of the handshake");

    /* De-serialize client's pubkey */
    EVP_PKEY *client_keypair = NULL;
    ret = deserialize_ECDHE_pubkey(client_pubkey, &client_keypair);
    CHECK_GOTO(ret == -1, WARNING, 0, free_server_keys, "Unable to de-serialize the client's pubkey");

    /* Derive the ECDHE master secret */
    uint8_t master_secret[MASTER_SECRET_LENGTH];
    ret = derive_ECDHE_master_secret(server_keypair, client_keypair, master_secret);
    CHECK_GOTO(ret == -1, WARNING, 0, free_all, "Unable to derive the master secret");

    log_msg(DEBUG, "Derived the master secret (length = %i):", MASTER_SECRET_LENGTH);
    debug_bytes(master_secret, MASTER_SECRET_LENGTH);

    ret = derive_AEAD_keys(master_secret, server_nonce, client_nonce, server2client_key, client2server_key);
    CHECK_GOTO(ret == -1, ERROR, 0, free_all, "Unable to derive the AEAD keys");

    log_msg(DEBUG, "Derived the AEAD server -> client key (length = %i):", AEAD_KEY_LENGTH);
    debug_bytes(server2client_key, AEAD_KEY_LENGTH);

    log_msg(DEBUG, "Derived the AEAD client -> server key (length = %i):", AEAD_KEY_LENGTH);
    debug_bytes(client2server_key, AEAD_KEY_LENGTH);

    ret = 0;
    log_msg(INFO, "Handshake with socket %i completed", sd);

free_all:
    EVP_PKEY_free(client_keypair);
free_server_keys:
    EVP_PKEY_free(server_keypair);

    return ret;
}

/**
 * Authenticates the client to the server by means of the couple (user_id, password).
 * Returns 0 on success, -1 on failure
 */
int authenticate
(
    int sd,
    const uint8_t *server2client_key,
    const uint8_t *client2server_key,
    uint8_t *user_id,
    char *plaintext_password,
    union Counter *counter
)
{
    int ret = -1;

    uint8_t action;
    uint8_t parameters[NETWORK_BUFFER_LENGTH];
    int parameters_len;
    
    /**
     * Structure of the authentication parameters:
     * - 1st byte: user_id
     * - 2nd byte onwards (MAX_PASSWORD_LENGTH bytes): password, null-terminated
     */

    ret = recv_secure_msg(sd, counter, &action, parameters, NETWORK_BUFFER_LENGTH, &parameters_len, client2server_key);
    CHECK(ret == -1, WARNING, 0, "Unable to receive the authentication message from the client");
    CHECK(ret == 1, WARNING, 0, "Client unexpectedly disconnected");
    CHECK(action != AUTH_REQUEST, WARNING, 0, "Received an unexpected command from the client");
    CHECK(parameters_len != 1 + MAX_PASSWORD_LENGTH, WARNING, 0, 
        "Authentication parameter length mismatch, expected %i, got %i", 
        1 + MAX_PASSWORD_LENGTH, parameters_len);

    *user_id = parameters[0];
    if (*user_id < 0 || *user_id >= USERS || users[*user_id] == NULL)
    {
        log_msg(WARNING, "Client on socket %i provided an invalid user id %i", sd, *user_id);
        ret = send_secure_msg(sd, counter, BAD_PARAMETERS, NULL, 0, server2client_key);
        CHECK(ret == -1, WARNING, 0, "Unable to respond to the client");
        return -1;
    }

    struct User *user = users[*user_id];

    char *password = (char *)parameters + 1;
    int password_len = 0;
    while (password_len < MAX_PASSWORD_LENGTH && password[password_len] != '\0')
    {
        password_len++;
    }
    CHECK(password_len == MAX_PASSWORD_LENGTH, WARNING, 0, "The password provided by the client is not null-terminated");

    ret = verify_password(user->hashed_password, password, password_len);
    if (ret != 0)
    {
        log_msg(WARNING, "Client on socket %i provided an invalid password for user %i", sd, *user_id);
        ret = send_secure_msg(sd, counter, BAD_PARAMETERS, NULL, 0, server2client_key);
        CHECK(ret == -1, WARNING, 0, "Unable to respond to the client");
        return -1;
    }

    if (user->status != WAITING_FOR_FIRST_LOGIN)
    {
        memcpy(plaintext_password, password, password_len + 1);

        ret = send_secure_msg(sd, counter, OK, NULL, 0, server2client_key);
        CHECK(ret == -1, WARNING, 0, "Unable to respond to the client");
        log_msg(INFO, "User %i succesfully authenticated through socket %i", *user_id, sd);
        return 0;
    }
    
    ret = send_secure_msg(sd, counter, PASSWORD_CHANGE_REQUIRED, NULL, 0, server2client_key);
    CHECK(ret == -1, WARNING, 0, "Unable to respond to the client");
    log_msg(INFO, "User %i succesfully authenticated through socket %i, but is required to change its password", *user_id, sd);

    ret = recv_secure_msg(sd, counter, &action, parameters, NETWORK_BUFFER_LENGTH, &parameters_len, client2server_key);
    CHECK(ret == -1, WARNING, 0, "Unable to receive the new password from the client");
    CHECK(ret == 1, WARNING, 0, "Client unexpectedly disconnected");
    CHECK(action != NEW_PASSWORD, WARNING, 0, "Received an unexpected command from the client");
    CHECK(parameters_len != MAX_PASSWORD_LENGTH, WARNING, 0, 
        "Password change parameter length mismatch, expected %i, got %i",
        MAX_PASSWORD_LENGTH, parameters_len);

    password = (char *)parameters;
    password_len = 0;
    while (password_len < MAX_PASSWORD_LENGTH && password[password_len] != '\0')
    {
        password_len++;
    }
    CHECK(password_len == MAX_PASSWORD_LENGTH, WARNING, 0, "The password provided by the client is not null-terminated");

    ret = hash_password(user->hashed_password, password, password_len);
    CHECK(ret == -1, ERROR, 0, "Unable to hash the password of user %i", user_id);
    
    user->status = OPERATIONAL;
    log_msg(INFO, "User %i succesfully changed its password", *user_id);
    
    ret = send_secure_msg(sd, counter, OK, NULL, 0, server2client_key);
    CHECK(ret == -1, WARNING, 0, "Unable to respond to the client");
    
    return 0;
}

/**
 * Creates a session for the authenticated user.
 * Returns 0 on success, -1 on failure
 */
int create_session
(
    int sd,
    const uint8_t *server2client_key, 
    const uint8_t *client2server_key, 
    uint8_t user_id, 
    const char *plaintext_password,
    union Counter counter
)
{
    sessions[sd] = malloc(sizeof(struct Session));
    CHECK(sessions[sd] == NULL, ERROR, errno, "Unable to allocate memory for session %i", sd);
    
    sessions[sd]->user_id = user_id;
    memcpy(sessions[sd]->plaintext_password, plaintext_password, MAX_PASSWORD_LENGTH);
    memcpy(sessions[sd]->server2client_key, server2client_key, AEAD_KEY_LENGTH);
    memcpy(sessions[sd]->client2server_key, client2server_key, AEAD_KEY_LENGTH);
    sessions[sd]->creation_time = time(NULL);
    sessions[sd]->counter.count = counter.count;

    log_msg(INFO, "Session %i created for user %i", sd, user_id);
    return 0;
}

/**
 * Creates the public and private keys for the calling user.
 * Returns 0 on success, -1 on failure
 */
int create_keys(int sd)
{
    int ret = -1;

    struct Session *session = sessions[sd];
    struct User *user = users[session->user_id];
    union Counter *counter = &session->counter;

    if (user->public_key_len != 0 && user->encrypted_private_key_len != 0)
    {
        log_msg(INFO, "CMD_CREATE_KEYS: the user already owns a keypair");
        ret = send_secure_msg(sd, counter, KEYS_ALREADY_EXIST, NULL, 0, session->server2client_key);
        CHECK(ret == -1, WARNING, 0, "Unable to respond to the client");
        return 0;
    }

    if (user->status == REQUIRES_OFFLINE_REGISTRATION)
    {
        log_msg(INFO, "CMD_CREATE_KEYS: the user requires offline registration");
        ret = send_secure_msg(sd, counter, NO_KEYS, NULL, 0, session->server2client_key);
        CHECK(ret == -1, WARNING, 0, "Unable to respond to the client");
        return 0;   
    }

    EVP_PKEY *keypair = NULL;
    ret = generate_ECDSA_keypair(&keypair);
    CHECK(ret == -1, ERROR, 0, "Unable to generate an ECDSA keypair");

    /* These operations must be atomic! Otherwise an user could end with no public key */
    int ret1 = serialize_ECDSA_privkey(keypair, user->encrypted_private_key, 
        &user->encrypted_private_key_len, session->plaintext_password);
    int ret2 = serialize_ECDSA_pubkey(keypair, user->public_key, &user->public_key_len);
    
    EVP_PKEY_free(keypair);

    CHECK_GOTO(ret1 == -1, ERROR, 0, restore_keys, "Unable to serialize the ECDSA private key");
    CHECK_GOTO(ret2 == -1, ERROR, 0, restore_keys, "Unable to serialize the ECDSA public key");

    log_msg(DEBUG, "Generated private ECDSA key (length = %i):", user->encrypted_private_key_len);
    debug_bytes(user->encrypted_private_key, user->encrypted_private_key_len);

    log_msg(DEBUG, "Generated public ECDSA key (length = %i):", user->public_key_len);
    debug_bytes(user->public_key, user->public_key_len);

    ret = send_secure_msg(sd, counter, OK, NULL, 0, session->server2client_key);
    CHECK(ret == -1, WARNING, 0, "Unable to respond to the client");

    log_msg(INFO, "CMD_CREATE_KEYS completed successfully");
    return 0;

restore_keys:
    user->encrypted_private_key_len = 0;
    user->public_key_len = 0;
    return -1;
}

/**
 * Signs a document on behalf of the calling user.
 * Returns 0 on success, -1 on failure
 */
int sign_document(int sd, const uint8_t *document, int document_len)
{
    int ret = -1;

    struct Session *session = sessions[sd];
    struct User *user = users[session->user_id];
    union Counter *counter = &session->counter;

    if (user->encrypted_private_key_len == 0)
    {
        log_msg(INFO, "CMD_SIGN_DOC: the user has no private key");
        ret = send_secure_msg(sd, counter, NO_KEYS, NULL, 0, session->server2client_key);
        CHECK(ret == -1, WARNING, 0, "Unable to respond to the client");
        return 0;
    }

    EVP_PKEY *privkey = NULL;
    ret = deserialize_ECDSA_privkey(user->encrypted_private_key, 
        user->encrypted_private_key_len, session->plaintext_password, &privkey);
    CHECK(ret == -1, ERROR, 0, "Unable to deserialize the ECDSA private key");

    uint8_t signature[SIGNATURE_LENGTH_MAX];
    int signature_len;

    ret = sign(document, document_len, privkey, signature, &signature_len);
    EVP_PKEY_free(privkey);
    CHECK(ret == -1, ERROR, 0, "Unable to sign the document");

    ret = send_secure_msg(sd, counter, OK, signature, signature_len, session->server2client_key);
    CHECK(ret == -1, WARNING, 0, "Unable to send the signature to the client");

    log_msg(INFO, "CMD_SIGN_DOC completed successfully");
    return 0;
}

/**
 * Fetches the public key of the specified user.
 * Returns 0 on success, -1 on failure
 */
int get_public_key(int sd, uint8_t user_id)
{
    int ret = -1;

    struct Session *session = sessions[sd];
    struct User *user = users[user_id];
    union Counter *counter = &session->counter;

    if (user->public_key_len == 0)
    {
        log_msg(INFO, "CMD_GET_PUBKEY: selected user %i has no public key", user_id);
        ret = send_secure_msg(sd, counter, NO_KEYS, NULL, 0, session->server2client_key);
        CHECK(ret == -1, WARNING, 0, "Unable to respond to the client");
        return 0;
    }

    ret = send_secure_msg(sd, counter, OK, user->public_key, user->public_key_len, session->server2client_key);
    CHECK(ret == -1, WARNING, 0, "Unable to respond to the client");

    log_msg(INFO, "CMD_GET_PUBKEY completed successfully");
    return 0;
}

/**
 * Deletes the signing keys of the calling user.
 * Returns 0 on success, -1 on failure
 */
int delete_keys(int sd)
{
    int ret = -1;    

    struct Session *session = sessions[sd];
    struct User *user = users[session->user_id];
    union Counter *counter = &session->counter;

    if (user->status == REQUIRES_OFFLINE_REGISTRATION)
    {
        log_msg(INFO, "CMD_DELETE_KEYS: the user already deleted his keys");
        ret = send_secure_msg(sd, counter, NO_KEYS, NULL, 0, session->server2client_key);
        CHECK(ret == -1, WARNING, 0, "Unable to respond to the client");
        return 0;
    }

    /**
     * If there are no keys to delete, the user might still want to 
     *  call CMD_DELETE_KEYS to force a new offline registration
     * (for example, in case he knows his password got compromised)
     */

    memset(user->encrypted_private_key, 0, SIGNATURE_KEY_LENGTH_MAX);
    user->encrypted_private_key_len = 0;
    memset(user->public_key, 0, SIGNATURE_KEY_LENGTH_MAX);
    user->public_key_len = 0;

    user->status = REQUIRES_OFFLINE_REGISTRATION;

    ret = send_secure_msg(sd, counter, OK, NULL, 0, session->server2client_key);
    CHECK(ret == -1, WARNING, 0, "Unable to respond to the client");

    log_msg(INFO, "CMD_DELETE_KEYS completed successfully");
    return 0;
}

/**
 * Receives, parses and executes a command from the specified socket.
 * Returns 0 on success, -1 on failure
 */
int recv_command(int sd)
{
    int ret = -1;

    struct Session *session = sessions[sd];
    union Counter *counter = &session->counter;

    uint8_t action;
    uint8_t parameters[NETWORK_BUFFER_LENGTH];
    int parameters_len;

    ret = recv_secure_msg(sd, counter, &action, parameters, NETWORK_BUFFER_LENGTH, &parameters_len, session->client2server_key);
    CHECK(ret == -1, WARNING, 0, "Unable to read the received command from user %i", session->user_id);
    if (ret == 1)
    {
        return 1;
    }

    /* The command is always the first byte of the message */
    switch (action)
    {
        case CMD_CREATE_KEYS:
            /* No arguments required */
            log_msg(INFO, "User %i issued the CMD_CREATE_KEYS command", session->user_id);
            CHECK_GOTO(parameters_len != 0, WARNING, 0, bad_parameters, "CMD_CREATE_KEYS received unexpected parameters");
            return create_keys(sd);

        case CMD_SIGN_DOC:
            /* The document to sign is contained in the parameters */
            log_msg(INFO, "User %i issued the CMD_SIGN_DOC command", session->user_id);
            CHECK_GOTO(parameters_len == 0, WARNING, 0, bad_parameters, "CMD_SIGN_DOC received an empty document");
            return sign_document(sd, parameters, parameters_len);

        case CMD_GET_PUBKEY:
            /* The only parameter should be an user id */
            log_msg(INFO, "User %i issued the CMD_GET_PUBKEY command", session->user_id);
            CHECK_GOTO(parameters_len != 1, WARNING, 0, bad_parameters, "CMD_GET_PUBKEY received unexpected parameters");
            uint8_t user_id = parameters[0];
            CHECK_GOTO(user_id < 0 || user_id >= USERS || users[user_id] == NULL,
                WARNING, 0, bad_parameters, "CMD_GET_PUBKEY: selected user (%i) does not exist", user_id);
            return get_public_key(sd, user_id);

        case CMD_DELETE_KEYS:
            /* No arguments required */
            log_msg(INFO, "User %i issued the CMD_DELETE_KEYS command", session->user_id);
            CHECK_GOTO(parameters_len != 0, WARNING, 0, bad_parameters, "CMD_DELETE_KEYS received unexpected parameters");
            return delete_keys(sd);
    }

    log_msg(WARNING, "User %i tried to issue an unknown command %i", session->user_id, action);

    ret = send_secure_msg(sd, counter, BAD_CMD, NULL, 0, session->server2client_key);
    CHECK(ret == -1, WARNING, 0, "Unable to respond to the client");
    return 0;

bad_parameters:
    ret = send_secure_msg(sd, counter, BAD_PARAMETERS, NULL, 0, session->server2client_key);
    CHECK(ret == -1, WARNING, 0, "Unable to respond to the client");
    return 0;
}

int main(void)
{
    printf("\n########################### DIGITAL SIGNATURE SERVER ###########################\n\n");

    int ret = -1;

    ret = sodium_init();
    CHECK(ret == -1, CRITICAL, 0, "Unable to initialize libsodium");
    log_msg(INFO, "Crypto libraries initialized");

    load_server_signature_privkey();

    populate_database();

    /* Create the socket which listens for new connections (blocking type) */
    int listener = socket(AF_INET, SOCK_STREAM, 0);
    CHECK(listener == -1, CRITICAL, errno, "Unable to create the listener socket");
    
    /* Define the listener socket's configuration */
    struct sockaddr_in server_addr;  
    memset(&server_addr, 0, sizeof(server_addr));
    server_addr.sin_family = AF_INET;
    server_addr.sin_port = htons(SERVER_PORT);
    server_addr.sin_addr.s_addr = INADDR_ANY;

    /* Apply the defined configuration to the listener socket */
    ret = bind(listener, (struct sockaddr*)&server_addr, sizeof(server_addr));
    CHECK(ret == -1, CRITICAL, errno, "Unable to bind the listener socket");

    /* Define the socket as passive (listener) */
    ret = listen(listener, LISTEN_SOCKET_QUEUE_LENGTH);
    CHECK(ret == -1, CRITICAL, errno, "Unable to define the listener socket as passive");

    /**
     * IO multiplexing technique to handle communications with more than one client at a time.
     * WARNING: the number of concurrent communications that the system is able to handle corresponds
     *  to the maximum number of file descriptors allocated to a single process (1024 in most cases).
     *  If performance is required, consider using epoll() insted of select(), multiple threads and
     *  non-blocking sockets.
     */
    fd_set master_read, read_fds;
    FD_ZERO(&master_read);
    FD_ZERO(&read_fds);
    FD_SET(listener, &master_read);

    int sd_max = listener;

    log_msg(INFO, "Server listening on port %i", SERVER_PORT);

    while(1) 
    {
        // sd: Socket Descriptor
        int sd;
        read_fds = master_read;

        /* No timeout (the server waits indefinitely) */
        select(sd_max + 1, &read_fds, NULL, NULL, NULL);

        for (sd = 0; sd <= sd_max; sd++) 
        {
            /* Socket does not exist or is not ready for reading  */
            if (!FD_ISSET(sd, &read_fds)) 
            {
                continue;
            }

            /* The connection socket received some bytes */
            else if (sd == listener) 
            {
                int new_sd = accept_connection(sd);
                if (new_sd == -1) 
                {
                    continue;
                }

                FD_SET(new_sd, &master_read);
                if (new_sd > sd_max)
                {
                    sd_max = new_sd;
                }
            }

            /* A communication socket received some bytes */
            else 
            {
                if (sessions[sd] == NULL)
                {
                    uint8_t server2client_key[AEAD_KEY_LENGTH];
                    uint8_t client2server_key[AEAD_KEY_LENGTH];

                    ret = handshake(sd, server2client_key, client2server_key);
                    CHECK_GOTO(ret == -1, WARNING, 0, free_socket, "Handshake with socket %i failed", sd);

                    uint8_t user_id;
                    char plaintext_password[MAX_PASSWORD_LENGTH];
                    union Counter counter = {0};

                    ret = authenticate(sd, server2client_key, client2server_key, &user_id, plaintext_password, &counter);
                    CHECK_GOTO(ret == -1, WARNING, 0, free_socket, "Unable to authenticate the client on socket %i", sd);

                    ret = create_session(sd, server2client_key, client2server_key, user_id, plaintext_password, counter);
                    CHECK_GOTO(ret == -1, WARNING, 0, free_socket, "Unable to create a session for user %i", user_id);
                }
                else 
                {
                    if (sessions[sd]->creation_time + SESSION_TIMEOUT_SECONDS < time(NULL))
                    {
                        log_msg(INFO, "Session %i timed out", sd);
                        
                        /**
                         * The command sent by the client is ignored and the server immediately responds with
                         *  a TIMED_OUT message. The counter must be incremented to simulate the reception of the 
                         *  client's command.
                         */
                        sessions[sd]->counter.count++;
                        
                        send_secure_msg(sd, &sessions[sd]->counter, TIMED_OUT, NULL, 0, sessions[sd]->server2client_key);
                        /* If the function above fails we would go anyway to free_all */
                        goto free_all;
                    }
                    
                    ret = recv_command(sd);
                    CHECK_GOTO(ret == -1, WARNING, 0, free_all, "Failed to receive, parse or execute a command from socket %i", sd);
                    if (ret == 1)
                    {
                        log_msg(INFO, "User %i disconnected from socket %i", sessions[sd]->user_id, sd);
                        goto free_all;
                    }
                }
                
                continue;

                /**
                 * If anything goes wrong (or the client disconnected),
                 *  close the connection and free the resources
                 */
            free_all:
                /* Explicitly zero the session memory */
                memset(sessions[sd], 0, sizeof(struct Session));
                free(sessions[sd]);
                sessions[sd] = NULL;
                log_msg(INFO, "Session %i closed", sd);
            free_socket:
                FD_CLR(sd, &master_read);
                close(sd);
                log_msg(INFO, "Socket %i closed", sd);
            }
        }
    }
    
    return 0;
}
