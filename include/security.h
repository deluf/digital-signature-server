
#ifndef SECURITY_H
#define SECURITY_H

#include <stdint.h>
#include <openssl/evp.h>

#define ECDHE_KEY_LENGTH            32  /* ECDHE - X25519 curve */
#define ECDHE_NONCE_LENGTH          16
#define MASTER_SECRET_LENGTH        ECDHE_KEY_LENGTH

/* In ECDSA - ANSI X9.62 Prime 256v1 curve - signatures do not have a fixed size */
#define SIGNATURE_LENGTH_MAX        72

/* PEM-serialized, possibly encrypted, ECDSA - ANSI X9.62 Prime 256v1 curve - key */
#define SIGNATURE_KEY_LENGTH_MAX    NETWORK_BUFFER_LENGTH

#define AEAD_KEY_LENGTH             16  /* AES-128-GCM */
#define AEAD_TAG_LENGTH             16  /* AES-128-GCM */
#define AEAD_IV_LENGTH              12  /* AES-128-GCM */

#define HASHED_PASSWORD_LENGTH      crypto_pwhash_STRBYTES

#define DOCUMENT_HASH_LENGTH        32  /* SHA256 */

/**
 * Used as authenticated nonce in the secure (AEAD) messages.
 * Must be unique to each session and initialized to zero,
 *  then everything is handled by the send_secure_msg() and
 *  recv_secure_msg() functions
 */ 
union Counter 
{
    uint32_t count;
    uint8_t bytes[4];
};

/**
 * Computes the hash of the given file.
 * "hash" must be large enough to hold DOCUMENT_HASH_LENGTH bytes.
 * Returns 0 on success, -1 on failure
 */
int compute_hash(uint8_t *hash, FILE *file);

/**
 * Generates a random nonce.
 * "nonce" must be large enough to hold len bytes.
 * Returns 0 on success, -1 on failure
 */
int generate_nonce(uint8_t *nonce, int len);

/**
 * Generates an ECDHE key pair using the X25519 curve.
 * Returns 0 on success, -1 on failure.
 * WARNING: It's the caller's responsibility to free the keypair with EVP_PKEY_free(key_pair);
 */
int generate_ECDHE_keypair(EVP_PKEY **keypair);

/**
 * Serializes the public key of the given ECDHE key pair. 
 * "raw_pubkey" must be large enough to hold ECDHE_KEY_LENGTH bytes.
 * Returns 0 on success, -1 on failure
 */
int serialize_ECDHE_pubkey(const EVP_PKEY *keypair, uint8_t *raw_pubkey);

/**
 * Deserializes the raw ECDHE public key into an EVP_PKEY object.
 * Returns 0 on success, -1 on failure.
 * WARNING: It's the caller's responsibility to free the pubkey with EVP_PKEY_free(key_pair);
 */
int deserialize_ECDHE_pubkey(const uint8_t *raw_pubkey, EVP_PKEY **pubkey);

/**
 * Generates an ECDSA key pair using the ANSI X9.62 Prime 256v1 curve.
 * Returns 0 on success, -1 on failure.
 * WARNING: It's the caller's responsibility to free the keypair with EVP_PKEY_free(key_pair);
 */
int generate_ECDSA_keypair(EVP_PKEY **keypair);

/**
 * Serializes the private key of the given ECDSA key pair in encrypted form.
 * "password" must be a null-terminated string.
 * Returns 0 on success, -1 on failure
 */
int serialize_ECDSA_privkey(const EVP_PKEY *keypair, uint8_t *raw_privkey, int *raw_privkey_len, const char *password);

/**
 * Serializes the public key of the given ECDSA key pair. 
 * Returns 0 on success, -1 on failure
 */
int serialize_ECDSA_pubkey(const EVP_PKEY *keypair, uint8_t *raw_pubkey, int *raw_pubkey_len);

/**
 * Deserializes the raw ECDSA private key into an EVP_PKEY object.
 * "password" must be a null-terminated string.
 * Returns 0 on success, -1 on failure.
 * WARNING: It's the caller's responsibility to free the key with EVP_PKEY_free(key);
 */
int deserialize_ECDSA_privkey(const uint8_t *raw_privkey, int raw_privkey_len, const char *password, EVP_PKEY **key);

/**
 * Deserializes the raw ECDSA public key into an EVP_PKEY object.
 * Returns 0 on success, -1 on failure.
 * WARNING: It's the caller's responsibility to free the key with EVP_PKEY_free(key);
 */
int deserialize_ECDSA_pubkey(const uint8_t *raw_pubkey, int raw_pubkey_len, EVP_PKEY **key);

/**
 * Derives the ECDHE master secret from the given private key and the peer's public key.
 * "secret" must be large enough to hold ECDHE_KEY_LENGTH bytes.
 * Returns 0 on success, -1 on failure
 */
int derive_ECDHE_master_secret(const EVP_PKEY *private_key, const EVP_PKEY *peer_pubkey, uint8_t *secret);

/**
 * Derives the AEAD keys from the master secret.
 * "server2client_key" and "client2server_key" must be 
 *  large enough to hold AEAD_KEY_LENGTH bytes each.
 * Returns 0 on success, -1 on failure
 */
int derive_AEAD_keys
(
    const uint8_t *master_secret,
    const uint8_t *server_nonce,
    const uint8_t *client_nonce,
    uint8_t *server2client_key,
    uint8_t *client2server_key
);

/**
 * Signs the message by means of the given private key.
 * "signature" must be large enough to hold SIGNATURE_LENGTH_MAX bytes.
 * Rerturns 0 on success, -1 on failure
 */
int sign(const uint8_t *msg, int msg_len, const EVP_PKEY *privkey, uint8_t *signature, int *sig_len);

/**
 * Verifies the signature of the message by means of the given public key.
 * Returns 0 if the signature matches, -1 if not (or something goes wrong)
 */
int verify(const uint8_t *message, int msg_len, const EVP_PKEY *pubkey, const uint8_t *signature, int sig_len);

/**
 * Sends an AEAD message through the given socket.
 * In particular, it sends:
 * - IV,  plaintext
 * - tag, plaintext
 * - aad, authenticated plaintext (optional if set to NULL)
 * - msg, authenticated and encrypted
 * _ex stands for "EXtended": gives more control on the sent message.
 * Returns 0 on success, -1 on failure
 */
int send_secure_msg_ex
(
    int sd, 
    const uint8_t *aad, int aad_len, 
    const uint8_t *msg, int msg_len, 
    const uint8_t *key
);

/**
 * Sends a message through the secure channel estabilished on the given socket.
 * A message is composed by:
 *  - An action (which can be a command issued by the client or a response sent back by the server)
 *  - A set of parameters (optional if set to NULL)
 * Returns 0 on success, -1 on failure
 */
int send_secure_msg
(
    int sd,
    union Counter *counter,
    uint8_t action,
    const uint8_t *parameters, int parameters_len, 
    const uint8_t *key
);

/**
 * Receives an AEAD message through the given socket.
 * The AAD header is optional, in that case all three parameters should be set to NULL.
 * _ex stands for "EXtended": gives more control on the received message.
 * Returns 0 on success, -1 on failure (for example, on tag mismatch),
 *  1 if the socket was closed.
 */
int recv_secure_msg_ex
(
    int sd, 
    uint8_t *aad, int aad_max_len, int *aad_len,
    uint8_t *msg, int msg_max_len, int *msg_len,
    const uint8_t *key
);

/**
 * Receives a message through the secure channel estabilished on the given socket.
 * A message is composed by:
 *  - An action (which can be a command issued by the client or a response sent back by the server)
 *  - An set of parameters (optional if set to NULL)
 * Returns 0 on success, -1 on failure, 1 if the socket was closed.
 */
int recv_secure_msg
(
    int sd, 
    union Counter *counter,
    uint8_t *action,
    uint8_t *parameters, int parameters_max_len, int *parameters_len,
    const uint8_t *key
);

/**
 * Hashes and salts the given plaintext password.
 * "hashed_password" must be large enough to hold HASHED_PASSWORD_LENGTH bytes.
 * "hashed_password" will be an ASCII-only zero-terminated string.
 * Rerturns 0 on success, -1 on failure
 */
int hash_password(char *hashed_password, const char *plaintext_password, int password_len);

/**
 * Verifies a plaintext password against an hashed password.
 * Returns 0 if the password matches, -1 if not (or something goes wrong)
 */
int verify_password(const char *hashed_password, const char *plaintext_password, int password_len);

#endif
