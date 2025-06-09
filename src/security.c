
#include <openssl/evp.h>
#include <openssl/rand.h>
#include <openssl/pem.h>
#include <openssl/kdf.h>

#include <sodium.h>
#include <stdint.h>

#include "security.h"
#include "common.h"

int compute_hash(uint8_t *hash, FILE *file)
{
    int ret = -1;
    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    CHECK(mdctx == NULL, ERROR, 0, "Failed to create the message digest context");

    ret = EVP_DigestInit(mdctx, EVP_sha256());
    CHECK_GOTO(ret <= 0, ERROR, 0, free_ctx, "Failed to initialize the SHA256 digest");

    uint8_t buffer[4096];
    size_t bytes;
    while ((bytes = fread(buffer, 1, sizeof(buffer), file)) != 0) 
    {
        ret = EVP_DigestUpdate(mdctx, buffer, bytes);
        CHECK_GOTO(ret <= 0, ERROR, 0, free_ctx, "Failed to update the SHA256 digest");
    }

    unsigned int hash_len;
    ret = EVP_DigestFinal(mdctx, hash, &hash_len);
    CHECK_GOTO(ret <= 0, ERROR, 0, free_ctx, "Failed to finalize the SHA256 digest");
    CHECK_GOTO(hash_len != DOCUMENT_HASH_LENGTH, ERROR, 0, free_ctx, 
        "Hash length mismatch: expected %u, got %u", DOCUMENT_HASH_LENGTH, hash_len);

    ret = 0;

free_ctx:
    EVP_MD_CTX_free(mdctx);

    return ret;
}

int generate_nonce(uint8_t *nonce, int len)
{
    int ret = RAND_bytes(nonce, len);
    if (ret <= 0)
    {
        return -1;
    }
    return 0;
}

int generate_ECDHE_keypair(EVP_PKEY **keypair)
{
    int ret = -1;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_X25519, NULL);
    CHECK(ctx == NULL, ERROR, 0, "Failed to create the EVP_PKEY_X25519 algorithm context");

    ret = EVP_PKEY_keygen_init(ctx);
    CHECK_GOTO(ret <= 0, ERROR, 0, free_ctx, "Failed to initialize the EVP_PKEY_X25519 algorithm context");
    
    *keypair = NULL;
    ret = EVP_PKEY_keygen(ctx, keypair);
    CHECK_GOTO(ret <= 0, ERROR, 0, free_ctx, "Failed to generate the X25519 key pair");

    ret = 0;

free_ctx:
    EVP_PKEY_CTX_free(ctx);

    return ret;
}

int serialize_ECDHE_pubkey(const EVP_PKEY *keypair, uint8_t *raw_pubkey)
{
    int ret = -1;

    size_t len;
    ret = EVP_PKEY_get_raw_public_key(keypair, NULL, &len);
    CHECK(ret <= 0, ERROR, 0, "Failed to get the ECDHE raw public key length");
    CHECK(len != ECDHE_KEY_LENGTH, ERROR, 0, 
        "ECDHE public key length mismatch: expected %u, got %u", ECDHE_KEY_LENGTH, len);

    ret = EVP_PKEY_get_raw_public_key(keypair, raw_pubkey, &len);
    CHECK(ret <= 0 || len != ECDHE_KEY_LENGTH, ERROR, 0, "Failed to extract the ECDHE raw public key");

    return 0;
}

int deserialize_ECDHE_pubkey(const uint8_t *raw_pubkey, EVP_PKEY **pubkey)
{
    *pubkey = EVP_PKEY_new_raw_public_key(EVP_PKEY_X25519, NULL, raw_pubkey, ECDHE_KEY_LENGTH);
    CHECK(pubkey == NULL, WARNING, 0, "Failed to deserialize the ECDHE public key");
    /* Just a warning because the key comes from the user, so we don't know if it's valid or not */

    return 0;
}

int generate_ECDSA_keypair(EVP_PKEY **keypair)
{
    int ret = -1;

    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new_id(EVP_PKEY_EC, NULL);
    CHECK(ctx == NULL, ERROR, 0, "Failed to create the EVP_PKEY_EC algorithm context");

    ret = EVP_PKEY_keygen_init(ctx);
    CHECK_GOTO(ret <= 0, ERROR, 0, free_ctx, "Failed to initialize the EVP_PKEY_EC algorithm context");
    
    ret = EVP_PKEY_CTX_set_ec_paramgen_curve_nid(ctx, NID_X9_62_prime256v1);
    CHECK_GOTO(ret <= 0, ERROR, 0, free_ctx, 
        "Failed to assign the curve NID_X9_62_prime256v1 to the EVP_PKEY_EC algorithm context");

    *keypair = NULL;
    ret = EVP_PKEY_keygen(ctx, keypair);
    CHECK_GOTO(ret <= 0, ERROR, 0, free_ctx, "Failed to generate the NID_X9_62_prime256v1 key pair");

    ret = 0;

free_ctx:
    EVP_PKEY_CTX_free(ctx);

    return ret;
}

int serialize_ECDSA_privkey(const EVP_PKEY *keypair, uint8_t *raw_privkey, int *raw_privkey_len, const char *password)
{
    int ret = -1;

    BIO *priv_bio = BIO_new(BIO_s_mem());
    CHECK(priv_bio == NULL, ERROR, 0, "Failed to create private key BIO");

    ret = PEM_write_bio_PrivateKey(priv_bio, keypair, EVP_aes_128_cbc(),
        (unsigned char*)password, strlen(password), NULL, NULL);
    CHECK_GOTO(ret <= 0, ERROR, 0, free_bio, "Failed to write the encrypted private key to the BIO");

    uint8_t *bio_data; 
    *raw_privkey_len = BIO_get_mem_data(priv_bio, &bio_data);
    CHECK_GOTO(*raw_privkey_len > SIGNATURE_KEY_LENGTH_MAX, ERROR, 0, free_bio, 
        "Serialized private key length mismatch: expected at most %i, got %i", 
        SIGNATURE_KEY_LENGTH_MAX, *raw_privkey_len);

    memcpy(raw_privkey, bio_data, *raw_privkey_len);

    ret = 0;

free_bio:
    BIO_free(priv_bio);

    return ret;
}

int serialize_ECDSA_pubkey(const EVP_PKEY *keypair, uint8_t *raw_pubkey, int *raw_pubkey_len)
{
    int ret = -1;

    BIO *pub_bio = BIO_new(BIO_s_mem());
    CHECK(pub_bio == NULL, ERROR, 0, "Failed to create public key BIO");

    ret = PEM_write_bio_PUBKEY(pub_bio, keypair);
    CHECK_GOTO(ret <= 0, ERROR, 0, free_bio, "Failed to write the public key to the BIO");

    uint8_t *bio_data; 
    *raw_pubkey_len = BIO_get_mem_data(pub_bio, &bio_data);
    CHECK_GOTO(*raw_pubkey_len > SIGNATURE_KEY_LENGTH_MAX, ERROR, 0, free_bio, 
        "Serialized public key length mismatch: expected at most %i, got %i", 
        SIGNATURE_KEY_LENGTH_MAX, *raw_pubkey_len);

    memcpy(raw_pubkey, bio_data, *raw_pubkey_len);

    ret = 0;

free_bio:
    BIO_free(pub_bio);

    return ret;
}

/* OPENSSL password callback */
int PEM_read_password_callback(char *buf, int size, int rwflag, void *userdata) {
    
    /* OpenSSL is not asking for a "read" password */
    if (rwflag != 0)
    {
        return 0;
    }

    const char *password = (const char *)userdata;
    int len = strlen(password);
    
    /* "size" is the length of the openssl's internal buffer */
    if (len > size)
    {
        len = size;
    }
    
    memcpy(buf, password, len);
    return len;
}

int deserialize_ECDSA_privkey(const uint8_t *raw_privkey, int raw_privkey_len, const char *password, EVP_PKEY **key)
{
    int ret = -1;

    BIO *priv_bio = BIO_new_mem_buf(raw_privkey, raw_privkey_len);
    CHECK(priv_bio == NULL, ERROR, 0, "Failed to create private key BIO");

    *key = PEM_read_bio_PrivateKey(priv_bio, NULL, PEM_read_password_callback, (void *)password);
    CHECK_GOTO(*key == NULL, ERROR, 0, free_bio, "Failed to decrypt the private key from the BIO");

    ret = 0;

free_bio:
    BIO_free(priv_bio);

    return ret;
}

int deserialize_ECDSA_pubkey(const uint8_t *raw_pubkey, int raw_pubkey_len, EVP_PKEY **key)
{
    int ret = -1;

    BIO *pub_bio = BIO_new_mem_buf(raw_pubkey, raw_pubkey_len);
    CHECK(pub_bio == NULL, ERROR, 0, "Failed to create public key BIO");

    *key = PEM_read_bio_PUBKEY(pub_bio, NULL, NULL, NULL);
    CHECK_GOTO(*key == NULL, ERROR, 0, free_bio, "Failed to read the public key from the BIO");

    ret = 0;

free_bio:
    BIO_free(pub_bio);

    return ret;
}

int derive_ECDHE_master_secret(const EVP_PKEY *private_key, const EVP_PKEY *peer_pubkey, uint8_t *secret)
{    
    int ret = -1;
    
    EVP_PKEY_CTX *ctx = EVP_PKEY_CTX_new((EVP_PKEY *)private_key, NULL);
    CHECK(ctx == NULL, ERROR, 0, "Failed to create the master secret derivation context");

    ret = EVP_PKEY_derive_init(ctx);
    CHECK_GOTO(ret <= 0, ERROR, 0, free_ctx, "Failed to initialize the master secret derivation context");

    ret = EVP_PKEY_derive_set_peer(ctx, (EVP_PKEY *)peer_pubkey);
    CHECK_GOTO(ret <= 0, ERROR, 0, free_ctx, "Failed to set the peer's ECDHE public key");

    size_t master_secret_len;
    ret = EVP_PKEY_derive(ctx, NULL, &master_secret_len);
    CHECK_GOTO(ret <= 0, ERROR, 0, free_ctx, "Failed to get the master secret length");
    CHECK_GOTO(master_secret_len != ECDHE_KEY_LENGTH, ERROR, 0, free_ctx, 
        "Master secret length mismatch: expected %u, got %u", ECDHE_KEY_LENGTH, master_secret_len);

    ret = EVP_PKEY_derive(ctx, secret, &master_secret_len);
    CHECK_GOTO(ret <= 0, ERROR, 0, free_ctx, "Failed to extract the master secret");

    ret = 0;

free_ctx:
    EVP_PKEY_CTX_free(ctx);
    
    return ret;
}

int derive_AEAD_keys
(
    const uint8_t *master_secret,
    const uint8_t *server_nonce,
    const uint8_t *client_nonce,
    uint8_t *server2client_key,
    uint8_t *client2server_key
)
{
    int ret = -1;

    EVP_KDF *kdf = EVP_KDF_fetch(NULL, "HKDF", NULL);
    CHECK(kdf == NULL, ERROR, 0, "Failed to find the HKDF algorithm");

    EVP_KDF_CTX *ctx = EVP_KDF_CTX_new(kdf);
    EVP_KDF_free(kdf);
    CHECK(ctx == NULL, ERROR, 0, "Failed to create the HKDF context");

    int salt_len = ECDHE_NONCE_LENGTH * 2;
    uint8_t salt[salt_len];
    memcpy(salt, server_nonce, ECDHE_NONCE_LENGTH);
    memcpy(salt + ECDHE_NONCE_LENGTH, client_nonce, ECDHE_NONCE_LENGTH);

    OSSL_PARAM params[5];
    params[0] = OSSL_PARAM_construct_utf8_string("digest", "SHA256", 0);
    params[1] = OSSL_PARAM_construct_octet_string("key", (void *)master_secret, MASTER_SECRET_LENGTH);
    params[2] = OSSL_PARAM_construct_octet_string("salt", salt, salt_len);
    params[3] = OSSL_PARAM_construct_octet_string("info", "AEAD-keys", 9);
    params[4] = OSSL_PARAM_construct_end();

    ret = EVP_KDF_CTX_set_params(ctx, params);
    CHECK_GOTO(ret <= 0, ERROR, 0, free_ctx, "Failed to set the HKDF parameters");

    uint8_t AEAD_keys[AEAD_KEY_LENGTH * 2];
    ret = EVP_KDF_derive(ctx, AEAD_keys, AEAD_KEY_LENGTH * 2, NULL);
    CHECK_GOTO(ret <= 0, ERROR, 0, free_ctx, "Failed to derive the AEAD keys");

    memcpy(server2client_key, AEAD_keys, AEAD_KEY_LENGTH);
    memcpy(client2server_key, AEAD_keys + AEAD_KEY_LENGTH, AEAD_KEY_LENGTH);

    ret = 0;

free_ctx:
    EVP_KDF_CTX_free(ctx);

    return ret;
}

int sign(const uint8_t *msg, int msg_len, const EVP_PKEY *privkey, uint8_t *signature, int *sig_len)
{
    int ret = -1;
    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    CHECK(mdctx == NULL, ERROR, 0, "Failed to create the signing context");

    ret = EVP_DigestSignInit(mdctx, NULL, EVP_sha256(), NULL, (EVP_PKEY *)privkey);
    CHECK_GOTO(ret <= 0, ERROR, 0, free_ctx, "Failed to initialize signing context");

    ret = EVP_DigestSignUpdate(mdctx, msg, msg_len);
    CHECK_GOTO(ret <= 0, ERROR, 0, free_ctx, "Failed to update the signature");

    size_t outlen;
    ret = EVP_DigestSignFinal(mdctx, NULL, &outlen);
    CHECK_GOTO(ret <= 0, ERROR, 0, free_ctx, "Failed to get the signature length");
    CHECK_GOTO(outlen > SIGNATURE_LENGTH_MAX, ERROR, 0, free_ctx, 
        "Signature length mismatch: expected at most %u, got %u", SIGNATURE_LENGTH_MAX, outlen);

    ret = EVP_DigestSignFinal(mdctx, signature, &outlen);
    CHECK_GOTO(ret <= 0, ERROR, 0, free_ctx, "Failed to finalize the signature");
    
    *sig_len = outlen;
    ret = 0;

free_ctx:
    EVP_MD_CTX_free(mdctx);

    return ret;
}

int verify(const uint8_t *message, int msg_len, const EVP_PKEY *pubkey, const uint8_t *signature, int sig_len)
{
    int ret = -1;
    
    EVP_MD_CTX *mdctx = EVP_MD_CTX_new();
    CHECK(mdctx == NULL, ERROR, 0, "Failed to create the signature verification context");

    ret = EVP_DigestVerifyInit(mdctx, NULL, EVP_sha256(), NULL, (EVP_PKEY *)pubkey);
    CHECK_GOTO(ret <= 0, ERROR, 0, free_ctx, "Failed to initialize the signature verification context");

    ret = EVP_DigestVerify(mdctx, signature, sig_len, message, msg_len);
    CHECK_GOTO(ret <= 0, WARNING, 0, free_ctx, "Failed to verify the signature");

    ret = 0;

free_ctx:
    EVP_MD_CTX_free(mdctx);

    return ret;
}

int send_secure_msg_ex
(
    int sd,
    const uint8_t *aad, int aad_len,
    const uint8_t *msg, int msg_len, 
    const uint8_t *key
)
{
    int ret = -1;

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    CHECK(ctx == NULL, ERROR, 0, "Failed to create the AEAD context");

    uint8_t iv[AEAD_IV_LENGTH];
    ret = generate_nonce(iv, AEAD_IV_LENGTH);
    CHECK_GOTO(ret == -1, ERROR, 0, free_ctx, "Failed to generate the IV");

	ret = EVP_EncryptInit(ctx, EVP_aes_128_gcm(), key, iv);
    CHECK_GOTO(ret <= 0, ERROR, 0, free_ctx, "Failed to initialize the AEAD context");

    /* With EVP_aes_128_gcm, the ciphertext is exactly as long as the plaintext */
    uint8_t ciphertext[NETWORK_BUFFER_LENGTH];
    CHECK_GOTO(msg_len > NETWORK_BUFFER_LENGTH, ERROR, 0, free_ctx, 
        "NETWORK_BUFFER_LENGTH (%i) is too small for the specified message (%i)",
        NETWORK_BUFFER_LENGTH, msg_len);
    
    int outlen;

    if (aad != NULL && aad_len != 0)
    {
        ret = EVP_EncryptUpdate(ctx, NULL, &outlen, aad, aad_len);
        CHECK_GOTO(ret <= 0, ERROR, 0, free_ctx, "Failed to insert the AAD");
        CHECK_GOTO(outlen != aad_len, ERROR, 0, free_ctx, 
            "AAD length mismatch: expected %i, got %i", aad_len, outlen);        
    }
    
	ret = EVP_EncryptUpdate(ctx, ciphertext, &outlen, msg, msg_len);
    CHECK_GOTO(ret <= 0, ERROR, 0, free_ctx, "Failed to encrypt the AEAD message");
    
    int ciphertext_len = outlen;
    
	ret = EVP_EncryptFinal(ctx, ciphertext + outlen, &outlen);
    CHECK_GOTO(ret <= 0, ERROR, 0, free_ctx, "Failed to finalize the AEAD message");
	
    ciphertext_len += outlen;

    CHECK(ciphertext_len != msg_len, CRITICAL, 0, 
        "Ciphertext length mismatch: expected %i, got %i. Possible memory corruption",
        msg_len, ciphertext_len);

    uint8_t tag[AEAD_TAG_LENGTH];
	ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_GET_TAG, AEAD_TAG_LENGTH, tag);
    CHECK_GOTO(ret <= 0, ERROR, 0, free_ctx, "Failed to get the tag");

    /* Send the IV, the tag, the AAD and the encrypted message */

#ifdef SERVER
    debug_AEAD(1, iv, tag, aad, &aad_len, ciphertext, ciphertext_len, msg, msg_len);
#endif

    ret = send_msg(sd, iv, AEAD_IV_LENGTH);
    CHECK_GOTO(ret == -1, WARNING, 0, free_ctx, "Failed to send the IV");

    ret = send_msg(sd, tag, AEAD_TAG_LENGTH);
    CHECK_GOTO(ret == -1, WARNING, 0, free_ctx, "Failed to send the tag");

    if (aad != NULL && aad_len != 0)
    {
        ret = send_msg(sd, aad, aad_len);
        CHECK_GOTO(ret == -1, WARNING, 0, free_ctx, "Failed to send the AAD");
    }

    ret = send_msg(sd, ciphertext, ciphertext_len);
    CHECK_GOTO(ret == -1, WARNING, 0, free_ctx, "Failed to send the ciphertext");

    ret = 0;

free_ctx:
    EVP_CIPHER_CTX_free(ctx);

	return ret;
}

int send_secure_msg
(
    int sd,
    union Counter *counter,
    uint8_t action,
    const uint8_t *parameters, int parameters_len, 
    const uint8_t *key
)
{
    int ret;
    
    if (parameters == NULL || parameters_len == 0)
    {
        ret = send_secure_msg_ex(sd, counter->bytes, 4, &action, 1, key);
        counter->count++;
        return ret;
    }

    CHECK(parameters_len + 1 > NETWORK_BUFFER_LENGTH, ERROR, 0,
        "NETWORK_BUFFER_LENGTH (%i) is too small for the specified parameters + the action (%i)",
        NETWORK_BUFFER_LENGTH, parameters_len + 1);
    
    uint8_t msg[NETWORK_BUFFER_LENGTH];
    int msg_len;

    msg[0] = action;
    memcpy(msg + 1, parameters, parameters_len);
    msg_len = parameters_len + 1;

    ret = send_secure_msg_ex(sd, counter->bytes, 4, msg, msg_len, key);
    counter->count++;
    return ret;
}

int recv_secure_msg_ex
(
    int sd, 
    uint8_t *aad, int aad_max_len, int *aad_len,
    uint8_t *msg, int msg_max_len, int *msg_len,
    const uint8_t *key
)
{
    int ret = -1;

    uint8_t iv[AEAD_IV_LENGTH];
    ret = recv_msg_known_len(sd, iv, AEAD_IV_LENGTH);
    CHECK(ret == -1, WARNING, 0, "Failed to receive the IV");
    if (ret == 1)
    {
        return 1;
    }

    uint8_t tag[AEAD_TAG_LENGTH];
    ret = recv_msg_known_len(sd, tag, AEAD_TAG_LENGTH);
    CHECK(ret == -1, WARNING, 0, "Failed to receive the tag");
    if (ret == 1)
    {
        return 1;
    }

    if (aad != NULL && aad_max_len != 0 && aad_len != NULL)
    {
        ret = recv_msg(sd, aad, aad_max_len, aad_len);
        CHECK(ret == -1, WARNING, 0, "Failed to receive the AAD");
        if (ret == 1)
        {
            return 1;
        }    
    }
    
    uint8_t ciphertext[NETWORK_BUFFER_LENGTH];
    int ciphertext_len;
    ret = recv_msg(sd, ciphertext, NETWORK_BUFFER_LENGTH, &ciphertext_len);
    CHECK(ret == -1, WARNING, 0, "Failed to receive the ciphertext");
    CHECK(ciphertext_len > msg_max_len, WARNING, 0, 
        "The received ciphertext length (%i) exceeds the message's maximum length (%i)",
        ciphertext_len, msg_max_len);
    if (ret == 1)
    {
        return 1;
    }

    /* Decrypt the message and authenticate both the AAD and the message */

	EVP_CIPHER_CTX *ctx = EVP_CIPHER_CTX_new();
    CHECK(ctx == NULL, ERROR, 0, "Failed to create the decryption context");

    ret = EVP_DecryptInit(ctx, EVP_aes_128_gcm(), key, iv);
    CHECK_GOTO(ret <= 0, ERROR, 0, free_ctx, "Failed to initialize the decryption context");
    
    int outlen;

    if (aad != NULL && aad_max_len != 0 && aad_len != NULL)
    {
        ret = EVP_DecryptUpdate(ctx, NULL, &outlen, aad, *aad_len);
        CHECK_GOTO(ret <= 0, ERROR, 0, free_ctx, "Failed to insert the AAD");
        CHECK_GOTO(*aad_len != outlen, ERROR, 0, free_ctx, 
            "AAD length mismatch: expected %i, got %i", *aad_len, outlen);
    }
	
	ret = EVP_DecryptUpdate(ctx, msg, &outlen, ciphertext, ciphertext_len);
    CHECK_GOTO(ret <= 0, WARNING, 0, free_ctx, "Failed to decrypt the ciphertext");
	*msg_len = outlen;

	ret = EVP_CIPHER_CTX_ctrl(ctx, EVP_CTRL_GCM_SET_TAG, AEAD_TAG_LENGTH, tag);
    CHECK_GOTO(ret <= 0, ERROR, 0, free_ctx, "Failed to set the tag");

	ret = EVP_DecryptFinal(ctx, msg + outlen, &outlen);
	CHECK_GOTO(ret <= 0, WARNING, 0, free_ctx, "Failed to authenticate the message");
    *msg_len += outlen;

    CHECK(*msg_len > msg_max_len, CRITICAL, 0, 
        "Plaintext length mismatch: expected at most %i, got %i. Possible memory corruption",
        msg_max_len, *msg_len);

#ifdef SERVER
    debug_AEAD(0, iv, tag, aad, aad_len, ciphertext, ciphertext_len, msg, *msg_len);
#endif

    ret = 0;

free_ctx:
    EVP_CIPHER_CTX_free(ctx);

    return ret;
}

int recv_secure_msg
(
    int sd,
    union Counter *counter,
    uint8_t *action,
    uint8_t *parameters, int parameters_max_len, int *parameters_len,
    const uint8_t *key
)
{
    uint8_t msg[NETWORK_BUFFER_LENGTH];
    int msg_len, recv_counter_len;
    union Counter recv_counter;
    int ret = recv_secure_msg_ex(sd, recv_counter.bytes, 4, &recv_counter_len, msg, NETWORK_BUFFER_LENGTH, &msg_len, key);
    if (ret == -1 || ret == 1) 
    {
        return ret;
    }

    CHECK(recv_counter_len != 4, WARNING, 0, "Counter length mismatch: expected 4, got %i", recv_counter_len);
    CHECK(recv_counter.count != counter->count, ERROR, 0, 
        "Counter value mismatch: expected %i, got %i. Possible replay attack", counter->count, recv_counter.count);
    counter->count++;

    *action = msg[0];

    if (parameters == NULL || parameters_max_len == 0 || parameters_len == NULL)
    {
        CHECK(msg_len != 1, WARNING, 0, "Secure message length mismatch: expected 1, got %i", msg_len);    
    }
    else 
    {
        CHECK(msg_len - 1 > parameters_max_len, WARNING, 0,
            "Received parameters length (%i) exceeds the parameter's maximum length (%i)",
            msg_len - 1, parameters_max_len);
        *parameters_len = msg_len - 1;
        memcpy(parameters, msg + 1, msg_len - 1);
    }

    return 0;
}

int hash_password(char *hashed_password, const char *plaintext_password, int password_len)
{
    return crypto_pwhash_str
    (
        hashed_password, 
        plaintext_password,
        password_len,
        crypto_pwhash_OPSLIMIT_MODERATE,
        crypto_pwhash_MEMLIMIT_MODERATE
    );
}

int verify_password(const char *stored_password, const char *plaintext_password, int password_len)
{
    return crypto_pwhash_str_verify
    (
        stored_password,
        plaintext_password,
        password_len
    );
}
