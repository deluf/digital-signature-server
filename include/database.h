
#ifndef DATABASE_H
#define DATABASE_H

#include <sodium.h>

#include "security.h"
#include "common.h"

#define USERS 2 /* Toy example */

/* As many as the "select" syscall allows at the same time */
#define MAX_SESSIONS 1024

/**
 * To avoid sending too much data using the same session key,
 *  session are automatically closed after 5 minutes
 */
#define SESSION_TIMEOUT_SECONDS 300

enum USER_STATUS
{
    WAITING_FOR_FIRST_LOGIN,
    OPERATIONAL,
    REQUIRES_OFFLINE_REGISTRATION
};

struct User
{
    enum USER_STATUS status;
    char hashed_password[HASHED_PASSWORD_LENGTH]; 
    uint8_t encrypted_private_key[SIGNATURE_KEY_LENGTH_MAX];
    uint8_t public_key[SIGNATURE_KEY_LENGTH_MAX];
    int encrypted_private_key_len;
    int public_key_len;
};

struct Session
{
    uint8_t user_id;
    char plaintext_password[MAX_PASSWORD_LENGTH];
    uint8_t server2client_key[AEAD_KEY_LENGTH];
    uint8_t client2server_key[AEAD_KEY_LENGTH];
    time_t creation_time;
    union Counter counter;
};

/**
 * Populates the database with dummy users.
 * Exits the program with code EXIT_FAILURE in case of error
 */
int populate_database(void);

#endif
