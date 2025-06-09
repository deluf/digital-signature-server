
#include <stdlib.h>
#include <string.h>
#include <errno.h>

#include "database.h"
#include "common.h"
#include "security.h"

struct User *users[USERS];
struct Session *sessions[MAX_SESSIONS];

int populate_database(void)
{
    int ret = -1; 

    for (int i = 0; i < USERS; i++) 
    {
        users[i] = malloc(sizeof(struct User));
        CHECK(users[i] == NULL, CRITICAL, errno, "Unable to allocate memory for user %i", i);

        users[i]->encrypted_private_key_len = 0;
        users[i]->public_key_len = 0;
        users[i]->status = WAITING_FOR_FIRST_LOGIN;

        const char *password = "password";
        ret = hash_password(users[i]->hashed_password, password, strlen(password));
        CHECK(ret == -1, CRITICAL, 0, "Unable to hash the password of user %i", i);

        log_msg(DEBUG, "Added user %i with password \"%s\" and hash \"%s\" to the database", i, password, users[i]->hashed_password);
    }

    return 0;
}
