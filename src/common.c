
#include <sys/socket.h>
#include <netinet/in.h>
#include <arpa/inet.h>
#include <sys/types.h>

#include <string.h>
#include <stdlib.h>
#include <stdint.h>
#include <stdio.h>
#include <stdarg.h>
#include <time.h>
#include <sys/time.h>
#include <errno.h>

#include "common.h"
#include "security.h"

const char *command_to_str[] = 
{
    "AUTH_REQUEST",
    "NEW_PASSWORD",
    "CMD_CREATE_KEYS",
    "CMD_SIGN_DOC",
    "CMD_GET_PUBKEY",
    "CMD_DELETE_KEYS"
};

const char *response_to_str[] = 
{
    "OK",
    "PASSWORD_CHANGE_REQUIRED",
    "BAD_CMD",
    "BAD_PARAMETERS",
    "NO_KEYS",
    "KEYS_ALREADY_EXIST",
    "TIMED_OUT"
};

void log_msg(enum LOG_LEVEL log_level, const char *format, ...) 
{
    if (log_level < LOG_THRESHOLD)
    {
        return;
    }

    /* Set the color and the log level prefix */
    const char *log_level_prefix = "    NONE";
    switch (log_level) 
    {
        case CRITICAL:
            printf(ANSI_CRITICAL);
            log_level_prefix = "CRITICAL";
            break;
        case ERROR:
            printf(ANSI_ERROR);
            log_level_prefix = "   ERROR";
            break;
        case WARNING:
            printf(ANSI_WARNING);
            log_level_prefix = " WARNING";
            break;
        case INFO:
            printf(ANSI_RESET);
            log_level_prefix = "    INFO";
            break;
        case DEBUG:
            printf(ANSI_DEBUG);
            log_level_prefix = "   DEBUG";
            break;
    }

    /* Print the timestamp prefix " [HH:MM:SS]" */
    struct timeval tv;
    int ret = gettimeofday(&tv, 0);
    if (ret == -1) 
    {
        printf("\n### log_msg() function failed - Unable to get the time ###\n");
        exit(EXIT_FAILURE);
    }
    struct tm *tm_info = localtime(&tv.tv_sec);
    if (tm_info == NULL) 
    {
        printf("\n### log_msg() function failed - Unable to get the local time ###\n");
        exit(EXIT_FAILURE);
    }
    char buffer[16];
    ret = strftime(buffer, 9, "%H:%M:%S", tm_info);
    if (ret == 0) 
    {
        printf("\n### log_msg() function failed - Unable to format the time ###\n");
        exit(EXIT_FAILURE);
    }
    printf(" [%s.%06i]", buffer, tv.tv_usec);

    /* Print the log level prefix " LEVEL - " */
    printf(" %s - ", log_level_prefix);

    /* Print the actual message */
    va_list args;
    va_start(args, format);
    vprintf(format, args);
    va_end(args);
    
    /* Reset the terminal color and append a newline */
    printf(" " ANSI_RESET "\n");
}

void print_bytes(const uint8_t *buffer, int buffer_len)
{
    for (int i = 0; i < buffer_len; i++) 
    {
        printf("%02x", buffer[i]);
    }
}

void debug_bytes(const uint8_t *buffer, int buffer_len)
{
    if (LOG_THRESHOLD > DEBUG)
    {
        return;
    }

    printf(ANSI_DEBUG "\t0x");
    print_bytes(buffer, buffer_len);
    printf(" " ANSI_RESET "\n");
}

void debug_AEAD
(
    int direction,
    const uint8_t *iv, 
    const uint8_t *tag, 
    const uint8_t *aad, const int *aad_len, 
    const uint8_t *ciphertext, int ciphertext_len, 
    const uint8_t *msg, int msg_len
) 
{
    if (LOG_THRESHOLD > DEBUG)
    {
        return;
    }

    const char *direction_str = direction == 0 ? "INCOMING" : "OUTGOING";

    printf(ANSI_DEBUG);
    printf("\n ----------- %s AEAD MSG ----------- ", direction_str);
    printf("\n IV (length = %i): \n\t0x", AEAD_IV_LENGTH);
    print_bytes(iv, AEAD_IV_LENGTH);
    printf("\n TAG (length = %i): \n\t0x", AEAD_TAG_LENGTH);
    print_bytes(tag, AEAD_TAG_LENGTH);
    if (aad != NULL && aad_len != NULL && *aad_len != 0)
    {
        printf("\n AAD (length = %i): \n\t", *aad_len);
        if (*aad_len == 4)
        {
            printf("%u", (uint32_t) *aad);
        }
        else 
        { 
            printf("0x");
            print_bytes(aad, *aad_len); 
        }
    }
    else 
    {
        printf("\n AAD: EMPTY");
    }
    printf("\n CIPHERTEXT (length = %i): \n\t0x", ciphertext_len);
    print_bytes(ciphertext, ciphertext_len);
    printf("\n # PLAINTEXT #");
    printf("\n   - ACTION (length = 1): %s", direction == 0 ? command_to_str[msg[0]] : response_to_str[msg[0]]);
    if (msg_len > 1)
    {
        printf("\n   - PARAMETERS (length = %i): \n\t0x", msg_len - 1);
    }
    else 
    {
        printf("\n   - PARAMETERS: EMPTY");
    }
    print_bytes(msg + 1, msg_len - 1);
    printf("\n ----------------------------------------- ");
    printf(" " ANSI_RESET "\n\n");
}

int send_msg(int sd, const uint8_t *buffer, int buffer_len) 
{
    int ret = -1;

    /* Send the message length on 4 bytes */
    uint32_t network_len = htonl((uint32_t)buffer_len);
    ret = send(sd, &network_len, sizeof(network_len), MSG_NOSIGNAL);
    CHECK(ret <= 0, WARNING, errno, "Failed to send the message length");

    /* Send the actual message */
    ret = send(sd, buffer, buffer_len, MSG_NOSIGNAL);
    CHECK(ret <= 0, WARNING, errno, "Failed to send the message body");

    return 0;
}

int recv_msg(int sd, uint8_t *buffer, int buffer_len, int *outlen)
{
    int ret = -1;

    /* Receive the message length on 4 bytes */
    uint32_t network_len;
    ret = recv(sd, &network_len, sizeof(network_len), 0);
    CHECK(ret == -1, WARNING, errno, "Failed to receive the message length");
    
    /* If recv returns 0 it means that the socket was closed by the client */
    if (ret == 0)
    {
        return 1;
    }

    *outlen = ntohl((uint32_t)network_len);
    CHECK(*outlen < 0 || *outlen > buffer_len, WARNING, 0, 
        "The incoming message length (%i) exceeds the buffer length (%i)", *outlen, buffer_len);

    /* Receive the actual message */
    ret = recv(sd, buffer, *outlen, 0);
    CHECK(ret == -1, WARNING, errno, "Failed to receive the message body");

    if (ret == 0)
    {
        return 1;
    }

    return 0;
}

int recv_msg_known_len(int sd, uint8_t *buffer, int expected_len)
{
    int ret = -1;

    int len;
    ret = recv_msg(sd, buffer, expected_len, &len);
    CHECK (ret == 0 && len != expected_len, WARNING, 0, 
        "Message length mismatch: expected %i, got %i", expected_len, len);

    return ret;
}

int fgetsnn(char *str, int count, FILE *stream)
{
    char *ret = fgets(str, count, stream);

    if (ret != NULL) 
    {
        int i;
        for (i = 0; (i < count - 1) && (str[i] != '\n'); i++);
        str[i] = '\0';
        return i;
    }

    return -1;
}
