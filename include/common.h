
#ifndef COMMON_H
#define COMMON_H

#include <stdint.h>
#include <stdio.h>

#define SERVER_PORT         7777
#define SERVER_IP           "127.0.0.1"

#define MAX_PASSWORD_LENGTH 32  /* Including the null terminator */

/**
 * Generic buffer used for network operations 
 * (more robust than calling malloc and free each time)
 */
#define NETWORK_BUFFER_LENGTH 1024

#define ANSI_CRITICAL   "\x1b[1;45m"
#define ANSI_ERROR      "\x1b[1;41m"
#define ANSI_WARNING    "\x1b[1;33m"
#define ANSI_DEBUG      "\x1b[30;47m"
#define ANSI_RESET      "\x1b[0m"   

/**
 * The minimum severity level to be logged
 */
#ifndef LOG_THRESHOLD
#define LOG_THRESHOLD DEBUG
#endif

/**
 * If the condition is true, logs a custom message (in printf style) possibly
 *  followed by the errno description. If the severity is CRITICAL exits
 *  with failure, otherwise returns -1
 */
#define CHECK(condition, severity, errno_, msg, ...) \
    if (condition) \
    { \
        if(errno_ != 0) log_msg(severity, "%s:%i (%s) > " msg " | %s", __FILE__, __LINE__, __func__, ##__VA_ARGS__, strerror(errno_)); \
        else log_msg(severity, "%s:%i (%s) > " msg, __FILE__, __LINE__, __func__, ##__VA_ARGS__); \
        if (severity == CRITICAL) exit(EXIT_FAILURE); \
        return -1; \
    }

/**
 * If the condition is true, logs a custom message (in printf style) possibly
 *  followed by the errno description, then sets ret to -1 and jumps to the specified label
 */
#define CHECK_GOTO(condition, severity, errno_, label, msg, ...) \
    if (condition) \
    { \
        if(errno_ != 0) log_msg(severity, "%s:%i (%s) > " msg " | %s", __FILE__, __LINE__, __func__, ##__VA_ARGS__, strerror(errno_)); \
        else log_msg(severity, "%s:%i (%s) > " msg, __FILE__, __LINE__, __func__, ##__VA_ARGS__); \
        ret = -1; \
        goto label; \
    }

enum LOG_LEVEL
{
    DEBUG,
    INFO,
    WARNING,
    ERROR,
    CRITICAL
};

enum COMMAND
{
    AUTH_REQUEST,
    NEW_PASSWORD,
    CMD_CREATE_KEYS,
    CMD_SIGN_DOC,
    CMD_GET_PUBKEY,
    CMD_DELETE_KEYS
};

enum RESPONSE
{
    OK,
    PASSWORD_CHANGE_REQUIRED,
    BAD_CMD,
    BAD_PARAMETERS,
    NO_KEYS,
    KEYS_ALREADY_EXIST,
    TIMED_OUT
};

/**
 * Prints to stdout a log message with the following format:
 *  [HH:MM:SS.SSSSSS]   LOG_LEVEL - format
 * "format" is format string, passed as-it-is to printf along with the optional arguments
 */
void log_msg(enum LOG_LEVEL log_level, const char *format, ...);

/**
 * Prints to stdout the given buffer in hexadecimal format (\t0x...\n).
 * Works only if LOG_THRESHOLD <= DEBUG
 */
void debug_bytes(const uint8_t *buffer, int buffer_len);

/**
 * Prints to stdout the contents of an AEAD message in hexadecimal format.
 * The AAD header is optional and can be set to NULL.
 * Works only if LOG_THRESHOLD <= DEBUG
 */
void debug_AEAD
(
    int direction,
    const uint8_t *iv, 
    const uint8_t *tag, 
    const uint8_t *aad, const int *aad_len, 
    const uint8_t *ciphertext, int ciphertext_len, 
    const uint8_t *msg, int msg_len
);

/**
 * Sends the message length on 4 bytes, and then the actual message.
 * Returns 0 on success, -1 on failure.
 * WARNING: For simplicity, assumes that each send() sends the entire buffer
 */ 
int send_msg(int sd, const uint8_t *buffer, int buffer_len);

/**
 * Receives the message length on 4 bytes, and then the actual message.
 * Returns 0 on success, -1 on failure, 1 if the socket was closed.
 * It is considered error if the received message length (outlen) is greater than the buffer length.
 * WARNING: For simplicity, assumes that each recv() receives the entire buffer
 */
int recv_msg(int sd, uint8_t *buffer, int buffer_len, int *outlen);

/**
 * Exactly like recv_msg, but also checks that the received length matches the expected length.
 */
int recv_msg_known_len(int sd, uint8_t *buffer, int expected_len);

/** 
 *  fgets no-newline
 * 
 * Reads at most "count" - 1 characters from the file "stream" and 
 *  stores them in the character array pointed to by "str".
 * 
 * Parsing stops if a newline character is found (in which case
 *  str will NOT contain that newline character) or if end-of-file occurs. 
 * 
 * If bytes are read and no errors occur, writes a null character at
 *  the position immediately after the last character written to str.
 * 
 * Returns the string length on success (excluding the null terminator), -1 on failure
 */
int fgetsnn(char *str, int count, FILE *stream);

#endif
