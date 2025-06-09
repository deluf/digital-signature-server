
# Compiler and flags
CC = clang
CFLAGS = -Wall -Wextra -pedantic -Wno-gnu-zero-variadic-macro-arguments -fno-builtin-memset 
# -Wno-gnu-zero-variadic-macro-arguments Allows the usage of ... and __VA_ARGS__ in macros (C11)
# -fno-builtin-memset Avoids the optimization of memset(dst, 0, len) calls
# -ggdb Debug symbols
INCLUDES = -Iinclude -I/opt/homebrew/opt/openssl/include -I/opt/homebrew/opt/libsodium/include
LIBS = -L/opt/homebrew/opt/openssl/lib -L/opt/homebrew/opt/libsodium/lib -lssl -lcrypto -lsodium

# Source files
COMMON_SRCS = src/security.c src/common.c
SERVER_SRCS = src/server.c src/database.c
CLIENT_SRCS = src/client.c

# Targets
all: server_t client_t

server_t: $(SERVER_SRCS) $(COMMON_SRCS)
	$(CC) $(CFLAGS) $(INCLUDES) $(SERVER_SRCS) $(COMMON_SRCS) $(LIBS) -DSERVER -o server

client_t: $(CLIENT_SRCS) $(COMMON_SRCS)
	$(CC) $(CFLAGS) $(INCLUDES) $(CLIENT_SRCS) $(COMMON_SRCS) $(LIBS) -DLOG_THRESHOLD=WARNING -DCLIENT -o client

clean:
	rm -f server client *.bin public_key_0.pem public_key_1.pem *.dSYM