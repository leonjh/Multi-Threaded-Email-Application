#pragma once

#include <string>

#define MAX_FILE_LENGTH 4096
#define MAX_LINE_LENGTH 4096
#define MAX_CMD_LENGTH 1000 // The maximum length of a command possible per the writeup
#define MAX_NUM_CONNECTIONS 100 // The maximum number of connections the server will accept

typedef enum logger_type {
    CLIENT_MESSAGE, // Something the client sent to the server
    GENERAL_MESSAGE,// Something the server reports, but not from an interaction w/ client
    SERVER_MESSAGE, // Something the server sent to the client
} log_type;

typedef enum pop3_stage_st {
    AUTHORIZATION,
    TRANSACTION,
    UPDATE,
} pop3_stage;

#define HELO_ENTERED 0
#define MAIL_FROM_ENTERED 1
#define RCPT_TO_ENTERED 2
#define DATA_ENTERED 3
#define QUIT_ENTERED 4
#define RSET_ENTERED 5
#define NOOP_ENTERED 6