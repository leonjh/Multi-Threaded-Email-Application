#pragma once

#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>

typedef struct connection_st {
    int connection_fd;
    pthread_t thread_id;
    bool is_completed;
} connection_t;

connection_t *init_connection(int fd);

void delete_connection(connection_t *conn);