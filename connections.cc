#include "connections.h"

connection_t *init_connection(int fd) {
    connection_t *conn = (connection_t *)malloc(sizeof(connection_t));

    if (conn == NULL) {
        perror("Memory allocation failed - init_connection");
        exit(EXIT_FAILURE);
    }

    conn->connection_fd = fd;
    conn->is_completed = false;

    return conn;
}

void delete_connection(connection_t *conn) {
    free(conn);
}