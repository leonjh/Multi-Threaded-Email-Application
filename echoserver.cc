#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>
#include <pthread.h>
#include <fcntl.h>
#include "connections.h"
#include "constants.h"

#include <vector>
#include <cerrno>
#include <string>
#include <iostream>

using namespace std;

bool debug_output = false; // Global variable to tell wether differnt parts of the program should print debug messages or not.
string GREETING_MESSAGE =  "+OK Server ready (Author: Leon Hertzberg / leonjh)\r\n"; // The greeting message to send upon connection to the server
string ECHO_CMD  = "echo";// Pre-defined string to compare against the clients command to see if it's an echo command
string QUIT_CMD =  "quit"; // Pre-defined string to compare against the clients command to see if it's a quit command

connection_t* connections[MAX_NUM_CONNECTIONS]; // Array of connections to keep track of all the connections

volatile int shutdown_flag = 0;

/**
 * @brief Signal handler to make sure when SIGINT is thrown we properly change the shutdown flag and 
 * send the user signal to every thread
 * 
 * @param signo - The signal number that was raised
 */
void sig_handler(int signo) {
    if (signo == SIGINT) {
        // Write a new line for cleanliness
        char newline[] = {'\n', 0};
        write(STDOUT_FILENO, newline, sizeof(newline));

        // Write shutdown message if in debug mode
        string shutdown_message = "\n[!] Server shutting down\n";
        write(STDOUT_FILENO, (char*)shutdown_message.c_str(), shutdown_message.size());

        // Flip the flag to being true so threads will do their shutdown behavior
        shutdown_flag = 1;

        // Send SIGUSR1 to each thread thats still running in connections so they'll react
        for (int i = 0; i < MAX_NUM_CONNECTIONS; i++) {
            if (connections[i] != NULL) {
                printf("Handling a connection in the array\n");
                if (connections[i]->is_completed) {
                    printf("This connection already ended, just handling joining it\n");
                    pthread_join(connections[i]->thread_id, NULL);
                } else {
                    printf("This connection did not end, marking it as completed, sending signal, and joining\n");
                    connections[i]->is_completed = true;
                    pthread_kill(connections[i]->thread_id, SIGUSR1);
                    pthread_join(connections[i]->thread_id, NULL);
                }
            }
        }
    }
}

/**
 * @brief Signal handler for the worker threads to use when SIGUSR1 is raised. Does nothing
 * as the signal is just used to unblock them 
 * 
 * @param signo - The signal number that was raised
 */
void sig_usr_handler(int signo) {
    if (signo == SIGUSR1) {
        // Does nothing - just being sent to unlock the threads
    }
}

/**
 * @brief Logs a message to stdout when debugging mode is enabled
 * 
 * @param fd - the file descriptor related to the logging message, 0 if none applicable, or the port number when 
 * printing port configuratio 
 * @param message - the message to be output
 * @param type - the type of message, i.e. a client input, server output, or general server debugging
 */
void log_message(int fd, char* message, int type) {
    if (!debug_output) {
        return;
    }

    if (type == CLIENT_MESSAGE) {
        fprintf(stdout, "[%d] C: %s", fd, message);
    }

    if (type == GENERAL_MESSAGE) {
        fprintf(stdout, "[%d] %s", fd, message);
    }

    if (type == SERVER_MESSAGE) {
        fprintf(stdout, "[%d] S: %s", fd, message);
    }
}

/**
 * @brief Checks if two strings are equal regardless of the casing
 * 
 * @param a The first string
 * @param b The second string
 * @return true - Returns true if the strings are equal
 * @return false - Returns false otherwise
 */
bool str_equals(string &a, string &b) {
    // Check the sizes are equal to begin
    if (a.size() != b.size()) {
        return false;
    }

    // Check that each character is equal, ignoring casing
    for (int i = 0; i < a.size(); i++) {
        if (tolower(a[i]) != tolower(b[i])) {
            return false;
        }
    }
    return true;
}

/**
 * @brief Writes a buffer to the specified connection fd. Continues until it's written all of the 
 * specified number of bytes
 * 
 * @param fd - The connection to write to
 * @param buffer - The buffer to write
 * @param len - The length of the buffer to write
 * @return true - Returns true if it successfully writes the full buffer to the file descripter
 * @return false - Returns false in case of any errors/write issues
 */
bool do_write(int fd, char *buffer, int len) { 
    int sent = 0;
    while (sent < len) {
        int n = write(fd, &buffer[sent],len-sent); 

        if (n<0) {
            return false;
        }
        
        sent += n;
    }

  return true;
}

/**
 * @brief Reads a number of bytes from the specified connection fd into the buffer. COntinues until it
 * sees a <CRLF> (i.e. \r\n characters next to each other)
 * 
 * @param fd - The connection to read from
 * @param buffer - The buffer to store the data
 * @return true - Returns true if it successfuly reads all the data from the FD
 * @return false  - Returns false in case of any errors or the command being longer than max length.
 */
bool do_read(int fd, char* buffer) {
    int bytes_read = 0;

    while (bytes_read < MAX_CMD_LENGTH && !shutdown_flag) {
        int n = read(fd, &buffer[bytes_read], 1);

        if (n < 0) {
            return false;
        }

        bytes_read += n;

        // If we've read at least 2 bytes and the last two characters are '\r' and '\n' we finish reading
        if (bytes_read >= 2 && buffer[bytes_read - 1] == '\n' && buffer[bytes_read - 2] == '\r') {
            return true;
        }
    }
    return true;
}

/**
 * @brief The worker thread for which all communication with the client takes place. This thread handles all reading/writing with
 * the client.
 * 
 * @param arg - A pointer to the connections file descriptor for communication
 * @return void* 
 */
void* echo_worker(void *arg) {
    // Initialize a sigaction for the worker thread for when SIGUSR1 is raised
    struct sigaction sa;
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGUSR1, &sa, NULL);

    // Don't block any signals except SIGINT in this thread
    sigset_t sigset;
    sigemptyset(&sigset);
    sigaddset(&sigset, SIGINT);
    pthread_sigmask(SIG_BLOCK, &sigset, NULL);

    // Get the connection file descriptor & set default messages that will be sent to the client
    connection_t* connection = (connection_t*)arg;
    int comm_fd = connection->connection_fd;
    string ERROR_MESSAGE = "-ERR Unknown command\r\n";
    string QUIT_MESSAGE = "+OK Goodbye!\r\n";

    while (!shutdown_flag) {
        // Read in the command sent from the client  to the buffer and null terminate
        char buffer[MAX_CMD_LENGTH+1] = {0};
        do_read(comm_fd, buffer);
        buffer[MAX_CMD_LENGTH] = 0;

        if (strlen(buffer) == 0) {
            continue;
        }

        // If string length is less than 4 no point checking - it must be wrong
        if (strlen(buffer) >= 0 && strlen(buffer) < 4) {
            // In debug mode print that this command us unknown
            log_message(comm_fd, (char*) ERROR_MESSAGE.c_str(), SERVER_MESSAGE);

            do_write(comm_fd, (char*)ERROR_MESSAGE.c_str(), ERROR_MESSAGE.size());
            continue;
        }

        // In debug mode output what we just read from the client.
        log_message(comm_fd, buffer, CLIENT_MESSAGE);

        // Create a command string of length 4 (i.e. either ECHO or QUIT) to case on the command entered
        string cmd(buffer, 4);
        if (buffer[4] == ' ' && str_equals(cmd, ECHO_CMD)) {
            // Get the echoed message andd add it to +OK for output
            string cmd_parameter(&buffer[4], strlen(buffer) - 4);
            string output = "+OK" + cmd_parameter;

            // In debug mode output what the server is about to send to the client
            log_message(comm_fd, (char*)output.c_str(), SERVER_MESSAGE);

            // Write the echo message to the client
            do_write(comm_fd, (char*)output.c_str(), output.size());
        } else if ((buffer[4] == ' ' || buffer[4] == '\r' || buffer[4] == '\n') && str_equals(cmd, QUIT_CMD)) {
            // Write the exit message to the client
            do_write(comm_fd, (char*)QUIT_MESSAGE.c_str(), QUIT_MESSAGE.size());

            // In debug mode print that we're closing the connection
            log_message(comm_fd, (char*)QUIT_MESSAGE.c_str(), SERVER_MESSAGE);
            log_message(comm_fd, (char*)"Connection closed\n", GENERAL_MESSAGE);

            // Close the connection and kill the thread
            connection->is_completed = true;
            close(comm_fd);
            pthread_exit(NULL);
        } else {

            // In debug mode print that the server is returning an unknown command was entered
            log_message(comm_fd, (char*)ERROR_MESSAGE.c_str(), SERVER_MESSAGE);

            // Not one of the valid commands, send error message
            do_write(comm_fd, (char*)ERROR_MESSAGE.c_str(), ERROR_MESSAGE.size());
        }
    }

    // In debug mode tell the server that we're closing the connection unpon threads being ended
    log_message(comm_fd, (char*)"Connection closed\n", GENERAL_MESSAGE);

    // Close the connection & end the thread
    close(comm_fd);
    connection->is_completed = true;
    pthread_exit(NULL);
}

/**
 * @brief The main function for the server. Listens to the specified port and accepts new clients, spanwing the thread that will handle them when appropriate
 * 
 * @param argc - The number of arguments passed in
 * @param argv - A char pointer array of the argumets
 * @return int 
 */
int main(int argc, char *argv[])
{
    // Initialize the connections array to null pointers
    for (int i = 0; i < MAX_NUM_CONNECTIONS; i++) {
        connections[i] = NULL;
    }

    // Default port number is set to 10000, can be changed upon launch.
    int port_no = 10000; 

    // Register SIGINT to use our custom sig_handler
    struct sigaction sa;
    sa.sa_handler = sig_handler;
    sigemptyset(&sa.sa_mask);
    sa.sa_flags = 0;
    sigaction(SIGINT, &sa, NULL);

    // Need to do argument parsing
    int opt;
    while ((opt = getopt(argc, argv, "avp:")) != -1) {
        switch (opt) {
            case 'a':
                fprintf(stderr, "Leon Hertzberg - leonjh");
                exit(EXIT_SUCCESS);
                break;
            case 'v':
                debug_output = true;
                break;
            case 'p':
                port_no = atoi(optarg);
                if (port_no < 0) { port_no = 10000; }
                break;
            case '?':
                printf("Use correct format: ./echoserver -p (number >= 0) (optional: -a) (optional: -v)\n");
                exit(EXIT_SUCCESS);
            default:
                /* Add printing full name / login when no args are given*/
                fprintf(stderr, "Leon Hertzberg - leonjh");
                exit(EXIT_SUCCESS);
        }
    }

    log_message(port_no, (char*)"<-- Entered server port\n", GENERAL_MESSAGE);

    // Listen acting as a stream socket
    int listen_fd = socket(PF_INET, SOCK_STREAM, 0);
    if (listen_fd < 0) {
        fprintf(stderr, "Fail to open socket: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    // Set socket options to prevent an error per edstem
    int socket_opt = 0;
    int socket_ret = setsockopt(listen_fd, SOL_SOCKET, SO_REUSEADDR|SO_REUSEPORT, &opt, sizeof(opt));
    if (socket_ret < 0) {
        fprintf(stderr, "Fail to set socket options: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    // Configure & Bind the socket
    struct sockaddr_in servaddr;
    bzero(&servaddr, sizeof(servaddr));
    servaddr.sin_family = AF_INET;
    servaddr.sin_addr.s_addr = htons(INADDR_ANY);
    servaddr.sin_port = htons(port_no);
    int bind_err = bind(listen_fd, (struct sockaddr*)&servaddr, sizeof(servaddr));

    if (bind_err < 0) {
        fprintf(stderr, "Fail to bind: %s\n", strerror(errno));
        exit(EXIT_FAILURE);
    }

    listen(listen_fd, 200);
    while (!shutdown_flag) {
        struct sockaddr_in clientaddr; 
        socklen_t clientaddrlen = sizeof(clientaddr);
        int client_fd; // Convert this to a pointer to prevent the connection issue

        // Accept new client connection
        client_fd = accept(listen_fd, (struct sockaddr*)&clientaddr, &clientaddrlen);
        if (client_fd < 0) {
            continue;
        }

        // If in debug mode print that a new connection has started.
        log_message(client_fd, (char*)"New connection \n", GENERAL_MESSAGE);
        log_message(client_fd, (char*) GREETING_MESSAGE.c_str(), SERVER_MESSAGE);

        for (int i = 0; i < MAX_NUM_CONNECTIONS; i++) {

            if (connections[i] != NULL && connections[i]->is_completed) { 
                pthread_join(connections[i]->thread_id, NULL);
                delete_connection(connections[i]);
                connections[i] = NULL;
            }

            if (connections[i] == NULL) {
                fprintf(stdout, "Assigning new worker index %d\n", i);
                connections[i] = init_connection(client_fd);
                connections[i]->is_completed = false;
                

                // Write the greeting message to the client before starting the thread.
                do_write(client_fd, (char*)GREETING_MESSAGE.c_str(), GREETING_MESSAGE.size());
                pthread_create(&connections[i]->thread_id, NULL, echo_worker, connections[i]);
                break;
            }

            if (i == MAX_NUM_CONNECTIONS - 1) {
                fprintf(stderr, "[!] Connection rejected - Max number of connections already reached.\n");
                close(client_fd);
            }
        }
    }

    for (int i = 0; i < MAX_NUM_CONNECTIONS; i++) {
        if (connections[i] != NULL) {
            pthread_join(connections[i]->thread_id, NULL);
            free(connections[i]);
            connections[i] = NULL;
        }
    }

    close(listen_fd);
    return 0;
}
