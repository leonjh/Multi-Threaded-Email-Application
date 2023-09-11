#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <time.h>
#include <unistd.h>

#include "connections.h"
#include "constants.h"
#include "email_file.h"
#include "tokenizer.h"

#include <cerrno>
#include <chrono>
#include <iostream>
#include <string>
#include <unordered_map>
#include <vector>

using namespace std;

bool debug_output = false; // Global variable to tell wether differnt parts of the program should print debug messages or not.
string GREETING_MESSAGE =  "220 localhost (Author: Leon Hertzberg / leonjh)\r\n"; // The greeting message to send upon connection to the server
string ECHO_CMD  = "echo";// Pre-defined string to compare against the clients command to see if it's an echo command

string directory_path;

string HELO_CMD = "HELO";
string MAIL_CMD = "MAIL";
string FROM_CMD = "FROM:";
string RCPT_CMD = "RCPT";
string TO_CMD = "TO:";
string DATA_CMD = "DATA\r\n";
string QUIT_CMD =  "QUIT\r\n"; // Pre-defined string to compare against the clients command to see if it's a quit command
string RSET_CMD = "RSET\r\n";
string NOOP_CMD = "NOOP\r\n";

connection_t* connections[MAX_NUM_CONNECTIONS]; // Array of connections to keep track of all the connections
vector<email_file_t*> email_files;
unordered_map<string, pthread_mutex_t> email_map;

volatile int shutdown_flag = 0;

/**
 * @brief Logs a message to the server when in debug mode
 * 
 * @param fd - The file descriptor of the client, or whatever val the server passes
 * @param message - The message to output
 * @param type - Whether this is from the server, a response to client, or a general info
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
        log_message(0, (char*) shutdown_message.c_str(), shutdown_message.size());

        // Flip the flag to being true so threads will do their shutdown behavior
        shutdown_flag = 1;

        // Send SIGUSR1 to each thread thats still running in connections so they'll react
        for (int i = 0; i < MAX_NUM_CONNECTIONS; i++) {
            if (connections[i] != NULL) {
                // printf("Handling a connection in the array\n");
                if (connections[i]->is_completed) {
                    // printf("This connection already ended, just handling joining it\n");
                    pthread_join(connections[i]->thread_id, NULL);
                } else {
                    // printf("This connection did not end, marking it as completed, sending signal, and joining\n");
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
 * @brief Checks if the most recently entered commands is valid based off all the commands recieved
 * 
 * @param command - The most recently entered command
 * @param recv_cmds - The 
 * @return true 
 * @return false 
 */
bool valid_command(int command, int recv_cmds[]) {
    // HELO entered, so check if any others are active, if not return true
    if (command == HELO_ENTERED) {
        for (int i = 1; i < 7; i++) {
            if (recv_cmds[i]) {
                log_message(i, (char*) "<-- Entered descriptor is command already running before HELO", GENERAL_MESSAGE);
                return false;
            }
        }

        return true;
    } 

    // If we have any command other than HELO and HELO_ENTERED isn't true were done its false
    if (!recv_cmds[HELO_ENTERED]) {
        return false;
    }

    if (command == MAIL_FROM_ENTERED) {
        if (!recv_cmds[HELO_ENTERED]) {
            return false;
        }

        // This can only happen between HELO and RCPT TO, so if HELO is true and we've already started a command we start fresh
        if (recv_cmds[MAIL_FROM_ENTERED]) {
            for (int i = 2; i < 7; i++) {
                recv_cmds[i] = 0;
            }
        }
    } else if (command == RCPT_TO_ENTERED) {
        if (!recv_cmds[HELO_ENTERED] || !recv_cmds[MAIL_FROM_ENTERED]) {
            return false;
        }
    } else if (command == DATA_ENTERED) {
        return (recv_cmds[HELO_ENTERED] == 1 && recv_cmds[MAIL_FROM_ENTERED] == 1) && recv_cmds[RCPT_TO_ENTERED] == 1;
    } else if (command == QUIT_ENTERED) {
        return true;
    } else if (command == RSET_ENTERED) {
        // Since initial state is entered and we've began a transaction (or done nothing) reset to only initial
        for (int i = 1; i < 7; i++) {
            recv_cmds[i] = 0;
        }
    } else if (command == NOOP_ENTERED) {
        return recv_cmds[HELO_ENTERED] == 1;
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

    string QUIT_MESSAGE = "221 Exiting server\r\n";
    string HELO_MSG = "250 localhost\r\n";
    string ERROR_MSG = "503 Bad sequence of commands\r\n";
    string INVALID_CMD = "500 Invalid Command\r\n";
    string OK_MSG = "250 OK\r\n";
    string INC_DATA_MSG = "354 OK\r\n";

    // Array that holds whether a command was recieved yet or not, so we adhere to order of commands.
    int recv_cmds[7] = {0};
    string cur_sender;
    vector<string> cur_recipients;
    string cur_email;

    while (!shutdown_flag) {
        // Read in the command sent from the client  to the buffer and null terminate
        char buffer[MAX_CMD_LENGTH+1] = {0};
        do_read(comm_fd, buffer);
        buffer[MAX_CMD_LENGTH] = 0;

        if (strlen(buffer) == 0) {
            continue;
        }

        // In debug mode output what we just read from the client.
        log_message(comm_fd, buffer, CLIENT_MESSAGE);

        // if in data mode we ignore everything else and handle writing and stuff
        string end_data_string = ".\r\n";
        if (recv_cmds[DATA_ENTERED] == 1) {
            string next_email_line = string(buffer);

            // Check if the current read in buffer is only ".\r.\n" - if not add the stuff and continue
            if (!str_equals(next_email_line, end_data_string)) {
                cur_email.append(next_email_line);
                continue;
            }

            // The string entered is only the end character, meaning last string ended with \r\n and thus we're done
            // For each item in our recipients vector, acquire their file descriptor, flock it, lock the mutex, write, unlock, unlock
            for (string cur_write_recipient : cur_recipients) {
                string full_path = directory_path + cur_write_recipient;

                int fd = open(full_path.c_str(), O_CREAT | O_RDWR | O_APPEND, 0644);
                if (fd < 0) {
                    fprintf(stderr, "Fail to open file descriptor: %s\n", strerror(errno));
                    exit(EXIT_FAILURE);
                }

                int flock_ret = flock(fd, LOCK_EX);
                pthread_mutex_lock(&email_map[cur_write_recipient]);

                // Make the cur_sender line that has to go at the top
                struct tm newtime;
                time_t ltime;
                char buf[50];
                ltime=time(&ltime);
                localtime_r(&ltime, &newtime);
                asctime_r(&newtime, buf);      
                for (int i = 0; i < strlen(buf); i++) { if (buf[i] == '\n') {buf[i] = 0; } }          
                string top_level = "From <" + cur_sender + "@localhost" + "> <" + buf + ">\n";

                write(fd, (char*)top_level.c_str(), top_level.size());
                write(fd, (char*)cur_email.c_str(), cur_email.size());
                pthread_mutex_unlock(&email_map[cur_write_recipient]);
                int unlock_ret = flock(fd, LOCK_UN);

                close(fd);
            }
            do_write(comm_fd, (char*) OK_MSG.c_str(), OK_MSG.size());

            // When we're completely done set us back to the initial state
            for (int i = 1; i < 7; i++) {
                recv_cmds[i] = 0;
            }
            
            cur_sender.assign("");
            cur_recipients.clear();
            continue;
        }

        // Tokenize input to find command
        vector<string> args;
        split_tokens(args, buffer, strlen(buffer));
        if (str_equals(args[0], HELO_CMD)) {
            if (valid_command(HELO_ENTERED, recv_cmds)) {
                recv_cmds[HELO_ENTERED] = 1;
            } else {
                do_write(comm_fd, (char*)ERROR_MSG.c_str(), ERROR_MSG.size());
                continue;
            }

            // Get the echoed message and add it to +OK for output
            if (args.size() == 1) {
                do_write(comm_fd, (char*)INVALID_CMD.c_str(), INVALID_CMD.size());
            }
            string output = "250 localhost sent as HELO response to domain " + args[1];

            // In debug mode output what the server is about to send to the client
            log_message(comm_fd, (char*)output.c_str(), SERVER_MESSAGE);

            // Write the echo message to the client
            do_write(comm_fd, (char*)HELO_MSG.c_str(), HELO_MSG.size());
            log_message(comm_fd, (char*)HELO_MSG.c_str(), SERVER_MESSAGE);

        } else if (str_equals(args[0], MAIL_CMD)) {
            if (args.size() < 2) {
                do_write(comm_fd, (char*)INVALID_CMD.c_str(), INVALID_CMD.size());
                log_message(comm_fd, (char*)INVALID_CMD.c_str(), SERVER_MESSAGE);
                continue;
            }

            string from_sender_arg = args[1];

            size_t loc_colon = from_sender_arg.find(':');
            size_t loc_open = from_sender_arg.find('<');
            size_t loc_close = from_sender_arg.find('>');
            
            if (loc_colon < 0 || loc_open < 0 || loc_close < 0) {
                do_write(comm_fd, (char*)INVALID_CMD.c_str(), INVALID_CMD.size());
                log_message(comm_fd, (char*)INVALID_CMD.c_str(), SERVER_MESSAGE);
                continue;
            }

            string before_colon = string(from_sender_arg.begin(), from_sender_arg.begin() + loc_colon + 1);

            if (!str_equals(before_colon, FROM_CMD)) {
                do_write(comm_fd, (char*)INVALID_CMD.c_str(), INVALID_CMD.size());
                log_message(comm_fd, (char*)INVALID_CMD.c_str(), SERVER_MESSAGE);
                continue;
            }

            if (valid_command(MAIL_FROM_ENTERED, recv_cmds)) {
                recv_cmds[MAIL_FROM_ENTERED] = 1;
                recv_cmds[RCPT_TO_ENTERED] = 0;
                cur_sender.assign("");
                cur_recipients.clear();
            } else {
                do_write(comm_fd, (char*)ERROR_MSG.c_str(), ERROR_MSG.size());
                continue;
            }

            do_write(comm_fd, (char*) OK_MSG.c_str(), OK_MSG.size());

            string parsed_sender = string(from_sender_arg.begin() + loc_open + 1, from_sender_arg.begin() + loc_close);
            string logger = "Entered MAIL FROM: " + parsed_sender + "\n";

            log_message(comm_fd, (char*)logger.c_str(), GENERAL_MESSAGE);

            cur_sender.assign(parsed_sender);

        } else if (str_equals(args[0], RCPT_CMD)) {
            if (args.size() < 2) {
                do_write(comm_fd, (char*)INVALID_CMD.c_str(), INVALID_CMD.size());
                continue;
            }

            string from_sender_arg = args[1];

            size_t loc_colon = from_sender_arg.find(':');
            size_t loc_open = from_sender_arg.find('<');
            size_t loc_close = from_sender_arg.find('>');
            
            if (loc_colon < 0 || loc_open < 0 || loc_close < 0) {
                do_write(comm_fd, (char*)INVALID_CMD.c_str(), INVALID_CMD.size());
                continue;
            }

            string before_colon = string(from_sender_arg.begin(), from_sender_arg.begin() + loc_colon + 1);

            if (!str_equals(before_colon, TO_CMD)) {
                do_write(comm_fd, (char*)INVALID_CMD.c_str(), INVALID_CMD.size());
                continue;
            }

            if (!valid_command(RCPT_TO_ENTERED, recv_cmds)) {
                do_write(comm_fd, (char*)ERROR_MSG.c_str(), ERROR_MSG.size());
                continue;
            }

            string parsed_recipient = string(from_sender_arg.begin() + loc_open + 1, from_sender_arg.begin() + loc_close);
            string logger = "Entered RCPT TO: " + parsed_recipient + "\n";

            size_t localhost_idx = parsed_recipient.find("@localhost");

            // Make sure @localhost is present in the string
            if (localhost_idx < 0) {
                do_write(comm_fd, (char*)INVALID_CMD.c_str(), INVALID_CMD.size());
                continue;
            }

            string mbox_string = string(parsed_recipient.begin(), parsed_recipient.begin() + localhost_idx);
            mbox_string.append(".mbox");

            string NO_MAILBOX_ERROR = "550 Non-existent email\r\n";
            // Checks if such a mailbox exists. If not error, otherwise continue
            if (email_map.find(mbox_string) == email_map.end()) {
                do_write(comm_fd, (char*) NO_MAILBOX_ERROR.c_str(), NO_MAILBOX_ERROR.size());
                continue;
            }

            recv_cmds[RCPT_TO_ENTERED] = 1;

            log_message(comm_fd, (char*) logger.c_str(), GENERAL_MESSAGE);
            do_write(comm_fd, (char*) OK_MSG.c_str(), OK_MSG.size());

            cur_recipients.push_back(mbox_string);
        } else if (str_equals(args[0], DATA_CMD)) {
            if (valid_command(DATA_ENTERED, recv_cmds)) {
                recv_cmds[DATA_ENTERED] = 1;
            } else {
                do_write(comm_fd, (char*)ERROR_MSG.c_str(), ERROR_MSG.size());
                continue;
            }
            cur_email.assign("");
            do_write(comm_fd, (char*)INC_DATA_MSG.c_str(), INC_DATA_MSG.size());
        } else if (str_equals(args[0], RSET_CMD)) {
            if (!valid_command(RSET_ENTERED, recv_cmds)) {
                // This will do the work if return true is coming
                // Otherwise Say error and continue
                do_write(comm_fd, (char*)ERROR_MSG.c_str(), ERROR_MSG.size());
                continue;
            }

            // Erase our cur_sender since we're resetting
            cur_sender = "";

            // Clear the list of our recipients since we're resetting
            cur_recipients.clear();
            do_write(comm_fd, (char*) OK_MSG.c_str(), OK_MSG.size());
        } else if (str_equals(args[0], NOOP_CMD)) {
            if (valid_command(NOOP_ENTERED, recv_cmds)) {
                do_write(comm_fd, (char*) OK_MSG.c_str(), OK_MSG.size());
                continue;
            } else {
                do_write(comm_fd, (char*)ERROR_MSG.c_str(), ERROR_MSG.size());
                continue;
            }
        } else if (str_equals(args[0], QUIT_CMD)) {
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
            do_write(comm_fd, (char*)INVALID_CMD.c_str(), INVALID_CMD.size());
            continue;
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
    int port_no = 2500; 

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

    for(; optind < argc; optind++){
        directory_path.assign(string(argv[optind]));
        if (directory_path[directory_path.size()-1] != '/') {
            directory_path.append("/");
        }
    }

    DIR *d;
    struct dirent *dir;
    d = opendir((char*)directory_path.c_str());
    if (d) {
        while ((dir = readdir(d)) != NULL) {
            if (dir->d_type == DT_REG && strcmp(dir->d_name,".")!=0 && strcmp(dir->d_name,"..")!=0 ) {
                // Map approach
                string dir_name(dir->d_name);
                pthread_mutex_t mutex;
                pthread_mutex_init(&mutex, NULL);
                email_map[dir_name] = mutex;

                email_file_t *cur_file = init_email_file(dir->d_name);
                pthread_mutex_init(&cur_file->mutex, NULL);
                email_files.push_back(cur_file);
            }
        }
        closedir(d);
    } else {
        fprintf(stderr, "Invalid directory entered. Cannot load mboxes.\n");
        exit(EXIT_FAILURE);
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
                // fprintf(stdout, "Assigning new worker index %d\n", i);
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

    for (email_file_t *cur : email_files) {
        delete_email_file(cur);
    }

    for (auto elem : email_map) {
        pthread_mutex_destroy(&elem.second);
    }

    close(listen_fd);
    return 0;
}
