#include <arpa/inet.h>
#include <dirent.h>
#include <fcntl.h>
#include <openssl/md5.h>
#include <pthread.h>
#include <signal.h>
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <sys/file.h>
#include <unistd.h>

#include "connections.h"
#include "constants.h"
#include "tokenizer.h"

#include <cerrno>
#include <fstream>
#include <iostream>
#include <string>
#include <unordered_map>
#include <unordered_set>
#include <vector>

using namespace std;

bool debug_output = false; // Global variable to tell wether differnt parts of the program should print debug messages or not.
string GREETING_MESSAGE =  "+OK POP3 ready [localhost]\r\n"; // The greeting message to send upon connection to the server
string ECHO_CMD  = "echo";// Pre-defined string to compare against the clients command to see if it's an echo command

string directory_path;

string correct_pass = "cis505";

string USER_CMD = "USER";
string PASS_CMD = "PASS";
string STAT_CMD = "STAT";
string UIDL_CMD = "UIDL";
string RETR_cmd = "RETR";
string DELE_CMD = "DELE";
string LIST_CMD = "LIST";
string NOOP_CMD = "NOOP";
string RSET_CMD = "RSET";
string QUIT_CMD = "QUIT";

connection_t* connections[MAX_NUM_CONNECTIONS]; // Array of connections to keep track of all the connections
unordered_map<string, pthread_mutex_t> email_map;

volatile int shutdown_flag = 0;

void computeDigest(char *data, int dataLengthBytes, unsigned char *digestBuffer)
{
    /* The digest will be written to digestBuffer, which must be at least MD5_DIGEST_LENGTH bytes long */

    MD5_CTX c;
    MD5_Init(&c);
    MD5_Update(&c, data, dataLengthBytes);
    MD5_Final(digestBuffer, &c);
}

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
 * @brief Converts a hash to a readable hex string
 * 
 * @param hash the md5 hash
 * @return string hex readable string
 */
string hash_to_string(unsigned char hash[]) {
    std::string result;
    result.reserve(32);  // C++11 only, otherwise ignore

    for (std::size_t i = 0; i != MD5_DIGEST_LENGTH; ++i)
    {
    result += "0123456789ABCDEF"[hash[i] / 16];
    result += "0123456789ABCDEF"[hash[i] % 16];
    }

    return result;
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

    // Current stage of pop3
    pop3_stage stage = AUTHORIZATION;

    // Define any thread needed strings here
    string ERR_UNKNOWN_CMD = "-ERR Unknown Command\r\n";
    string ERR_INVALID_USER = "-ERR Invalid (or no) user entered\r\n";
    string ERR_INVALID_PASS = "-ERR Invalid (or no) password entered\r\n";
    string ERR_INVALID_CMD_ORDER = "-ERR Invalid command order - cannot do this right now\r\n";
    string ERR_INVALID_EMAIL_IDX = "-ERR Invalid email index\r\n";
    string ERR_INVALID_RETR_IDX = "-ERR Invalid RETR - No index entered or invalid index\r\n";
    string ERR_INVALID_DELE_IDX = "-ERR Invalid Deletion - Check email index.\r\n"; 
        string ERR_DELETED_ALREADY = "-ERR Email already dleted.\r\n";

    string ERR_LIST_EMPTY_INBOX = "-ERR Inbox email empty.\r\n";
        string ERR_LIST_INVALID_INDEX = "-ERR List invalid index entered.\r\n";

    string ERR_INVALID_UIDL = "-ERR Invalid UIDL - Check index.\r\n";
    

    string OK_VALID_USER = "+OK Valid user entered\r\n";
    string OK_VALID_PASS = "+OK Valid pass entered - maildrop locked and ready \r\n";
    // UIDL string
    string OK_VALID_RETR = "+OK Valid message retrieval\r\n";
    string OK_VALID_DELE = "+OK Valid message deletion.\r\n";
    string OK_VALID_QUIT = "+OK Closing connection.\r\n";
    string OK_VALID_LIST = "+OK Valid List";

    // Current user & Current read in email (unsure if needed)
    string cur_user_inbox = "";
    string empty_user = "";

    int cur_inbox_fd = - 1;
    FILE *inputFile;

    string cur_email;

    unordered_map <int, string> cur_idx_to_email;
    unordered_set <string> cur_deletion_set;
    unordered_set <int> cur_deletion_idx_set;
    

    while (!shutdown_flag) {
        // Read in the command sent from the client  to the buffer and null terminate
        char buffer[MAX_CMD_LENGTH+1] = {0};
        do_read(comm_fd, buffer);
        // fprintf(stderr,"The buffer: %s\n", buffer);

        if (strlen(buffer) == 0) {
            continue;
        }

        // In debug mode output what we just read from the client.
        log_message(comm_fd, buffer, CLIENT_MESSAGE);

        // Tokenize input to find command
        vector<string> args;
        split_tokens_no_crlf(args, buffer, strlen(buffer));

        if (str_equals(args[0], USER_CMD)) {
            if (stage != AUTHORIZATION) {
                do_write(comm_fd, (char*)ERR_INVALID_CMD_ORDER.c_str(), ERR_INVALID_CMD_ORDER.size());
                continue;
            }
            // Check that theres another index for a user to be at
            if (args.size() < 2) {
                do_write(comm_fd, (char*)ERR_INVALID_USER.c_str(), ERR_INVALID_USER.size());
                log_message(comm_fd, (char*)ERR_INVALID_USER.c_str(), SERVER_MESSAGE);
                stage = AUTHORIZATION;
                continue;
            }

            // Check that such an mbox exists in the directory
            string possible_mbox = args[1] + ".mbox";
            if (email_map.find(possible_mbox) == email_map.end()) {
                do_write(comm_fd, (char*)ERR_INVALID_USER.c_str(), ERR_INVALID_USER.size());
                log_message(comm_fd, (char*)ERR_INVALID_USER.c_str(), SERVER_MESSAGE);
                stage = AUTHORIZATION;
                continue;
            }
            // Set current user
            cur_user_inbox.assign(possible_mbox);
            do_write(comm_fd, (char*) OK_VALID_USER.c_str(), OK_VALID_USER.size());
            log_message(comm_fd, (char*)OK_VALID_USER.c_str(), SERVER_MESSAGE);
            stage = AUTHORIZATION;
        } else if (str_equals(args[0], PASS_CMD)) {
            if (stage != AUTHORIZATION) {
                do_write(comm_fd, (char*)ERR_INVALID_CMD_ORDER.c_str(), ERR_INVALID_CMD_ORDER.size());
                continue;
            }
            // Make it so that if theres no user (i.e. empty string) this is instantly false.
            if (str_equals(cur_user_inbox, empty_user)) {
                do_write(comm_fd, (char*)ERR_INVALID_USER.c_str(), ERR_INVALID_USER.size());
                log_message(comm_fd, (char*)ERR_INVALID_USER.c_str(), SERVER_MESSAGE);
                continue;
            }
            
            // Check that theres another index for the password to be at
            if (args.size() < 2) {
                do_write(comm_fd, (char*)ERR_INVALID_PASS.c_str(), ERR_INVALID_PASS.size());
                log_message(comm_fd, (char*)ERR_INVALID_PASS.c_str(), SERVER_MESSAGE);
                stage = AUTHORIZATION;
                continue;
            }

            // Check that the password matches cis505 - NOTE MAY HAVE ISSUES IF CARRIAGE RETURN INCLUDED
            // Maybe make a second tokenizer that doesn't take in the carriage returns?
            if (!str_equals(args[1], correct_pass))  {
                do_write(comm_fd, (char*)ERR_INVALID_PASS.c_str(), ERR_INVALID_PASS.size());
                log_message(comm_fd, (char*)ERR_INVALID_PASS.c_str(), SERVER_MESSAGE);
                cur_user_inbox.assign(""); // Erase the user that was trying to log in
                stage = AUTHORIZATION;
                continue;
            }

            // Acquire any needed flocks and mutexes. 
            string full_path = directory_path + cur_user_inbox;
            cur_inbox_fd = open(full_path.c_str(), O_CREAT | O_RDWR | O_APPEND, 0644);
            if (cur_inbox_fd < 0) {
                    fprintf(stderr, "Fail to open file descriptor: %s\n", strerror(errno));
                    exit(EXIT_FAILURE);
            }
            inputFile = fdopen(cur_inbox_fd, "r");
            if (inputFile == NULL) {
                perror("fdopen failed.");
                close(cur_inbox_fd);
                exit(EXIT_FAILURE);
            }
            int flock_ret = flock(cur_inbox_fd, LOCK_EX);
            pthread_mutex_lock(&email_map[cur_user_inbox]);

            do_write(comm_fd, (char*)OK_VALID_PASS.c_str(), OK_VALID_PASS.size());
            log_message(comm_fd, (char*)OK_VALID_PASS.c_str(), SERVER_MESSAGE);
            stage = TRANSACTION;
        } else if (str_equals(args[0], STAT_CMD)) {
            if (stage != TRANSACTION) {
                do_write(comm_fd, (char*)ERR_INVALID_CMD_ORDER.c_str(), ERR_INVALID_CMD_ORDER.size());
                log_message(comm_fd, (char*)ERR_INVALID_CMD_ORDER.c_str(), SERVER_MESSAGE);
                continue;
            }

            char line[MAX_CMD_LENGTH] = {0};
            bool insideMessage = false;
            string new_email_marker = "FROM ";
            int num_emails = 0;
            int num_unwritable = 0;
            int octet_size = 0;
            bool writable_email = false;
            while (fgets(line, 1000, inputFile) != NULL) {
                string first_four(line, 5);
                if (str_equals(first_four, new_email_marker)) {
                    num_emails++;
                    if (cur_deletion_idx_set.count(num_emails) == 0) {
                        writable_email = true;
                    } else {
                        num_unwritable++;
                        writable_email = false;
                    }
                    insideMessage = true;
                } else if (insideMessage && writable_email) {
                    octet_size += strlen(line);
                }
                for (int i = 0; i < MAX_CMD_LENGTH; i++) { line[i] = 0; }
            }
            num_emails -= num_unwritable;

            int lseek_ret = fseek(inputFile, 0, SEEK_SET);
            if (lseek_ret < 0) {
                perror("LSeek Error.\n");
                exit(EXIT_FAILURE);
            }

            string output_string = "+OK " + to_string(num_emails) + " " + to_string(octet_size) + "\r\n";
            do_write(comm_fd, (char*) output_string.c_str(), output_string.size());
            log_message(comm_fd, (char*) output_string.c_str(), SERVER_MESSAGE);
        } else if (str_equals(args[0], UIDL_CMD)) {
            if (stage != TRANSACTION) {
                do_write(comm_fd, (char*)ERR_INVALID_CMD_ORDER.c_str(), ERR_INVALID_CMD_ORDER.size());
                log_message(comm_fd, (char*)ERR_INVALID_CMD_ORDER.c_str(), SERVER_MESSAGE);
                continue;
            }

            int desired_email_idx = 0;
            if (args.size() > 1) {
                desired_email_idx = stoi(args[1]);
            }

            if (desired_email_idx < 1 && args.size() > 1) {
                do_write(comm_fd, (char*)ERR_INVALID_EMAIL_IDX.c_str(), ERR_INVALID_EMAIL_IDX.size());
                log_message(comm_fd, (char*)ERR_INVALID_EMAIL_IDX.c_str(), SERVER_MESSAGE);
                continue;
            }

            vector<string> all_email_hashes;

            char line[MAX_CMD_LENGTH] = {0};
            int count = 0;
            bool insideMessage = false;
            string new_email_marker = "FROM ";
            int num_emails = 0;
            int octet_size = 0;
            string current_email = "";
            while (fgets(line, 1000, inputFile) != NULL) {
                string first_four(line, 5);
                if (str_equals(first_four, new_email_marker)) {
                    if (num_emails != 0) {
                        unsigned char digest_buffer[MAX_LINE_LENGTH] = {0};
                        computeDigest((char*)current_email.c_str(), current_email.size(), digest_buffer);
                        string output = hash_to_string(digest_buffer);
                        all_email_hashes.push_back(output);
                    }
                    current_email.assign("");
                    num_emails++;
                    insideMessage = true;
                } else if (insideMessage) {
                    octet_size += strlen(line);
                    current_email.append(line);
                }
                for (int i = 0; i < MAX_CMD_LENGTH; i++) { line[i] = 0; }
            }
            int lseek_ret = fseek(inputFile, 0, SEEK_SET);
            if (lseek_ret < 0) {
                perror("LSeek Error.\n");
                exit(EXIT_FAILURE);
            }

            if (insideMessage) {
                unsigned char digest_buffer[MAX_LINE_LENGTH] = {0};
                computeDigest((char*)current_email.c_str(), current_email.size(), digest_buffer);
                string output = hash_to_string(digest_buffer);
                all_email_hashes.push_back(output);
            }

            if (desired_email_idx != 0 && desired_email_idx <= all_email_hashes.size()) {
                if (cur_deletion_idx_set.count(desired_email_idx) == 0) {
                    string ok_specific_index = "+OK " + to_string(desired_email_idx) + " " + all_email_hashes[desired_email_idx-1] + "\r\n";
                    do_write(comm_fd, (char*) ok_specific_index.c_str(), ok_specific_index.size());
                    log_message(comm_fd, (char*) ok_specific_index.c_str(), SERVER_MESSAGE);
                    continue;
                } else {
                    string err_deleted_idx = "-ERR Trying to UIDL a deleted message";
                    do_write(comm_fd, (char*) err_deleted_idx.c_str(), err_deleted_idx.size());
                    log_message(comm_fd, (char*) err_deleted_idx.c_str(), SERVER_MESSAGE);
                    continue;
                }     
            }

            if (desired_email_idx > all_email_hashes.size()) {
                do_write(comm_fd, (char*) ERR_INVALID_UIDL.c_str(), ERR_INVALID_UIDL.size());
                log_message(comm_fd, (char*) ERR_INVALID_UIDL.c_str(), SERVER_MESSAGE);
                continue;
            }
            
            if (all_email_hashes.size() == 0) {
                string ok_done = "+OK.\r\n";
                do_write(comm_fd, (char*) ok_done.c_str(), ok_done.size());
                log_message(comm_fd, (char*) ok_done.c_str(), SERVER_MESSAGE);
                continue;
            }

            string ok = "+OK\r\n";
            do_write(comm_fd, (char*)ok.c_str(), ok.size());
            log_message(comm_fd, (char*) ok.c_str(), SERVER_MESSAGE);
            for (int i = 0; i < all_email_hashes.size(); i++) {
                if (cur_deletion_idx_set.count(i)) {
                    continue;
                }
		        int nummy = i+1;
                string output = to_string(nummy) + " " + all_email_hashes[i] + "\r\n";
                do_write(comm_fd, (char*) output.c_str(), output.size());
		        log_message(comm_fd, (char*) output.c_str(), SERVER_MESSAGE);
            }
            string done = ".\r\n";
            do_write(comm_fd, (char*) done.c_str(), done.size());
            log_message(comm_fd, (char*) done.c_str(), SERVER_MESSAGE);
        } else if (str_equals(args[0], RETR_cmd)) {
            if (stage != TRANSACTION) {
                do_write(comm_fd, (char*)ERR_INVALID_CMD_ORDER.c_str(), ERR_INVALID_CMD_ORDER.size());
                log_message(comm_fd, (char*)ERR_INVALID_CMD_ORDER.c_str(), SERVER_MESSAGE);
                continue;
            }

            if (args.size() < 2) {
		        log_message(comm_fd, (char*)ERR_INVALID_RETR_IDX.c_str(), SERVER_MESSAGE);
                do_write(comm_fd, (char*)ERR_INVALID_RETR_IDX.c_str(), ERR_INVALID_RETR_IDX.size());
                continue;
            }
	    
            int desired_email_idx = 0;
            desired_email_idx = stoi(args[1]);
            if (desired_email_idx < 1) {
                do_write(comm_fd, (char*)ERR_INVALID_RETR_IDX.c_str(), ERR_INVALID_RETR_IDX.size());
                log_message(comm_fd, (char*)ERR_INVALID_RETR_IDX.c_str(), SERVER_MESSAGE);
                continue;
            }

            char line[MAX_CMD_LENGTH] = {0};
            bool insideMessage = false;
            string new_email_marker = "FROM ";
            int num_emails = 0;
            int octet_size = 0;
            string current_email = "";

            while (fgets(line, 1000, inputFile) != NULL) {
                string first_four(line, 5);
                if (str_equals(first_four, new_email_marker)) {
                    if (num_emails == desired_email_idx) {
                        break;
                    }
                    current_email.assign("");
                    num_emails++;
                    insideMessage = true;
                } else if (insideMessage) {
                    octet_size += strlen(line);
                    current_email.append(line);
                }
                for (int i = 0; i < MAX_CMD_LENGTH; i++) { line[i] = 0; }
            }

            if (insideMessage) {
                current_email.append(line);
            } 

            int lseek_ret = fseek(inputFile, 0, SEEK_SET);
            if (lseek_ret < 0) {
                perror("LSeek Error.\n");
                exit(EXIT_FAILURE);
            }

            if (desired_email_idx > num_emails) {
                do_write(comm_fd, (char*)ERR_INVALID_RETR_IDX.c_str(), ERR_INVALID_RETR_IDX.size());
                log_message(comm_fd, (char*)ERR_INVALID_RETR_IDX.c_str(), SERVER_MESSAGE);
                continue;
            }

            if (cur_deletion_idx_set.count(desired_email_idx) == 0) {
                do_write(comm_fd, (char*)OK_VALID_RETR.c_str(), OK_VALID_RETR.size());
                log_message(comm_fd, (char*)OK_VALID_RETR.c_str(), SERVER_MESSAGE);
                string email_plus_chars = current_email + ".\r\n";
                do_write(comm_fd, (char*)email_plus_chars.c_str(), email_plus_chars.size());
            } else {
                string err_deleted_idx = "-ERR Trying to RETR a deleted message";
                do_write(comm_fd, (char*) err_deleted_idx.c_str(), err_deleted_idx.size());
                log_message(comm_fd, (char*)err_deleted_idx.c_str(), SERVER_MESSAGE);
            }   
        } else if (str_equals(args[0], DELE_CMD)) {
            if (stage != TRANSACTION) {
                do_write(comm_fd, (char*)ERR_INVALID_CMD_ORDER.c_str(), ERR_INVALID_CMD_ORDER.size());
                log_message(comm_fd, (char*)ERR_INVALID_CMD_ORDER.c_str(), SERVER_MESSAGE);
                continue;
            }

            if (args.size() < 2) {
                do_write(comm_fd, (char*)ERR_INVALID_DELE_IDX.c_str(), ERR_INVALID_DELE_IDX.size());
                log_message(comm_fd, (char*)ERR_INVALID_DELE_IDX.c_str(), SERVER_MESSAGE);
                continue;
            }

            int desired_email_idx = 0;
            desired_email_idx = stoi(args[1]);
            if (desired_email_idx < 1) {
                do_write(comm_fd, (char*)ERR_INVALID_DELE_IDX.c_str(), ERR_INVALID_DELE_IDX.size());
                log_message(comm_fd, (char*)ERR_INVALID_DELE_IDX.c_str(), SERVER_MESSAGE);
                continue;
            }

            if (cur_deletion_idx_set.count(desired_email_idx) != 0) {
                string err_index = "-ERR Trying to delete a deleted email\r\n";
                do_write(comm_fd, (char*) err_index.c_str(), err_index.size());
                log_message(comm_fd, (char*)err_index.c_str(), SERVER_MESSAGE);
                continue;
            }

            char line[MAX_CMD_LENGTH] = {0};
            bool insideMessage = false;
            string new_email_marker = "FROM ";
            int num_emails = 0;
            int octet_size = 0;
            while (fgets(line, 1000, inputFile) != NULL) {
                string first_four(line, 5);
                if (str_equals(first_four, new_email_marker)) {
                    num_emails++;
                    insideMessage = true;
                } else if (insideMessage) {
                    octet_size += strlen(line);
                }
                for (int i = 0; i < MAX_CMD_LENGTH; i++) { line[i] = 0; }
            }
            int lseek_ret = fseek(inputFile, 0, SEEK_SET);
            if (lseek_ret < 0) {
                perror("LSeek Error.\n");
                exit(EXIT_FAILURE);
            }

            if (desired_email_idx > num_emails) {
                do_write(comm_fd, (char*) ERR_INVALID_DELE_IDX.c_str(), ERR_INVALID_DELE_IDX.size());
                log_message(comm_fd, (char*)ERR_INVALID_DELE_IDX.c_str(), SERVER_MESSAGE);
                continue;
            }

            cur_deletion_idx_set.insert(desired_email_idx);
            do_write(comm_fd, (char*)OK_VALID_DELE.c_str(), OK_VALID_DELE.size());
            log_message(comm_fd, (char*)OK_VALID_DELE.c_str(), SERVER_MESSAGE);
        } else if (str_equals(args[0], LIST_CMD)) {
            if (stage != TRANSACTION) {
                do_write(comm_fd, (char*)ERR_INVALID_CMD_ORDER.c_str(), ERR_INVALID_CMD_ORDER.size());
                log_message(comm_fd, (char*)ERR_INVALID_CMD_ORDER.c_str(), SERVER_MESSAGE);
                continue;
            }


            int desired_email_idx = 0;
            if (args.size() > 1) {
                desired_email_idx = stoi(args[1]);
            }

            if (desired_email_idx < 1 && args.size() > 1) {
                do_write(comm_fd, (char*)ERR_INVALID_EMAIL_IDX.c_str(), ERR_INVALID_EMAIL_IDX.size());
                log_message(comm_fd, (char*)ERR_INVALID_EMAIL_IDX.c_str(), SERVER_MESSAGE);
                continue;
            }

            vector<int> all_email_octets;

            char line[MAX_CMD_LENGTH] = {0};
            int count = 0;
            bool insideMessage = false;
            string new_email_marker = "FROM ";
            int num_emails = 0;
            int octet_size = 0;
            string current_email = "";
            while (fgets(line, 1000, inputFile) != NULL) {
                string first_four(line, 5);
                if (str_equals(first_four, new_email_marker)) {
                    if (num_emails != 0) {
                        all_email_octets.push_back(octet_size);
                        octet_size = 0;
                    }
                    current_email.assign("");
                    num_emails++;
                    insideMessage = true;
                } else if (insideMessage) {
                    octet_size += strlen(line);
                    current_email.append(line);
                }
                for (int i = 0; i < MAX_CMD_LENGTH; i++) { line[i] = 0; }
            }
            int lseek_ret = fseek(inputFile, 0, SEEK_SET);
            if (lseek_ret < 0) {
                perror("LSeek Error.\n");
                exit(EXIT_FAILURE);
            }

            if (num_emails == 0) {
                do_write(comm_fd, (char*) ERR_LIST_EMPTY_INBOX.c_str(), ERR_LIST_EMPTY_INBOX.size());
                log_message(comm_fd, (char*)ERR_LIST_EMPTY_INBOX.c_str(), SERVER_MESSAGE);
            }

            if (insideMessage) {
                all_email_octets.push_back(octet_size);
            }

            if (desired_email_idx != 0 && desired_email_idx <= all_email_octets.size()) {
                if (cur_deletion_idx_set.count(desired_email_idx) == 0) {
                    string ok_specific_index = "+OK " + to_string(desired_email_idx) + " " + to_string(all_email_octets[desired_email_idx-1]) + "\r\n";
                    do_write(comm_fd, (char*) ok_specific_index.c_str(), ok_specific_index.size());
                    log_message(comm_fd, (char*)ok_specific_index.c_str(), SERVER_MESSAGE);
                    continue;
                } else {
                    string err_deleted_idx = "-ERR Trying to LIST a deleted message";
                    do_write(comm_fd, (char*) err_deleted_idx.c_str(), err_deleted_idx.size());
                    log_message(comm_fd, (char*)err_deleted_idx.c_str(), SERVER_MESSAGE);
                    continue;
                }     
            }

            if (desired_email_idx > all_email_octets.size()) {
                do_write(comm_fd, (char*) ERR_LIST_INVALID_INDEX.c_str(), ERR_LIST_INVALID_INDEX.size());
                log_message(comm_fd, (char*)ERR_LIST_INVALID_INDEX.c_str(), SERVER_MESSAGE);
                continue;
            }
            
            if (all_email_octets.size() == 0) {
                string ok_done = "+OK.\r\n";
                do_write(comm_fd, (char*) ok_done.c_str(), ok_done.size());
                log_message(comm_fd, (char*)ok_done.c_str(), SERVER_MESSAGE);
                continue;
            }

            

            string ok = "+OK\r\n";
            do_write(comm_fd, (char*)ok.c_str(), ok.size());
            log_message(comm_fd, (char*)ok.c_str(), SERVER_MESSAGE);
            for (int i = 0; i < all_email_octets.size(); i++) {
                string output = to_string(i+1) + " " + to_string(all_email_octets[i]) + "\r\n";
                do_write(comm_fd, (char*) output.c_str(), output.size());
                log_message(comm_fd, (char*)output.c_str(), SERVER_MESSAGE);
            }
            string done = ".\r\n";
            do_write(comm_fd, (char*) done.c_str(), done.size());
            log_message(comm_fd, (char*)done.c_str(), SERVER_MESSAGE);


        } else if (str_equals(args[0], RSET_CMD)) {
            if (stage != TRANSACTION) {
                do_write(comm_fd, (char*) ERR_INVALID_CMD_ORDER.c_str(), ERR_INVALID_CMD_ORDER.size());
                log_message(comm_fd, (char*)ERR_INVALID_CMD_ORDER.c_str(), SERVER_MESSAGE);
                continue;
            }

            cur_deletion_idx_set.clear();
            string ok = "+OK";
            do_write(comm_fd, (char*) ok.c_str(), ok.size());
            log_message(comm_fd, (char*)ok.c_str(), SERVER_MESSAGE);
        } else if (str_equals(args[0], NOOP_CMD)) {
            if (stage != TRANSACTION) {
                do_write(comm_fd, (char*) ERR_INVALID_CMD_ORDER.c_str(), ERR_INVALID_CMD_ORDER.size());
                log_message(comm_fd, (char*)ERR_INVALID_CMD_ORDER.c_str(), SERVER_MESSAGE);
                continue;
            }

            string ok = "+OK";
            do_write(comm_fd, (char*) ok.c_str(), ok.size());
            log_message(comm_fd, (char*)ok.c_str(), SERVER_MESSAGE);
        } else if (str_equals(args[0], QUIT_CMD)) {
            if (stage == AUTHORIZATION) {
                do_write(comm_fd, (char*)OK_VALID_QUIT.c_str(), OK_VALID_QUIT.size());
                log_message(comm_fd, (char*)OK_VALID_QUIT.c_str(), SERVER_MESSAGE);
                connection->is_completed = true;
                close(comm_fd);
                pthread_exit(NULL);
            }
            stage = UPDATE;

            if (cur_deletion_idx_set.size()) {
                string temp_box = directory_path + cur_user_inbox + ".temp";
                int temp_open = open(temp_box.c_str(), O_CREAT | O_RDWR, 0644);
                if (temp_open < 0) {
                    perror("Open error.");
                    exit(EXIT_FAILURE);
                }
                char line[MAX_CMD_LENGTH] = {0};
                bool insideMessage = false;
                string new_email_marker = "FROM ";
                int num_emails = 0;
                int octet_size = 0;
                bool writable_email = false;
                while (fgets(line, 1000, inputFile) != NULL) {
                    string first_four(line, 5);
                    if (str_equals(first_four, new_email_marker)) {
                        num_emails++;
                        if (cur_deletion_idx_set.count(num_emails) == 0) {
                            writable_email = true;
                            write(temp_open, line, sizeof(line));
                        } else {
                            writable_email = false;
                        }
                        insideMessage = true;
                    } else if (insideMessage && writable_email) {
                        octet_size += strlen(line);
                        write(temp_open, line, sizeof(line));
                    }
                    for (int i = 0; i < MAX_CMD_LENGTH; i++) { line[i] = 0; }
                }

                int lseek_ret = fseek(inputFile, 0, SEEK_SET);
                if (lseek_ret < 0) {
                    perror("LSeek Error.\n");
                    exit(EXIT_FAILURE);
                }
                int lseek_temp_ret = lseek(temp_open, (off_t) 0, SEEK_SET);
                if (lseek_temp_ret < 0) {
                    perror("LSeek Error.\n");
                    exit(EXIT_FAILURE);
                }


                string full_path = directory_path + cur_user_inbox;
                int rewrite_fd = open((char*)full_path.c_str(), O_TRUNC | O_WRONLY);

                char rewrite_temp_buffer[1] = {0};
                while (read(temp_open, rewrite_temp_buffer, sizeof(rewrite_temp_buffer))) {
                    write(rewrite_fd, rewrite_temp_buffer, sizeof(rewrite_temp_buffer));
                }

                
                close(temp_open);
                close(rewrite_fd);
                remove((char *)temp_box.c_str());
            }
            
            connection->is_completed;
            close(cur_inbox_fd);
            pthread_mutex_unlock(&email_map[cur_user_inbox]);
            do_write(comm_fd, (char*)OK_VALID_QUIT.c_str(), OK_VALID_QUIT.size());
            log_message(comm_fd, (char*)OK_VALID_QUIT.c_str(), SERVER_MESSAGE);
            close(comm_fd);
            pthread_exit(NULL);
        } else {
            do_write(comm_fd, (char*) ERR_UNKNOWN_CMD.c_str(), ERR_UNKNOWN_CMD.size());
            log_message(comm_fd, (char*)ERR_UNKNOWN_CMD.c_str(), SERVER_MESSAGE);
        }
    } 

    // In debug mode tell the server that we're closing the connection unpon threads being ended
    log_message(comm_fd, (char*)"Connection closed\n", GENERAL_MESSAGE);

    if (inputFile != NULL) {
        fclose(inputFile);
    }

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
    int port_no = 11000; 

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

    for (auto elem : email_map) {
        pthread_mutex_destroy(&elem.second);
    }

    close(listen_fd);
    return 0;
}
