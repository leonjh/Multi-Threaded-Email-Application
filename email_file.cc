#include "email_file.h"

email_file_t *init_email_file(char name[]) {
    email_file_t *email_file = (email_file_t *)malloc(sizeof(email_file_t));

    if (email_file == NULL) {
        perror("Memory allocation failed - init_email_file");
        exit(EXIT_FAILURE);
    }

    for (int i = 0; i < strlen(name); i++) {
        email_file->mbox_name[i] = name[i];
    }

    return email_file;
}

void delete_email_file(email_file_t *email) {
    if (&email->mutex != NULL) {
        pthread_mutex_destroy(&email->mutex);
    }
    free(email);
}