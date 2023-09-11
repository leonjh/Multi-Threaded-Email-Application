#pragma once

#include "constants.h"
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>


typedef struct email_file_st {
    char mbox_name[MAX_FILE_LENGTH];
    pthread_mutex_t mutex;
} email_file_t;

email_file_t *init_email_file(char name[]);

void delete_email_file(email_file_t *email);