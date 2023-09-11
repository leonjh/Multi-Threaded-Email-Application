#pragma once
#include <stdlib.h>
#include <string.h>
#include <stdio.h>
#include <unistd.h>
#include <arpa/inet.h>
#include <signal.h>
#include <pthread.h>
#include <fcntl.h>

#include <vector>
#include <cerrno>
#include <string>
#include <iostream>

using namespace std;

int count_tokens(char cmd[], int cmd_length);

void split_tokens(vector<string> &strings, char cmd[], int cmd_length);

void repair_string(char cmd[], int cmd_length);

void split_tokens_no_crlf(vector<string> &strings, char cmd[], int cmd_length);