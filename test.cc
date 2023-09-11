#include <iostream>
#include <cstdio>
#include <cstring>
#include <openssl/md5.h>

using namespace std;

void computeDigest(char *data, int dataLengthBytes, unsigned char *digestBuffer);

int main() {
    FILE* inputFile = fopen("input.txt", "r");
    char line[1000];
    int count = 0;
    bool insideMessage = false;
    unsigned char digestBuffer[MD5_DIGEST_LENGTH];

    while (fgets(line, 1000, inputFile) != NULL) {
        if (strncmp(line, "FROM ", 5) == 0) {
            if (insideMessage) {
                cout << "Number of lines in message: " << count << endl;
                computeDigest(message, messageLength, digestBuffer);
                cout << "MD5 hash: ";
                for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
                    printf("%02x", digestBuffer[i]);
                }
                cout << endl;
            }
            insideMessage = true;
            count = 0;
            message[0] = '\0';
            messageLength = 0;
            MD5_Init(&c);
        }
        else if (insideMessage) {
            count++;
            messageLength += strlen(line);
            strncat(message, line, strlen(line));
        }
    }

    if (insideMessage) {
        cout << "Number of lines in message: " << count << endl;
        computeDigest(message, messageLength, digestBuffer);
        cout << "MD5 hash: ";
        for (int i = 0; i < MD5_DIGEST_LENGTH; i++) {
            printf("%02x", digestBuffer[i]);
        }
        cout << endl;
    }

    fclose(inputFile);

    return 0;
}

void computeDigest(char *data, int dataLengthBytes, unsigned char *digestBuffer) {
    MD5_CTX c;
    MD5_Init(&c);
    MD5_Update(&c, data, dataLengthBytes);
    MD5_Final(digestBuffer, &c);
}
