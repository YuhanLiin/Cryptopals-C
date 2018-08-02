#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DATA_PATH(filename) "data/"filename

// A for loop macro that reads a line from specified file each time and strips line endings
// Also populates a variable with the length of the line
#define READ_LINES(file, line, line_len, line_cap) for (;\
    fgets(line, line_cap, file) &&\
    ((line[line_len = strcspn(line, "\n\r")] = '\0') || 1);\
)

// Reads entire file into a malloced string and returns it along with its length.
// On failure returns NULL and sets invalid length value.
static inline char * read_file_contents(const char * path, size_t * len_ptr) {
    char * contents = NULL;
    long int len = 0;
    FILE * file = fopen(path, "rb");
    if (file) {
        if (fseek(file, 0, SEEK_END) == 0) {
            len = ftell(file);
            if (len >= 0) {
                rewind(file);
                contents = malloc(len * sizeof(char));
                if (contents) {
                    fread(contents, sizeof(char), len, file);
                }
            }
        }
        fclose(file);
    }
    *len_ptr = len;
    return contents;
}
