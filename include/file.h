#include <stdio.h>
#include <string.h>

#define DATA_PATH(filename) "data/"filename

// A for loop macro that reads a line from specified file each time and strips line endings
#define READ_LINES(path, file_var, line, line_len) for (\
    FILE * file_var = fopen(path, "r");\
    (file_var != NULL && fgets(line, line_len, file_var)) &&\
    ((line[strcspn(line, "\n\r")] = '\0') || 1);\
)
