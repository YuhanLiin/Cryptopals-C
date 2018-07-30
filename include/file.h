#include <stdio.h>

// A for loop macro that reads a line from specified file each time
#define READ_LINES(filename, file_var, line, line_len) for (\
    FILE * file_var = fopen(filename, "r");\
    file_var != NULL && fgets(line, line_len, file_var);\
)
