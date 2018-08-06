#pragma once

#include <stdio.h>
#include <stdlib.h>
#include <string.h>

#define DATA_PATH(filename) "data/"filename

// A for loop macro that reads a line from specified file each time and strips line endings
// Also populates a variable with the length of the line
#define READ_LINES(file, line, line_len_var, line_cap) for (;\
    fgets(line, line_cap, file) &&\
    ((line[line_len_var = strcspn(line, "\n\r")] = '\0') || 1);\
)
