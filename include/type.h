#pragma once

#include <stdint.h>
#include <string.h>

typedef uint8_t byte_t;

// Converts string literal to byte ptr. Works best with ascii
#define BYTE_STR(str) (const byte_t *)str
