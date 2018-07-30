#pragma once

#include <stdint.h>

typedef uint8_t byte_t;

// Converts string literal to byte ptr. Works best with ascii
#define BYTE_STR(str_lit) (const byte_t *)str_lit
