#include <assert.h>
#include <stdlib.h>

#include "type.h"

byte_t from_hex(char hex);

byte_t * hex_to_bytes(const char * hex, size_t h_len, size_t * bytes_len);

char to_base64(byte_t digit);

char * bytes_to_base64(const byte_t * bytes, size_t bt_len);
