#pragma once

#include <assert.h>
#include <stdlib.h>

#include "type.h"

byte_t from_hex(char hex);
char to_hex(byte_t num);

byte_t * hex_to_bytes(const char * hex, size_t h_len, size_t * bytes_len);
char * bytes_to_hex(const byte_t * bytes, const size_t bt_len);

byte_t from_base64(char b64);
char to_base64(byte_t digit);

char * bytes_to_base64(const byte_t * bytes, size_t bt_len);
byte_t * base64_to_bytes(const char * base64, const size_t b64_len, size_t * bt_len);

char * hex_to_base64(const char * hex);
