#pragma once

#include "type.h"

byte_t * xor_bytes(const byte_t * buf1, const byte_t * buf2, const size_t len);

char * xor_hex(const char * hex1, const char * hex2);

void single_byte_xor(const byte_t * buf, byte_t * out, const size_t len, byte_t byte);

byte_t * break_xor_cipher(const byte_t * buf, const size_t len, int * res_score, byte_t * res_key);


