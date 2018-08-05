#include "type.h"

size_t edit_distance(const byte_t * str1, const byte_t * str2, const size_t len);

byte_t * break_repeating_xor(byte_t * bytes,
                             const size_t len,
                             size_t * key_len);
