#include "type.h"

int decrypt_aes(const byte_t * cipher,
                     const size_t len,
                     byte_t * out,
                     const byte_t * key);

int decrypt_aes_file(const char * filename, const byte_t * key, byte_t * out);
