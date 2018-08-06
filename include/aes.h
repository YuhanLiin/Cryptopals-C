#include "type.h"

int decrypt_aes(const byte_t * cipher,
                     const size_t len,
                     byte_t * out,
                     const byte_t * key);

int decrypt_aes_file(const char * filename, const byte_t * key, byte_t * out);

size_t count_repeated_blocks(const byte_t * bytes,
                             const size_t blk_size,
                             const size_t blk_count);

byte_t * detect_aes_ecb(const char * filename);
