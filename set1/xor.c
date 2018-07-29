#include <string.h>

#include "type.h"
#include "convert.h"
#include "letter_score.h"
#include "xor.h"

byte_t * xor_bytes(const byte_t * buf1, const byte_t * buf2, const size_t len) {
    byte_t * xor = malloc(len);
    if (xor == NULL) {
        return NULL;
    }
    for (size_t i = 0; i < len; i++) {
        xor[i] = buf1[i] ^ buf2[i];
    }
    return xor;
}

char * xor_hex(const char * hex1, const char * hex2) {
    char * result = NULL;
    size_t len1, len2;
    byte_t * buf1 = hex_to_bytes(hex1, strlen(hex1), &len1);
    byte_t * buf2 = hex_to_bytes(hex2, strlen(hex2), &len2);

    if (buf1 && buf2) {
        assert(len1 == len2);
        byte_t * xor = xor_bytes(buf1, buf2, len1);
        if (xor) {
            result = bytes_to_hex(xor, len1);
        }
        free(xor);
    }
    free(buf1);
    free(buf2);
    return result;
}

// Xors each byte of the buffer against a single byte. Result is stored in out buffer
void single_byte_xor(const byte_t * buf, byte_t * out, const size_t len, byte_t byte) {
    for (size_t i = 0; i < len; i++) {
        out[i] = buf[i] ^ byte;
    }
}

// Xors input buffer against all possible chars to find the result with the highest letter score
// Returns the newly allocated result along with the key that produced it and its score
byte_t * break_xor_cipher(const byte_t * buf, const size_t len, int * res_score, byte_t * res_key) {
    // The default score may be -ve in future
    int best_score = 0;
    byte_t key = 0x0;
    byte_t * plain = malloc(len);
    if (plain == NULL) {
        goto end;
    }
    
    for (byte_t b = 0; b < 256; b++) {
        single_byte_xor(buf, plain, len, b);
        int score = score_text(plain);
        if (score > best_score) {
            best_score = score;
            key = b;
        }
    }

    // Retrieve the plaintext produced by the winning key
    single_byte_xor(buf, plain, len, key);
end:
    *res_score = best_score;
    *res_key = key;
    return plain;
}
