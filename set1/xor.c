#include <string.h>

#include "type.h"
#include "convert.h"
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
