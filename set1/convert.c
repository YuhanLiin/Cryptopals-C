#include <assert.h>
#include <stdlib.h>

#include "type.h"

// Converts hex character to 4-bit number in the lower half of a byte
byte_t from_hex(char hex) {
    switch (hex) {
        case '0': return 0;
        case '1': return 1;
        case '2': return 2;
        case '3': return 3;
        case '4': return 4;
        case '5': return 5;
        case '6': return 6;
        case '7': return 7;
        case '8': return 8;
        case '9': return 9;
        case 'a': return 10;
        case 'b': return 11;
        case 'c': return 12;
        case 'd': return 13;
        case 'e': return 14;
        case 'f': return 15;
        default:
            assert(0 && "Not a valid hex");
    }
}

// Converts array of hex characters into array of bytes of correct size
// Returns dynamically allocated byte array ptr and its length
byte_t * hex_to_bytes(const char * hex, size_t h_len, size_t * bytes_len) {
    size_t bt_len = (h_len + 1) / 2;
    byte_t * bytes = malloc(bt_len);
    if (bytes == NULL) {
        *bytes_len = 0;
        return NULL;
    }
    // Set the byte array length
    *bytes_len = bt_len;

    size_t h_idx = 0, b_idx = 0;
    // An odd # of hexes mean the 1st byte has a zeroed upper half, with the 1st hex as the lower half
    if (h_len % 2 == 1) {
        bytes[0] = from_hex(hex[0]);
        h_idx = 1;
        b_idx = 1;
    } 

    assert((bt_len - b_idx) * 2 == (h_len - h_idx));
    for (; h_idx < h_len; h_len += 2, bt_len++) {
        byte_t byte = from_hex(hex[h_idx]);
        byte &= from_hex(hex[h_idx + 1]);
        bytes[b_idx] = byte;
    }
    return bytes;
}

// Converts base64 digit to its character representation. Assumes the digit is <64
char to_base64(byte_t digit) {
    if (digit < 26) {
        return 'A' + digit;
    }
    if (digit < 52) {
        return 'a' + digit - 26;
    }
    if (digit < 62) {
        return '0' + digit - 52;
    }
    if (digit == 62) return '+';
    if (digit == 63) return '/';
    assert(0 && "Invalid base64 digit");
}

// Converts 3 bytes to 4 base64 characters. Assumes output pointer has at least 4 chars allocated
static void byte_chunk_to_base64(byte_t b1, byte_t b2, byte_t b3, char * out) {
    // Take the upper 6 bits of byte 1 as the 1st b64
    out[0] = to_base64(b1 >> 2);
    // Take the lower 2 bits of byte 1 and upper 4 bits of byte 2 as 2nd b64
    out[1] = to_base64((b1 << 4) & 0x00ffffff | (b2 >> 4));
    // Take the lower 4 bits of byte 2 and upper 2 bits of byte 3 as 3rd b64
    out[2] = to_base64((b2 << 2) & 0x00ffffff | (b3 >> 6));
    // Take the lower 6 bits of byte 3 as 4th b64
    out[3] = to_base64(b3 & 0x00ffffff);
}

char * bytes_to_base64(const byte_t * bytes, size_t bt_len) {
    // Every 3 bytes convert to 4 base64 numbers, so divide by 3 (round up) and times 4.
    size_t b64_len = (bt_len + 2) / 3 * 4;

    // Allocate an extra spot for the null char
    char * base64 = malloc(b64_len + 1);
    if (base64 == NULL) {
        return NULL;
    }
    
    size_t b_idx = 0, b64_idx = 0;
    size_t extra_bytes = bt_len % 3;
    if (extra_bytes == 1) {
        byte_chunk_to_base64(0, 0, bytes[0], base64);
        // 1 byte = 2 base64, so we want the 1st byte to align with the 1st and 2nd base64
        base64[0] = base64[2];
        base64[1] = base64[3];
        b_idx = 1, b64_idx = 2;
    }
    else if (extra_bytes == 2) {
        byte_chunk_to_base64(0, bytes[0], bytes[1], base64);
        // 2 bytes = 3 base64, so we want bytes 1 and 2 to align with 1st, 2nd, and 3rd base64
        base64[0] = base64[1];
        base64[1] = base64[2];
        base64[2] = base64[3];
        b_idx = 2, b64_idx = 3;
    }
    
    // The # of b64s remaining should be 4/3 of the # of bytes remaining
    assert((b64_len - b64_idx) * 3 == (bt_len - b_idx) * 4);
    for (; b_idx < bt_len; b_idx += 3, b64_idx += 4) {
        byte_chunk_to_base64(bytes[b_idx], bytes[b_idx+1], bytes[b_idx+2], &base64[b64_idx]);
    }
    base64[b64_len] = '\0';
    return base64;
}
