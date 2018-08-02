#include <string.h>
#include <assert.h>
#include <stdlib.h>

#include "type.h"
#include "convert.h"

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

// Converts 4-bit number (lower half of byte) to hex char
char to_hex(byte_t num) {
    assert(num < 16);
    if (num < 10) {
        return '0' + num;
    }
    return 'a' + num - 10;
}

// Converts array of hex characters into array of bytes of correct size
// Returns dynamically allocated byte array ptr and its length
byte_t * hex_to_bytes(const char * hex, const size_t h_len, size_t * bytes_len) {
    const size_t bt_len = (h_len + 1) / 2;
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
    for (; h_idx < h_len; h_idx += 2, b_idx++) {
        byte_t byte = from_hex(hex[h_idx]) << 4;
        byte |= (unsigned)from_hex(hex[h_idx + 1]);
        bytes[b_idx] = byte;
    }
    return bytes;
}

// Convert bytes into hex array
char * bytes_to_hex(const byte_t * bytes, const size_t bt_len) {
    const size_t h_len = bt_len * 2;
    // Reserve 1 more spot for null character
    char * hex = malloc(h_len + 1);
    if (hex == NULL) return NULL;

    for (size_t b_idx = 0, h_idx = 0; b_idx < bt_len; b_idx++, h_idx += 2) {
        byte_t byte = bytes[b_idx];
        // Extract upper 4 bits
        hex[h_idx] = to_hex(byte >> 4);
        // Extract lower 4 bits
        hex[h_idx + 1] = to_hex(byte & 0x0fu);
    }
    // Place the null char
    hex[h_len] = '\0';
    return hex;
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
    out[1] = to_base64(((b1 << 4) & 0x3fu) | (b2 >> 4));
    // Take the lower 4 bits of byte 2 and upper 2 bits of byte 3 as 3rd b64
    out[2] = to_base64(((b2 << 2) & 0x3fu) | (b3 >> 6));
    // Take the lower 6 bits of byte 3 as 4th b64
    out[3] = to_base64(b3 & 0x3fu);
}

char * bytes_to_base64(const byte_t * bytes, const size_t bt_len) {
    // Every 3 bytes convert to 4 base64 numbers, so divide by 3 (round up) then multiply by 4
    const size_t b64_len = (bt_len + 2) / 3 * 4;

    // Allocate an extra spot for the null char
    char * base64 = malloc(b64_len + 1);
    if (base64 == NULL) {
        return NULL;
    }
    
    size_t b_idx = 0, b64_idx = 0;
    for (; b_idx < bt_len; b_idx += 3, b64_idx += 4) {
        if (b_idx == bt_len - 1) {
            // Only 1 byte left, so 2 padding b64s are needed
            byte_chunk_to_base64(bytes[b_idx], 0, 0, &base64[b64_idx]);
            base64[b64_idx + 2] = '=';
            base64[b64_idx + 3] = '=';
        } else if (b_idx == bt_len - 2) {
            // Only 2 bytes left, so 1 padding b64s are needed
            byte_chunk_to_base64(bytes[b_idx], bytes[b_idx+1], 0, &base64[b64_idx]);
            base64[b64_idx + 3] = '=';
        } else {
            byte_chunk_to_base64(bytes[b_idx], bytes[b_idx+1], bytes[b_idx+2], &base64[b64_idx]);
        }
    }
    base64[b64_len] = '\0';
    return base64;
}

// Converts hex string to bytes, then to base64 string. Caller must clean up base64 string
char * hex_to_base64(const char * hex) {
    char * base64 = NULL;
    size_t bt_len;
    byte_t * bytes = hex_to_bytes(hex, strlen(hex), &bt_len);
    if (bytes) {
        base64 = bytes_to_base64(bytes, bt_len);
    }
    free(bytes);
    return base64;
}
