#include <assert.h>
#include <math.h>
#include <stdlib.h>

#include "type.h"
#include "xor.h"

#define MAX_KEYSIZE 40
#define MIN_KEYSIZE 2

size_t edit_distance(const byte_t * str1, const byte_t * str2, const size_t len) {
    size_t total = 0;
    for (size_t i = 0; i < len; ++i) {
        byte_t xor = str1[i] ^ str2[i];
        for (size_t _ = 0; _ < 8; ++_) {
            total += xor & 1; 
            xor >>= 1;
        }
    }
    return total;
}

// With a given keysize, allocate and return key used for the cipher. Decrypts the cipher in place.
static byte_t * find_key(byte_t * bytes, const size_t len, const size_t keysize) {
    const size_t blk_cap = len / keysize + 1; 
    byte_t * key = malloc(keysize);
    if (key == NULL) return NULL;

    for (size_t k = 1; k <= keysize; k++) {
        size_t start = k - 1;
        byte_t block[blk_cap];
        // Form a block of all the characters encrypted with byte k of the repeated key
        size_t blk_len = 0;
        for (size_t i = start; i < len; i += keysize, blk_len++) {
            block[blk_len] = bytes[i];
        }
        assert(blk_len <= blk_cap);
        
        // Decode the block using single byte xor. This also reveals the kth byte of the key.
        int score; byte_t key_byte;
        byte_t * decoded_blk = break_xor_cipher(block, blk_len, &score, &key_byte);
        // Having the decoded block be NULL means allocation failure OR no valid key has been found
        // In the 2nd case it means one of the blocks cannot be decoded without an illegal character,
        // so we just give up.
        if (decoded_blk == NULL) goto error;

        // Decrypt the block with the single-byte key
        for (size_t i = start; i < len; i += keysize) {
            bytes[i] ^= key_byte;
        }
        free(decoded_blk);
    }
    return key;
error:
    free(key);
    return NULL;
}

// Returns the repeated key and its length as well as decrypting the byte string in place.
// On failure (no memory or valid key) null is returned and the length and byte string are invalidated.
byte_t * break_repeating_xor(byte_t * bytes, const size_t len, size_t * key_len) {
    // Algorithm only works on strings at least 2 keysizes long
    if (len < MIN_KEYSIZE * 2) {
        return NULL;
    }
    // As such, the max keysize can't be more than half the string length
    const size_t max_keysize = MIN(len / 2, MAX_KEYSIZE);

    float min_norm_dist = INFINITY; 
    size_t best_keysize = MIN_KEYSIZE;
    for (size_t keysize = MIN_KEYSIZE; keysize <= max_keysize; keysize++) {
        // Find edit distance between first and second keysized chunks of the string
        size_t dist = edit_distance(&bytes[0], &bytes[keysize], keysize);
        // Normalize distance by dividing by keysize.
        // The keysize with the lowest normalized edit distance is the right one
        float norm_dist = dist / (float)keysize;
        if (norm_dist < min_norm_dist) {
            min_norm_dist = norm_dist;
            best_keysize = keysize;
        }
    }
    *key_len = best_keysize;
    return find_key(bytes, len, best_keysize);
}
