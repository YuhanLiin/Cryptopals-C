#include <assert.h>
#include <stdlib.h>

#include "type.h"
#include "letter_score.h"
#include "xor.h"

#define MAX_KEYSIZE 40
#define MIN_KEYSIZE 2

size_t edit_distance(const byte_t * str1, const byte_t * str2, const size_t len) {
    size_t total = 0;
    for (size_t i = 0; i < len; ++i) {
        byte_t xor = str1[i] ^ str2[i];
        for (size_t _ = 0; _ < 8; ++_) {
            total += xor & 1u; 
            xor >>= 1;
        }
    }
    return total;
}

struct Key_tuple {
    float norm_dist;
    size_t key_len;
};

// Comparison function for key tuples. Finds the best key size by sorting the edit distances
int keycmp(const void * a, const void * b) {
    const struct Key_tuple * ka = a;
    const struct Key_tuple * kb = b;
    return ka->norm_dist - kb->norm_dist;
}

// With a given keysize, allocate and return the normalized letter score of the entire text.
// Decrypts the cipher in place and populates a buffer with the key bytes.
// On error or invalid plaintext MINIMUM_TEXT_SCORE is returned.
static float find_key(byte_t * bytes, const size_t len, byte_t * key, const size_t keysize) {
    const size_t blk_cap = len / keysize + 1; 
    int total_score = MINIMUM_TEXT_SCORE;

    for (size_t k = 0; k < keysize; k++) {
        byte_t block[blk_cap];
        size_t blk_len = 0;
        // Form a block of all the characters encrypted with byte k of the repeated key
        for (size_t i = k; i < len; i += keysize, blk_len++) {
            block[blk_len] = bytes[i];
        }
        assert(blk_len <= blk_cap);
        
        // Decode the block using single byte xor. This also reveals the kth byte of the key.
        int score;
        byte_t key_byte;
        byte_t * decoded_blk = break_xor_cipher(block, blk_len, &score, &key_byte);
        if (decoded_blk == NULL) break;
        // Minimum score means that this key length produces invalid characters 
        if (score == MINIMUM_TEXT_SCORE) break;

        key[k] = key_byte;
        total_score += score;

        // Decrypt the block with the single-byte key
        for (size_t i = k; i < len; i += keysize) {
            bytes[i] ^= key_byte;
        }
        free(decoded_blk);
    }
    return total_score / (float)len;
}

// Returns the repeated key and its length as well as decrypting the byte string in place.
// On failure (no memory or valid key) null is returned and the length and byte string are invalidated.
byte_t * break_repeating_xor(byte_t * bytes,
                             const size_t len,
                             size_t * key_len) {
    // Algorithm only works on strings at least 4 keysizes long
    if (len < MIN_KEYSIZE * 4) {
        return NULL;
    }
    // As such, the max keysize can't be more than half the string length
    const size_t max_keysize = MIN(len / 2, MAX_KEYSIZE);

    struct Key_tuple key_tuples[max_keysize - MIN_KEYSIZE];
    for (size_t keysize = MIN_KEYSIZE; keysize <= max_keysize; keysize++) {
        // Find edit distances between consecutive keysized chunks of the string
        size_t dist1 = edit_distance(&bytes[0], &bytes[keysize], keysize);
        size_t dist2 = edit_distance(&bytes[keysize], &bytes[keysize * 2], keysize);
        size_t dist3 = edit_distance(&bytes[keysize * 2], &bytes[keysize * 3], keysize);
        // Normalize distance by dividing by keysize.
        // The keysize with the lowest normalized edit distance is the right one
        float norm_dist = (dist1 + dist2 + dist3) / (float)keysize;
        key_tuples[keysize - MIN_KEYSIZE] =
            (struct Key_tuple){.norm_dist = norm_dist, .key_len = keysize};
    }

    qsort(
        key_tuples,
        sizeof(key_tuples) / sizeof(struct Key_tuple),
        sizeof(struct Key_tuple),
        &keycmp
    );

    byte_t cpy[len];
    byte_t * key = malloc(max_keysize);
    if (key == NULL) return NULL;

    size_t best_key_len = MIN_KEYSIZE;
    float best_key_score = MINIMUM_TEXT_SCORE;

    // Take the 5 best key lengths and find the one with the best score
    for (size_t i = 0; i < 5; i++) {
        memcpy(cpy, bytes, len);
        size_t k_len = key_tuples[i].key_len;
        float score = find_key(cpy, len, key, k_len);
        
        if (score > best_key_score) {
            best_key_len = k_len;
            best_key_score = score;
        }
    }

    // Retrieve the plaintext and key of the best key length
    find_key(bytes, len, key, best_key_len);
    *key_len = best_key_len;
    return key;
}
