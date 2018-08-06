#include <stdbool.h>

#include <openssl/evp.h>
#include <openssl/ssl.h>
#include <openssl/rsa.h>
#include <openssl/x509.h>

#include "type.h"
#include "convert.h"
#include "file.h"

// Decrypts ciphertext using AES in ECB mode via OpenSSL. Assumes key and IV lengths are valid
// Returns size of plaintext or -1 on failure
int decrypt_aes(const byte_t * cipher,
                     const size_t len,
                     byte_t * out,
                     // The key buffer needs to be null terminated
                     const byte_t * key) {
    EVP_CIPHER_CTX * ctx = EVP_CIPHER_CTX_new();
    if (ctx == NULL) goto error;
    // Check lengths?
    EVP_CipherInit_ex(ctx, EVP_aes_128_ecb(), NULL, NULL, NULL, 0);
    EVP_CipherInit_ex(ctx, NULL, NULL, key, BYTE_STR("1234567890123456"), 0);

    int out_len;
    if (!EVP_CipherUpdate(ctx, out, &out_len, cipher, len)) {
        out_len = -1;
        goto error;
    }
    int final_len;
    if (!EVP_CipherFinal_ex(ctx, out + out_len, &final_len)) {
        out_len = -1;
        goto error;
    }
    out_len += final_len;
error:
    EVP_CIPHER_CTX_free(ctx);
    return out_len;
}

#define MAX_FILE_LEN 8000

// Decrypt base64 file with the given key using AES
// Key needs to be null-terminated
// Returns length of decrypted output or -1 on error
int decrypt_aes_file(const char * filename, const byte_t * key, byte_t * out) {
    int out_len = -1;
    FILE * file = fopen(filename, "r");
    if (file) {
        char base64[MAX_FILE_LEN + 1];
        size_t b64_len;
        // Get last and only line of the base64 file
        READ_LINES(file, base64, b64_len, sizeof(base64));

        // Convert file to bytes
        size_t b_len;
        byte_t * bytes = base64_to_bytes(base64, b64_len, &b_len);
        if (bytes) {
            out_len = decrypt_aes(bytes, b_len, out, key);
            free(bytes);
        }
        fclose(file);
    }
    return out_len;
}

static bool bytes_eq(const byte_t * b1, const byte_t * b2, const size_t len) {
    for (size_t i = 0; i < len; i++) {
        if (b1[i] != b2[i]) return false;
    }
    return true;
}

// Count number of repeated blocks in the text. Assumes that length == blk_size * blk_count
size_t count_repeated_blocks(const byte_t * bytes,
                             const size_t blk_size,
                             const size_t blk_count) {
    size_t repeat = 0;
    for (size_t i = 0; i < blk_count; i++) {
        for (size_t j = i + 1; j < blk_count; j++) {
            if (bytes_eq(bytes + i * blk_size, bytes + j * blk_size, blk_size)) {
                repeat += 1;
            }
        }
    }
    return repeat;
}

#define MAX_LINE_LEN 1000
#define BLK_SIZE 16
// Find the line in a hex file with the highest number of repeated 16-byte blocks
// Returns null on fail
byte_t * detect_aes_ecb(const char * filename, size_t * len) {
    size_t highest_repeats = 0, best_len = 0;
    byte_t * best_text = NULL;

    FILE * file = fopen(filename, "r");
    if (file == NULL) goto end;
    char line[MAX_LINE_LEN];
    size_t line_len;
    // Find the line in the text with the most number of repeated 16-byte blocks
    READ_LINES(file, line, line_len, sizeof(line)) {
        // Convert each line from hex to bytes
        size_t b_len;
        byte_t * bytes = hex_to_bytes(line, line_len, &b_len);
        if (bytes == NULL) continue;

        assert(b_len % BLK_SIZE == 0);
        size_t repeats = count_repeated_blocks(bytes, BLK_SIZE, b_len / BLK_SIZE);
        if (repeats > highest_repeats) {
            highest_repeats = repeats;
            best_len = b_len;
            free(best_text);
            best_text = bytes;
        } else {
            free(bytes);
        }
    }
    fclose(file);
end:
    *len = best_len;
    return best_text;
}
