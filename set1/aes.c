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
