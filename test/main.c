#include <stdlib.h>
#include <string.h>

#include "utils.h"

#include "convert.h"
#include "letter_score.h"
#include "xor.h"

tst_begin_test(FROM_HEX) {
    tst_assert_eq_uint(from_hex('0'), 0);
    tst_assert_eq_uint(from_hex('1'), 1);
    tst_assert_eq_uint(from_hex('2'), 2);
    tst_assert_eq_uint(from_hex('3'), 3);
    tst_assert_eq_uint(from_hex('4'), 4);
    tst_assert_eq_uint(from_hex('5'), 5);
    tst_assert_eq_uint(from_hex('6'), 6);
    tst_assert_eq_uint(from_hex('7'), 7);
    tst_assert_eq_uint(from_hex('8'), 8);
    tst_assert_eq_uint(from_hex('9'), 9);
    tst_assert_eq_uint(from_hex('a'), 10);
    tst_assert_eq_uint(from_hex('b'), 11);
    tst_assert_eq_uint(from_hex('c'), 12);
    tst_assert_eq_uint(from_hex('d'), 13);
    tst_assert_eq_uint(from_hex('e'), 14);
    tst_assert_eq_uint(from_hex('f'), 15);
} tst_end_test()

tst_begin_test(TO_HEX) {
    tst_assert_eq_char(to_hex(0), '0');
    tst_assert_eq_char(to_hex(9), '9');
    tst_assert_eq_char(to_hex(10), 'a');
    tst_assert_eq_char(to_hex(15), 'f');
} tst_end_test()

tst_begin_test(HEX_TO_BYTES) {
    const char * hex1 = "";
    const byte_t bytes1[] = {0};
    const char * hex2 = "f";
    const byte_t bytes2[] = {0xf};
    const char * hex3 = "40";
    const byte_t bytes3[] = {0x40};
    const char * hex4 = "125ae";
    const byte_t bytes4[] = {0x01, 0x25, 0xae};

    byte_t * bytes = NULL;
    size_t size;

    bytes = hex_to_bytes(hex1, strlen(hex1), &size);
    tst_assert_eq_uint(size, 0);
    tst_assert_eq_bytes(bytes, bytes1 , size);
    free(bytes);

    bytes = hex_to_bytes(hex2, strlen(hex2), &size);
    tst_assert_eq_uint(size, sizeof(bytes2));
    tst_assert_eq_bytes(bytes, bytes2, size);
    free(bytes);

    bytes = hex_to_bytes(hex3, strlen(hex3), &size);
    tst_assert_eq_uint(size, sizeof(bytes3));
    tst_assert_eq_bytes(bytes, bytes3, size);
    free(bytes);

    bytes = hex_to_bytes(hex4, strlen(hex4), &size);
    tst_assert_eq_uint(size, sizeof(bytes4));
    tst_assert_eq_bytes(bytes, bytes4, size);
    free(bytes);
} tst_end_test()

tst_begin_test(BYTES_TO_HEX) {
    const byte_t bytes1[] = {0x00};
    const byte_t bytes2[] = {0x00, 0xfe, 0x13};
    char * hex;

    hex = bytes_to_hex(bytes1, 0);
    tst_assert_eq_str(hex, "");
    free(hex);

    hex = bytes_to_hex(bytes1, sizeof(bytes1));
    tst_assert_eq_str(hex, "00");
    free(hex);

    hex = bytes_to_hex(bytes2, sizeof(bytes2));
    tst_assert_eq_str(hex, "00fe13");
    free(hex);
} tst_end_test()

tst_begin_test(TO_BASE64) {
    tst_assert_eq_char(to_base64(0), 'A');
    tst_assert_eq_char(to_base64(25), 'Z');
    tst_assert_eq_char(to_base64(26), 'a');
    tst_assert_eq_char(to_base64(51), 'z');
    tst_assert_eq_char(to_base64(52), '0');
    tst_assert_eq_char(to_base64(61), '9');
    tst_assert_eq_char(to_base64(62), '+');
    tst_assert_eq_char(to_base64(63), '/');
} tst_end_test()

tst_begin_test(BYTES_TO_BASE64) {
    const byte_t bytes1[] = {0x0};
    const byte_t bytes2[] = {0x32, 0xe0};
    const byte_t bytes3[] = {0xef, 0x96, 0xac};
    const byte_t bytes4[] = {0x11, 0x00, 0x00, 0xff};
    char * base64;

    base64 = bytes_to_base64(bytes1, 0);
    tst_assert_eq_str(base64, "");
    free(base64);

    base64 = bytes_to_base64(bytes1, sizeof(bytes1));
    tst_assert_eq_str(base64, "AA==");
    free(base64);

    base64 = bytes_to_base64(bytes2, sizeof(bytes2));
    tst_assert_eq_str(base64, "MuA=");
    free(base64);

    base64 = bytes_to_base64(bytes3, sizeof(bytes3));
    tst_assert_eq_str(base64, "75as");
    free(base64);

    base64 = bytes_to_base64(bytes4, sizeof(bytes4));
    tst_assert_eq_str(base64, "EQAA/w==");
    free(base64);

} tst_end_test()

tst_begin_test(HEX_TO_BASE64) {
    char * hex;
    tst_assert_eq_str(hex = hex_to_base64(""), "");
    free(hex);
    tst_assert_eq_str(hex = hex_to_base64("a"), "Cg==");
    free(hex);
    tst_assert_eq_str(hex = hex_to_base64("bc"), "vA==");
    free(hex);
    tst_assert_eq_str(hex = hex_to_base64("123"), "ASM=");
    free(hex);
    tst_assert_eq_str(hex = hex_to_base64("90fe"), "kP4=");
    free(hex);
    tst_assert_eq_str(hex = hex_to_base64("ffffff"), "////");
    free(hex);
    tst_assert_eq_str(
        hex = hex_to_base64(
            "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        ),
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    );
    free(hex);
} tst_end_test()

tst_begin_test(XOR_BYTES) {
    const byte_t bytes1[] = {0x12, 0xff};
    const byte_t bytes2[] = {0x54, 0x23};
    byte_t * xor;

    // Just see if this crashes or not
    xor = xor_bytes(bytes1, bytes1, 0);
    free(xor);

    const byte_t result1[] = {0, 0};
    xor = xor_bytes(bytes1, bytes1, 2);
    tst_assert_eq_bytes(xor, result1, 2);
    free(xor);

    const byte_t result2[] = {0x46, 0xdc};
    xor = xor_bytes(bytes1, bytes2, 2);
    tst_assert_eq_bytes(xor, result2, 2);
    free(xor);
} tst_end_test()

tst_begin_test(XOR_HEX) {
    char * hex;
    tst_assert_eq_str(hex = xor_hex("", ""), "");
    free(hex);
    tst_assert_eq_str(hex = xor_hex("abcd", "a3cd"), "0800");
    free(hex);
    // Hex values are padded after byte conversion, so result is padded as well
    tst_assert_eq_str(hex = xor_hex("123", "456"), "0575");
    free(hex);
    tst_assert_eq_str(
        hex = xor_hex("1c0111001f010100061a024b53535009181c", "686974207468652062756c6c277320657965"),
        "746865206b696420646f6e277420706c6179"
    );
    free(hex);
} tst_end_test()

tst_begin_test(SINGLE_BYTE_XOR) {
    const byte_t plain[] = {0x12, 0x43, 0x96, 0x78};
    byte_t cipher[sizeof(plain)];
    const size_t len = sizeof(plain);
    
    const byte_t xor1[] = {0x33, 0x62, 0xb7, 0x59};
    const byte_t xor2[] = {0xed, 0xbc, 0x69, 0x87};

    single_byte_xor(plain, cipher, len, 0x00);
    tst_assert_eq_bytes(cipher, plain, len);
    single_byte_xor(plain, cipher, len, 0x21);
    tst_assert_eq_bytes(cipher, xor1, len);
    single_byte_xor(plain, cipher, len, 0xff);
    tst_assert_eq_bytes(cipher, xor2, len);
} tst_end_test()

tst_begin_test(SCORE_LETTER) {
    tst_assert_eq_int(score_letter('e'), 13);
    tst_assert_eq_int(score_letter('t'), 9);
    tst_assert_eq_int(score_letter('o'), 8);
    tst_assert_eq_int(score_letter('d'), 4);
    tst_assert_eq_int(score_letter(' '), 2);
    tst_assert_eq_int(score_letter(','), 0);
    tst_assert_eq_int(score_letter(0xff), -1);

    // Letter scores should be case insensitive
    for (byte_t letter = 'a'; letter <= 'z'; letter++) {
        byte_t cap = letter + 'A' - 'a';
        tst_assert_eq_int(score_letter(letter), score_letter(cap));
    }
} tst_end_test()

tst_begin_test(SCORE_TEXT) {
    const byte_t text[] = {'e','t','a','o','i','n'};
    const int total = 13 + 9 + 8 + 8 + 7 + 7;
    tst_assert_eq_int(score_text(text, sizeof(text)), total);
} tst_end_test()

tst_begin_test(BREAK_XOR_CIPHER) {
    size_t len;
    const char * cypher = "1b37373331363f78151b7f2b783431333d78397828372d363c78373e783a393b3736";
    const byte_t * solution = (const byte_t *)"Cooking MC's like a pound of bacon";

    byte_t * buf = hex_to_bytes(cypher, strlen(cypher), &len);
    int best_score;
    byte_t key;
    byte_t * plain = break_xor_cipher(buf, len, &best_score, &key);
    tst_assert_eq_uint(key, 0x58);
    tst_assert_eq_bytes(plain, solution, len);
    free(plain);
    free(buf);
} tst_end_test()

int main(void)
{
    tst_run_test(FROM_HEX);
    tst_run_test(TO_HEX);
    tst_run_test(HEX_TO_BYTES);
    tst_run_test(BYTES_TO_HEX);
    tst_run_test(TO_BASE64);
    tst_run_test(BYTES_TO_BASE64);
    tst_run_test(HEX_TO_BASE64);
    tst_run_test(XOR_BYTES);
    tst_run_test(XOR_HEX);
    tst_run_test(SINGLE_BYTE_XOR);
    tst_run_test(SCORE_LETTER);
    tst_run_test(SCORE_TEXT);
    tst_run_test(BREAK_XOR_CIPHER);

    tst_report_results();
}
