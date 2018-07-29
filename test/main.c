#include <stdlib.h>
#include <string.h>

#include "convert.h"
#include "utils.h"

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
    tst_assert_eq_str(hex_to_base64(""), "");
    tst_assert_eq_str(hex_to_base64("a"), "Cg==");
    tst_assert_eq_str(hex_to_base64("bc"), "vA==");
    tst_assert_eq_str(hex_to_base64("123"), "ASM=");
    tst_assert_eq_str(hex_to_base64("90fe"), "kP4=");
    tst_assert_eq_str(hex_to_base64("ffffff"), "////");
    tst_assert_eq_str(
        hex_to_base64(
            "49276d206b696c6c696e6720796f757220627261696e206c696b65206120706f69736f6e6f7573206d757368726f6f6d"
        ),
        "SSdtIGtpbGxpbmcgeW91ciBicmFpbiBsaWtlIGEgcG9pc29ub3VzIG11c2hyb29t"
    );
} tst_end_test()

int main(void)
{
    tst_run_test(FROM_HEX);
    tst_run_test(HEX_TO_BYTES);
    tst_run_test(TO_BASE64);
    tst_run_test(BYTES_TO_BASE64);
    tst_run_test(HEX_TO_BASE64);

    tst_report_results();
}
