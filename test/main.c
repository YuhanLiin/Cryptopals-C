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
    const byte_t bytes1[1] = {0};
    const char * hex2 = "f";
    const byte_t bytes2[1] = {0xf};
    /*const char * hex3 = "40";*/
    /*const char * hex3 = "125ae";*/

    byte_t * bytes = NULL;
    size_t size;

    bytes = hex_to_bytes(hex1, strlen(hex1), &size);
    tst_assert_eq_bytes(bytes, bytes1 , size);
    free(bytes);

    bytes = hex_to_bytes(hex2, strlen(hex2), &size);
    tst_assert_eq_bytes(bytes, bytes2, size);
    free(bytes);
} tst_end_test()

int main(void)
{
    tst_run_test(FROM_HEX);
    tst_run_test(HEX_TO_BYTES);
    tst_report_results();
}
