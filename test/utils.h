#pragma once

#include <stdio.h>
#include <string.h>
#include <stdint.h>
#include <stdbool.h>
#include <inttypes.h>

struct _tst_assertion_stats_t {
    unsigned passed;
    unsigned failed;
};

struct _tst_test_stats_t {
    unsigned passed;
    unsigned failed;
    unsigned skipped;
};

// Global test stat trackers used for final reporting
static struct _tst_assertion_stats_t _tst_assertion_stats = {0};
static struct _tst_test_stats_t _tst_test_stats = {0};
// The pointer is guaranteed to point to global data, since the struct variable may be shadowed
static struct _tst_assertion_stats_t * _g_tst_assertion_stats_ptr = &_tst_assertion_stats;

// Default setup/teardown function, which does nothing and always succeeds
int _tst_do_nothing( void ) { return 0; }

// Function ptrs for setup and teardown
// Takes no args, returns 0 for sucess, fail otherwise
typedef int ( *_tst_hook_func_t )( void );
static _tst_hook_func_t _tst_g_setup_ptr = &_tst_do_nothing;
static _tst_hook_func_t _tst_g_teardown_ptr = &_tst_do_nothing;

// Macros for setting/unsetting setup and teardown functions
#define tst_set_setup( func ) (_tst_g_setup_ptr = &func)
#define tst_set_teardown( func ) (_tst_g_teardown_ptr = &func)
#define tst_unset_setup() (_tst_g_setup_ptr = &_tst_do_nothing)
#define tst_unset_teardown() (_tst_g_teardown_ptr = &_tst_do_nothing)

// Symbols
#define _tst_checkmark "\u2713"
#define _tst_crossmark "\u2717"
#define _tst_circle "\u25CB"
#define _tst_checkmark_line _tst_checkmark _tst_checkmark _tst_checkmark _tst_checkmark
#define _tst_crossmark_line _tst_crossmark _tst_crossmark _tst_crossmark _tst_crossmark

// Generates name of test functions. Used to generate function definitions and calls
#define _tst_gen_name( name ) _tst_func_##name

// Returns whether the test case or the suite is passing based on asserts.
#define tst_passing() (_tst_assertion_stats.failed == 0)

// Convenient if wrappers for determining test/fail
#define tst_if_pass() if( tst_passing() )
#define tst_if_fail() if( !tst_passing() )

#define _tst_report_asserts()\
    printf(\
        "- Assertions: %u attempted, %u passed, %u failed\n",\
        _tst_assertion_stats.passed + _tst_assertion_stats.failed,\
        _tst_assertion_stats.passed, _tst_assertion_stats.failed\
    );\

// Only report tests if tests have actually been made and run
#define _tst_report_tests() do {\
    unsigned _tst_total_tests =\
        _tst_test_stats.passed + _tst_test_stats.failed + _tst_test_stats.skipped;\
    if( _tst_total_tests > 0 ) printf(\
        "- Test cases: %u attemped, %u passed, %u failed, %u skipped\n",\
        _tst_total_tests,\
        _tst_test_stats.passed, _tst_test_stats.failed, _tst_test_stats.skipped\
    );\
} while( 0 )

// Final reporting called from main to print all test results and return success code
#define tst_report_results() do {\
    printf( "\n" );\
    if( tst_passing() ){\
        printf( _tst_checkmark_line " Module %s PASSED! " _tst_checkmark_line "\n", __FILE__ );\
    } else {\
        printf( _tst_crossmark_line " Module %s FAILED! " _tst_crossmark_line "\n", __FILE__ );\
    }\
    _tst_report_tests();\
    _tst_report_asserts();\
    /* Since we're returning to shell, we return 0 if the tests are passing, 1 otherwise */\
    return !tst_passing();\
} while( 0 )

// Sync the assert stats from within a test case to the global assert stats.
// Should be updated for new assert stats. DON'T USE OUTSIDE TEST CASES
#define _tst_sync() do {\
    _g_tst_assertion_stats_ptr->passed += _tst_assertion_stats.passed;\
    _g_tst_assertion_stats_ptr->failed += _tst_assertion_stats.failed;\
} while( 0 )

// Calls teardown, checks for failures, then updates the test counter before returning.
// Called whenever we need to exit from the test
#define _tst_exit( test_stat_field ) do {\
    _tst_test_stats.test_stat_field += 1;\
    int _tst_teardown_ret = (*_tst_g_teardown_ptr)();\
    if( _tst_teardown_ret != 0 ){\
        printf(\
            _tst_crossmark " Warning: TEARDOWN FAILED with code %d, carrying on.\n",\
            _tst_teardown_ret\
        );\
    }\
    printf("\n");\
    return;\
} while( 0 )

// Initializes a new test function. Must be matched by an END_TEST.
// name =  unique identifier name of the test
#define tst_begin_test( name ) void _tst_gen_name( name )( void )\
{\
    static struct _tst_assertion_stats_t _tst_assertion_stats = {0};\
    const char * _tst_name = #name;\
    int _tst_setup_ret = (*_tst_g_setup_ptr)();\
    if( _tst_setup_ret != 0 ){\
        printf(\
            _tst_crossmark " Test case \"%s\" SETUP FAILED with code %d, ABORTING!\n",\
            _tst_name, _tst_setup_ret\
        );\
        _tst_exit( skipped );\
    }

// Version of tst_begin_test that skips the whole test case.
#define tst_begin_test_skip( name ) tst_begin_test( name )\
    printf( _tst_circle " Test case \"%s\" SKIPPED!\n", _tst_name );\
    _tst_exit( skipped );
    
// Prints result message depending on whether the test case passed or failed
// and reports assert stats for this test
#define tst_end_test()\
    _tst_sync();\
    if( tst_passing() ){\
        printf( _tst_checkmark " Test case \"%s\" PASSED!\n", _tst_name );\
        _tst_report_asserts();\
        _tst_exit( passed );\
    } else {\
        printf( _tst_crossmark " Test case \"%s\" FAILED!\n", _tst_name );\
        _tst_report_asserts();\
        _tst_exit( failed );\
    }\
}

// Aborts a test, which marks it as failed
#define tst_abort_test() do {\
    printf( _tst_crossmark " Test case \"%s\" ABORTED!\n", _tst_name );\
    _tst_report_asserts();\
    _tst_sync();\
    _tst_exit( failed );\
} while( 0 )

// Abort test when failing
 #define tst_abort_if_failing() tst_if_fail() tst_abort_test()

// Runs a test runner function of the specified name
#define tst_run_test( name ) _tst_gen_name( name )()

// Asserts equality. Type and format string of the values are needed
// Requires comparator macro that returns true if the two values result in passing the test
#define _tst_assert_base( expr, expected, fmt_spec, type, cmp, cmp_text ) do {\
    type _expr = (expr);\
    type _expected = (expected);\
    if( !cmp( _expr, _expected ) ){\
        fprintf(\
            stderr,\
            "Assert error in %s:%d: ",\
            __FILE__, __LINE__\
        );\
        fprintf(\
            stderr,\
            "Expected %s="fmt_spec" to "cmp_text" "fmt_spec"\n",\
            #expr, _expr, _expected\
        );\
        _tst_assertion_stats.failed += 1;\
    } else {\
        _tst_assertion_stats.passed += 1;\
    }\
} while( 0 )

#define _tst_print_array( arr, len, fmt_spec ) do {\
    fprintf( stderr, "{ " );\
    for( size_t _i = 0; _i < len; _i++ ) {\
        fprintf( stderr, fmt_spec" ", arr[_i] );\
    }\
    fprintf( stderr, "}" );\
} while( 0 )

#define _tst_assert_array_base( expr, expected, len, fmt_spec, type, cmp_arr, cmp_text ) do {\
    type _expr = (expr);\
    type _expected = (expected);\
    bool _passed;\
    cmp_arr( _expr, _expected, len, _passed );\
    if( !_passed ) {\
        fprintf(\
            stderr,\
            "Assert error in %s:%d: ",\
            __FILE__, __LINE__\
        );\
        fprintf( stderr, "Expected %s=", #expr );\
        _tst_print_array( _expr, len, fmt_spec );\
        fprintf( stderr, " to "cmp_text" " );\
        _tst_print_array( _expected, len, fmt_spec );\
        fprintf( stderr, "\n" );\
        _tst_assertion_stats.failed += 1;\
    } else {\
        _tst_assertion_stats.passed += 1;\
    }\
} while( 0 )

// Int asserts
#define _tst_int_cmp( a, b ) (a == b)

#define tst_assert_int( expr, expected, cmp, cmp_text )\
    _tst_assert_base( expr, expected, "%d", int, cmp, cmp_text )

#define tst_assert_eq_int( expr, expected )\
    tst_assert_int( expr, expected, _tst_int_cmp, "equal" ) 

#define tst_assert_ne_int( expr, expected )\
    tst_assert_int( expr, expected, !_tst_int_cmp, "not equal" ) 

// UInt asserts
#define tst_assert_uint( expr, expected, cmp, cmp_text )\
    _tst_assert_base( expr, expected, "%u", unsigned, cmp, cmp_text )

#define tst_assert_eq_uint( expr, expected )\
    tst_assert_uint( expr, expected, _tst_int_cmp, "equal" ) 

#define tst_assert_ne_uint( expr, expected )\
    tst_assert_uint( expr, expected, !_tst_int_cmp, "not equal" ) 

// Pointer asserts
#define tst_assert_ptr( expr, expected, cmp, cmp_text )\
    _tst_assert_base( expr, expected, "%p", void *, cmp, cmp_text )

#define tst_assert_eq_ptr( expr, expected )\
    tst_assert_ptr( expr, expected, _tst_int_cmp, "equal" ) 

#define tst_assert_ne_ptr( expr, expected )\
    tst_assert_ptr( expr, expected, !_tst_int_cmp, "not equal" ) 

// Char asserts
#define tst_assert_char( expr, expected, cmp, cmp_text )\
    _tst_assert_base( expr, expected, "'%c'", char, cmp, cmp_text )

#define tst_assert_eq_char( expr, expected )\
    tst_assert_char( expr, expected, _tst_int_cmp, "equal" ) 

#define tst_assert_ne_char( expr, expected )\
    tst_assert_char( expr, expected, !_tst_int_cmp, "not equal" ) 

// Size_t asserts
#define tst_assert_size( expr, expected, cmp, cmp_text )\
    _tst_assert_base( expr, expected, "%zu", size_t, cmp, cmp_text )

#define tst_assert_eq_size( expr, expected )\
    tst_assert_size( expr, expected, _tst_int_cmp, "equal" ) 

#define tst_assert_ne_size( expr, expected )\
    tst_assert_size( expr, expected, !_tst_int_cmp, "not equal" ) 

// String-type asserts
#define _tst_str_cmp( a, b ) (strcmp( a, b ) == 0)

#define tst_assert_str( expr, expected, cmp, cmp_text )\
    _tst_assert_base( expr, expected, "\"%s\"", const char *, cmp, cmp_text )

#define tst_assert_eq_str( expr, expected )\
    tst_assert_str( expr, expected, _tst_str_cmp, "equal" )

#define tst_assert_ne_str( expr, expected )\
    tst_assert_str( expr, expected, !_tst_str_cmp, "not equal" )

// General array comparison macro for testing equality
#define _tst_cmp_arr_base( cmp, a1, a2, len, eq_var ) do {\
    eq_var = true;\
    for( size_t _i = 0; _i < len; _i++ ){\
        if( !cmp( a1[_i], a2[_i] ) ){\
            eq_var = false;\
            break;\
        }\
    }\
} while( 0 )

// Byte array asserts
#define _tst_cmp_arr_bytes( a1, a2, len, eq_var )\
    _tst_cmp_arr_base( _tst_int_cmp, a1, a2, len, eq_var );

#define _tst_cmp_arr_ne_bytes( a1, a2, len, eq_var ) do {\
    _tst_cmp_arr_base( _tst_int_cmp, a1, a2, len, eq_var );\
    eq_var = !eq_var;\
} while( 0 )

#define _tst_assert_bytes( expr, expected, len, cmp, cmp_text )\
    _tst_assert_array_base( expr, expected, len, "0x%02x", const uint8_t *, cmp, cmp_text )

#define tst_assert_eq_bytes( expr, expected, len )\
    _tst_assert_bytes( expr, expected, len, _tst_cmp_arr_bytes, "equal" );

#define tst_assert_ne_bytes( expr, expected, len )\
    _tst_assert_bytes( expr, expected, len, _tst_cmp_arr_ne_bytes "not equal" );
