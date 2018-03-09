#ifndef _STOR_TEST_H_
#define _STOR_TEST_H_
#include <setjmp.h>

#ifdef NDEBUG
#undef NDEBUG
#endif
#include "debug.h"

#ifndef STOR_TEST
#define STOR_TEST 1
#endif

extern int assertions_passed;
extern int assertions_failed;
extern int tests_passed;
extern int tests_skipped;
extern int tests_failed;

static jmp_buf jmploc;
bool jmpset = false;

static inline void START_TESTS(void) {
    assertions_passed = 0;
    assertions_failed = 0;
    tests_passed = 0;
    tests_skipped = 0;
    tests_failed = 0;
}

static inline void END_TESTS(void) {
    fprintf(stdout, "Assertions passed: %d\n", assertions_passed);
    fprintf(stdout, "Assertions failed: %d\n", assertions_failed);
    fprintf(stdout, "Tests passed: %d\n", tests_passed);
    fprintf(stdout, "Tests failed: %d\n", tests_failed);
    if (tests_failed > 0) {
        exit(1);
    } else {
        exit(0);
    }
}

static inline void FAIL_ASSERT(const char *file, int line, const char *func) {
    LOG_ERR("Assertion failed at %s:%d in %s\n", file, line, func);
    assertions_failed++;
    if (jmpset) {
        longjmp(jmploc, 1);
    }
}

static inline void PASS_ASSERT(void) {
    assertions_passed++;
}

#define RUN_TEST(testfn) _RUN_TEST(testfn, #testfn)
static inline void _RUN_TEST(int (*test_fn)(void), const char *fnname) {
    DEBUG(DBG_TEST, "-- Running %s --\n", fnname);
    int old_failed = assertions_failed;
    int jmpres = setjmp(jmploc);
    jmpset = true;
    int testres;
    if (jmpres == 0) { // jump was set
        testres = test_fn();
        if (testres == 0 && old_failed == assertions_failed) {
            tests_passed++;
        } else {
            tests_failed++;
        }
    } else if (jmpres > 0) { // assertion failure caused jump
        tests_failed++;
    }
    jmpset = false;
}

#define SKIP_TEST(testfn) _SKIP_TEST(#testfn)
static inline void _SKIP_TEST(const char *fnname) {
    DEBUG(DBG_TEST, "-- Skipping %s --\n", fnname);
    tests_skipped++;
}

#define T_ASSERT(expr) ((expr) ? PASS_ASSERT() : FAIL_ASSERT(__FILE__, __LINE__, __func__))
#define T_ASSERT_EQ(expr1,expr2) ((expr1==expr2) ? PASS_ASSERT() : FAIL_ASSERT(__FILE__, __LINE__, __func__))

#endif
