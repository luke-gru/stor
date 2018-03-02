#include "stor.h"
#include "test.h"

int argc;
char **argv;

int assertions_passed;
int assertions_failed;
int tests_passed;
int tests_failed;

int my_test(void) {
    T_ASSERT(true);
    return 0;
}

int main(int _argc, char **_argv) {
    argc = _argc;
    argv = _argv;
    START_TESTS();
    RUN_TEST(my_test);
    END_TESTS();
}
