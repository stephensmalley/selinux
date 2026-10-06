#ifndef TEST_RECORDS_H
#define TEST_RECORDS_H

#include <CUnit/Basic.h>

int records_test_init(void);
int records_test_cleanup(void);
int records_add_tests(CU_pSuite suite);

#endif
