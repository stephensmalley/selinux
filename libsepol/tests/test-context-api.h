#ifndef TEST_CONTEXT_API_H
#define TEST_CONTEXT_API_H

#include <CUnit/Basic.h>

int context_api_test_init(void);
int context_api_test_cleanup(void);
int context_api_add_tests(CU_pSuite suite);

#endif
