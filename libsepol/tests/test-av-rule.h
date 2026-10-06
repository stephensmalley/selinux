#ifndef TEST_AV_RULE_H
#define TEST_AV_RULE_H

#include <CUnit/Basic.h>

int av_rule_test_init(void);
int av_rule_test_cleanup(void);
int av_rule_add_tests(CU_pSuite suite);

#endif
