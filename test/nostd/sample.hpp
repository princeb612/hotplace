#ifndef __HOTPLACE_TEST_NOSTD__
#define __HOTPLACE_TEST_NOSTD__

#include <hotplace/sdk/sdk.hpp>
#include <hotplace/test/test.hpp>

struct OPTION : public CMDLINEOPTION {};

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION>> _cmdline;

void test_btree();
void test_avl_tree();
void test_vector();
void test_list();
void test_pq();
void test_find_lessthan_or_equal();

#endif
