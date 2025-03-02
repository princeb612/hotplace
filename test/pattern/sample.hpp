#ifndef __HOTPLACE_TEST_PATTERN__
#define __HOTPLACE_TEST_PATTERN__

#include <algorithm>
#include <functional>
#include <sdk/sdk.hpp>

using namespace hotplace;
using namespace hotplace::crypto;
using namespace hotplace::io;
using namespace hotplace::net;

typedef struct _OPTION {
    int verbose;
    int debug;
    int log;
    int time;

    _OPTION() : verbose(0), debug(0), log(0), time(0) {
        // do nothing
    }
} OPTION;

extern test_case _test_case;
extern t_shared_instance<logger> _logger;
extern t_shared_instance<t_cmdline_t<OPTION> > _cmdline;

struct pattern_t {
    const char* pattern;
    unsigned len;
};

void test_kmp();
void test_aho_corasick_simple();
void test_aho_corasick();
void test_trie();
void test_trie_autocompletion();
void test_trie_lookup();
void test_trie_scan();
void test_suffixtree();
void test_suffixtree2();
void test_ukkonen();
void test_ukkonen2();
void test_lcp();
void test_wildcards();
void test_wildcards2();
void test_merge_ovl_intervals();
void test_aho_corasick_wildcard();
void test_aho_corasick_ignorecase();

#endif
