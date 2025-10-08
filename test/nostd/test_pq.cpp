/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

void test_pq() {
    _test_case.begin("binaryheap");

    t_binary_heap<uint32> heap;
    openssl_prng prng;

    std::vector<uint32> table;
    table.resize(10);

    for (size_t i = 0; i < 10; i++) {
        table[i] = prng.rand32();  // expensive
    }

    _test_case.assert(heap.size() == 0, __FUNCTION__, "random generated");

    for (size_t i = 0; i < 10; i++) {
        heap.push(table[i]);  // fast
        _logger->writeln("push %u", table[i]);
    }

    _test_case.assert(heap.size() > 0, __FUNCTION__, "case 1");

    bool errorcheck = false;
    uint32 lastone = 0;
    while (heap.size()) {
        uint32 elem = heap.top();
        _logger->writeln("top %u", elem);
        if (lastone > elem) {
            errorcheck |= true;
        }
        lastone = elem;
        heap.pop();
    }

    _test_case.assert(0 == heap.size(), __FUNCTION__, "case 2");
    _test_case.assert(false == errorcheck, __FUNCTION__, "case 3");
}
