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

void test_maphint() {
    _test_case.begin("t_maphint");
    return_t ret = errorcode_t::success;

    std::map<int, std::string> source;
    t_maphint<int, std::string> hint(source);

    source[1] = "one";
    source[2] = "two";
    source[3] = "three";
    std::string value;
    hint.find(1, &value);
    _test_case.assert("one" == value, __FUNCTION__, "t_maphint.find(1)");
    ret = hint.find(10, &value);
    _test_case.assert(errorcode_t::not_found == ret, __FUNCTION__, "t_maphint.find(10)");

    t_maphint_const<int, std::string> hint_const(source);
    hint_const.find(2, &value);
    _test_case.assert("two" == value, __FUNCTION__, "t_maphint.find(2)");
}

void test_mapinsert() {
    _test_case.begin("understanding map insert");
    return_t ret = errorcode_t::success;

    struct copyitem_t {
        int i;

        copyitem_t() : i(0) { _logger->writeln("ctor"); }
        copyitem_t(int v) : i(v) { _logger->writeln("ctor1"); }
        copyitem_t(const copyitem_t& rhs) : i(rhs.i) { _logger->writeln("copy"); }
        ~copyitem_t() { _logger->writeln("dtor"); }
        const copyitem_t& operator=(const copyitem_t& rhs) {
            _logger->writeln("copy1");
            return *this;
        }
    };
    struct moveitem_t {
        int i;

        moveitem_t() : i(0) { _logger->writeln("ctor"); }
        moveitem_t(int v) : i(v) { _logger->writeln("ctor1"); }
        moveitem_t(const moveitem_t&) = delete;
        moveitem_t& operator=(const moveitem_t&) = delete;
        moveitem_t(moveitem_t&& rhs) {
            i = rhs.i;
            _logger->writeln("move");
        }
        moveitem_t& operator=(moveitem_t&& rhs) {
            i = rhs.i;
            _logger->writeln("move1");
            return *this;
        }
        moveitem_t& operator=(int v) {
            i = v;
            _logger->writeln("move2");
            return *this;
        }
        ~moveitem_t() { _logger->writeln("dtor"); }
    };

    // ctor1 copy copy dtor dtor dtor
    _logger->colorln("case 1");
    {
        std::map<int, copyitem_t> dict;

        dict.insert({0, copyitem_t(0)});
    }

    // ctor1 move move dtor(moved) dtor(moved) dtor
    _logger->colorln("case 2");
    {
        std::map<int, moveitem_t> dict;

        dict.insert({0, moveitem_t(0)});
    }

    // ctor1 copy copy dtor dtor dtor
    _logger->colorln("case 3");
    {
        std::map<int, copyitem_t> dict;
        auto pib = dict.insert({0, copyitem_t(0)});
        if (true == pib.second) {
            auto& entry = pib.first->second;
            //
        }
    }

    // ctor1 move move dtor(moved) dtor(moved) dtor
    _logger->colorln("case 4");
    {
        std::map<int, moveitem_t> dict;

        auto pib = dict.insert({0, moveitem_t(0)});
        if (true == pib.second) {
            auto& entry = pib.first->second;
            //
        }
    }

    // ctor dtor
    _logger->colorln("case 5");
    {
        std::map<int, copyitem_t> dict;

        auto iter = dict.find(0);
        if (dict.end() == iter) {
            auto& item = dict[0];
            item.i = 0;
        }
    }

    /**
     * valgrind
     *
     * | map         | DRD, helgrind | cf.                   | error                                        |
     * | insert      | ERROR         | copy, dtor, dtor*     | pthread_mutex_destroy with invalid parameter |
     * | operator [] | PASS          | in-place default ctor | N/A                                          |
     */

    struct testitem_t {
        critical_section lock;
        int i;

        testitem_t() : i(0) { _logger->writeln("ctor"); }
        testitem_t(int v) : i(v) { _logger->writeln("ctor1"); }
        testitem_t(const testitem_t& rhs) : i(rhs.i) { _logger->writeln("copy"); }
        ~testitem_t() { _logger->writeln("dtor"); }
        const testitem_t& operator=(const testitem_t& rhs) {
            _logger->writeln("copy1");
            return *this;
        }
    };

    // ctor dtor
    _logger->colorln("case 6");
    {
        std::map<int, testitem_t> dict;

        auto iter = dict.find(0);
        if (dict.end() == iter) {
            auto& item = dict[0];  // in-place default ctor, pthread_mutex_init
            item.i = 0;
        }
    }  // dtor, pthread_mutex_destroy
}
