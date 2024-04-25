/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <stdio.h>

#include <functional>
#include <iostream>
#include <sdk/base/basic/tree.hpp>
#include <sdk/sdk.hpp>
#include <string>

using namespace hotplace;
using namespace hotplace::io;

test_case _test_case;

int simple_instance1_dtor = 0;
int simple_instance2_dtor = 0;

class simple_instance1 {
   public:
    simple_instance1() {
        _instance.make_share(this);
        std::cout << "constructor" << std::endl;
    }
    ~simple_instance1() {
        std::cout << "destructor" << std::endl;

        simple_instance1_dtor = 1;
    }

    void dosomething() { std::cout << "hello world " << std::endl; }
    int addref() { return _instance.addref(); }
    int release() { return _instance.delref(); }
    int getref() { return _instance.getref(); }

   private:
    t_shared_reference<simple_instance1> _instance;
};

class simple_instance2 {
   public:
    simple_instance2() { std::cout << "constructor" << std::endl; }
    ~simple_instance2() {
        std::cout << "destructor" << std::endl;

        simple_instance2_dtor = 1;
    }
    void dosomething() { std::cout << "hello world" << std::endl; }
};

void test_sharedinstance1() {
    int ret = 0;

    _test_case.begin("shared reference");

    simple_instance1* inst = new simple_instance1;  // ++refcounter
    _test_case.assert(1 == inst->getref(), __FUNCTION__, "ref count == 1");
    ret = inst->addref();  // ++refcounter
    _test_case.assert(2 == ret, __FUNCTION__, "addref");
    inst->dosomething();
    ret = inst->release();  // --refcounter
    _test_case.assert(1 == ret, __FUNCTION__, "release");
    inst->dosomething();
    ret = inst->release();  // --refcounter, delete here
    _test_case.assert(0 == ret, __FUNCTION__, "release");
    _test_case.assert(1 == simple_instance1_dtor, __FUNCTION__, "dtor called");
}

void test_sharedinstance2() {
    _test_case.begin("shared instance");

    {
        simple_instance2* object = new simple_instance2;
        t_shared_instance<simple_instance2> inst(object);  // ++refcounter
        _test_case.assert(1 == inst.getref(), __FUNCTION__, "getref");
        inst->dosomething();
        t_shared_instance<simple_instance2> inst2(inst);  // ++refcounter
        _test_case.assert(2 == inst.getref(), __FUNCTION__, "getref");
        inst2->dosomething();
        // delete here (2 times ~t_shared_instance)
    }  // curly brace for instance lifetime
    _test_case.assert(1 == simple_instance2_dtor, __FUNCTION__, "shared instance");
}

void dump_data(const char* text, void* ptr, size_t size) {
    basic_stream bs;
    dump_memory((byte_t*)ptr, size, &bs, 16, 2);
    std::cout << (text ? text : "") << std::endl << bs.c_str() << std::endl;
}

void test_convert_endian() {
    _test_case.begin("endian");

    uint64 i64 = t_htoi<uint64>("0001020304050607");
    uint128 i128 = t_htoi<uint128>("000102030405060708090a0b0c0d0e0f");

    if (is_little_endian()) {
        uint32 i32 = 7;
        _test_case.assert(ntoh32(i32) == convert_endian(i32), __FUNCTION__, "32bits");
        _test_case.assert(ntoh64(i64) == convert_endian(i64), __FUNCTION__, "64bits");
        _test_case.assert(ntoh128(i128) == convert_endian(i128), __FUNCTION__, "128bits");
    } else {
        // ntoh ... no effect
    }

#define do_convert_endian_test(type, val)        \
    {                                            \
        type var = val;                          \
        type temp = convert_endian(var);         \
        dump_data("before", &var, sizeof(var));  \
        dump_data("after", &temp, sizeof(temp)); \
    }

    do_convert_endian_test(uint32, 7);
    do_convert_endian_test(uint32, -2);
    do_convert_endian_test(uint64, 7);
    do_convert_endian_test(uint64, -2);
    do_convert_endian_test(uint128, 7);
    do_convert_endian_test(uint128, -2);
    do_convert_endian_test(uint64, i64);
    do_convert_endian_test(uint128, i128);
}

void test_endian() {
    _test_case.begin("endian");

    bool ret = false;
    std::string text;
    bool is_be = is_big_endian();
    bool is_le = is_little_endian();

#if defined __LITTLE_ENDIAN
    text = "__LITTLE_ENDIAN__";
    ret = (true == is_le);
#elif defined __BIG_ENDIAN
    text = "__BIG_ENDIAN__";
    ret = (true == is_be);
#endif
    _test_case.assert((true == ret), __FUNCTION__, text.c_str());
}

void test_maphint() {
    _test_case.begin("maphint");
    return_t ret = errorcode_t::success;

    std::map<int, std::string> source;
    maphint<int, std::string> hint(source);
    source[1] = "one";
    source[2] = "two";
    source[3] = "three";
    std::string value;
    hint.find(1, &value);
    _test_case.assert("one" == value, __FUNCTION__, "maphint.find(1)");
    ret = hint.find(10, &value);
    _test_case.assert(errorcode_t::not_found == ret, __FUNCTION__, "maphint.find(10)");

    maphint_const<int, std::string> hint_const(source);
    hint_const.find(2, &value);
    _test_case.assert("two" == value, __FUNCTION__, "maphint.find(2)");
}

template <typename T>
struct t_comparor_base {
    friend bool operator<(const T& lhs, const T& rhs) { return lhs < rhs; }
};

template <typename T>
struct t_type_comparor : t_comparor_base<T> {
    bool operator()(const T& lhs, const T& rhs) { return lhs.code < rhs.code; }
};

template <typename T>
struct t_huffmancoding_comparor : t_comparor_base<T> {
    bool operator()(const T& lhs, const T& rhs) const {
        bool ret = false;

        if (lhs.weight < rhs.weight) {
            ret = true;
        } else if (lhs.weight == rhs.weight) {
            if (lhs.flags < rhs.flags) {
                ret = true;
            } else {
                ret = lhs.code < rhs.code;
            }
        }

        return ret;
    }
};

void test_btree() {
    _test_case.begin("binary tree");
    // case.1
    {
        t_btree<int> bt;

        int i = 0;
        for (i = 0; i < 20; i++) {
            bt.insert(i);
        }
        for (i = 0; i < 20; i++) {
            bt.insert(i);
        }

        printf("members in [ ");
        bt.for_each([](int const& i) -> void { printf("%d ", i); });
        printf("]\n");

        _test_case.assert(20 == bt.size(), __FUNCTION__, "t_btree.insert");

        for (i = 0; i < 20; i++) {
            bt.remove(i);
        }
        _test_case.assert(0 == bt.size(), __FUNCTION__, "t_btree.remove");
        _test_case.assert(true == bt.empty(), __FUNCTION__, "t_btree.empty");
    }
    // case.2
    {
        t_btree<std::string> bt;
        bt.insert("hello");
        bt.insert("world");
        bt.insert("t_btree");

        printf("members in [ ");
        bt.for_each([](std::string const& s) -> void { printf("%s ", s.c_str()); });
        printf("]\n");

        _test_case.assert(3 == bt.size(), __FUNCTION__, "t_btree<std::string>");
    }
    // case.3~
    {
        struct basedata {
            uint32 key;
            std::string value;

            basedata(uint32 k, std::string const& v) : key(k), value(v) {}
            basedata(const basedata& rhs) : key(rhs.key), value(rhs.value) {}
        };
        // 1 2 3 ...
        struct testdata1 : basedata {
            testdata1(uint32 k, std::string const& v) : basedata(k, v) {}
            testdata1(const testdata1& rhs) : basedata(rhs) {}

            bool operator<(const testdata1& rhs) const {
                bool test = false;
                if (key < rhs.key) {
                    return true;
                } else if (key == rhs.key) {
                    return value < rhs.value;
                } else {
                    return false;
                }
            }
        };
        // a b c ...
        struct testdata2 : basedata {
            testdata2(uint32 k, std::string const& v) : basedata(k, v) {}
            testdata2(const testdata2& rhs) : basedata(rhs) {}

            bool operator<(const testdata2& rhs) const {
                bool test = false;
                if (value < rhs.value) {
                    return true;
                } else if (value == rhs.value) {
                    return key < rhs.key;
                } else {
                    return false;
                }
            }
        };

        // case.3
        {
            t_btree<struct testdata1> bt;
            bt.insert(testdata1(1, "one"));
            bt.insert(testdata1(2, "two"));
            bt.insert(testdata1(3, "three"));
            bt.insert(testdata1(4, "four"));
            bt.insert(testdata1(5, "five"));

            printf("members in [ ");
            bt.for_each([](struct testdata1 const& t) -> void { printf("%u %s ", t.key, t.value.c_str()); });
            printf("]\n");

            _test_case.assert(5 == bt.size(), __FUNCTION__, "t_btree<struct> #1");
        }
        // case.4
        {
            t_btree<struct testdata2> bt;
            bt.insert(testdata2(1, "one"));
            bt.insert(testdata2(2, "two"));
            bt.insert(testdata2(3, "three"));
            bt.insert(testdata2(4, "four"));
            bt.insert(testdata2(5, "five"));

            printf("members in [ ");
            bt.for_each([](struct testdata2 const& t) -> void { printf("%u %s ", t.key, t.value.c_str()); });
            printf("]\n");

            _test_case.assert(5 == bt.size(), __FUNCTION__, "t_btree<struct> #2");
        }
    }
    // case.5~
    {
        constexpr char sample[] = "still a man hears what he wants to hear and disregards the rest";

        struct testdata {
            byte_t code;
            size_t weight;

            testdata() : code(0), weight(0) {}
            testdata(byte_t b) : code(b), weight(0) {}
            testdata(const testdata& rhs) : code(rhs.code), weight(rhs.weight) {}

            // bool operator<(const testdata& rhs) const { return code < rhs.code; }
        };

        // case.5
        {
            t_btree<testdata, t_type_comparor<testdata>> bt;
            for (auto b : sample) {
                if (b) {
                    bt.insert(testdata((byte_t)b), [](testdata& code) -> void { code.weight++; });
                }
            }
            _test_case.assert(15 == bt.size(), __FUNCTION__, "t_btree<structure, custom_compararor> insert and update");

            printf("members in [\n");
            bt.for_each([](testdata const& t) -> void { printf("%c %02x %u\n", isprint(t.code) ? t.code : '?', t.code, t.weight); });
            printf("]\n");
        }
    }
}

void test_avl_tree() {
    _test_case.begin("AVL tree");
    {
        t_avltree<int> bt;

        int i = 0;
        for (i = 0; i < 20; i++) {
            bt.insert(i);
        }
        for (i = 0; i < 20; i++) {
            bt.insert(i);
        }

        printf("members in [ ");
        bt.for_each([](int const& i) -> void { printf("%d ", i); });
        printf("]\n");

        _test_case.assert(20 == bt.size(), __FUNCTION__, "t_avltree.insert");

        for (i = 0; i < 20; i++) {
            bt.remove(i);
        }
        _test_case.assert(0 == bt.size(), __FUNCTION__, "t_avltree.remove");
        _test_case.assert(true == bt.empty(), __FUNCTION__, "t_avltree.empty");
    }
}

// check result https://asecuritysite.com/calculators/huff

namespace hotplace {

template <typename key_t, typename comparator_t = t_huffmancoding_comparor<key_t>>
class huffman_coding {
   public:
    typedef typename std::function<void(key_t& t, const key_t& lhs, const key_t& rhs)> const_node_visitor;
    typedef typename std::function<void(key_t const& t)> const_visitor;
    typedef typename std::function<void(key_t const& t, bool& use, uint8& symbol, std::string const&)> const_hcode_visitor;
    typedef t_btree<key_t> measure_tree_t;
    typedef t_btree<key_t, comparator_t> btree_t;
    typedef std::map<key_t, typename btree_t::node_t*, comparator_t> map_t;
    typedef std::pair<typename map_t::iterator, bool> map_pib_t;
    typedef typename btree_t::node_t node_t;
    typedef std::map<uint8, std::string> table_t;
    struct hcode {
        size_t depth;
        std::string code;

        hcode() : depth(0) {}
    };

    huffman_coding() {}

    void reset() { _measure.clear(); }

    void operator<<(const char* s) {
        // count
        for (const char* p = s; *p; p++) {
            _measure.insert(key_t((uint8)*p), [](key_t& code) -> void { code.weight++; });
        }
    }

    void merge(const_node_visitor visit) {
        _btree.clear();
        _m.clear();
        _table.clear();

        _measure.for_each([&](key_t const& t) -> void { _btree.insert(key_t(t.code, t.weight)); });

        while (_btree.size() > 1) {
            key_t k;
            key_t k_left;
            key_t k_right;

            typename btree_t::node_t* l = _btree.clone_nocascade(_btree.first());
            k_left = l->_key;
            _btree.remove(l->_key);

            typename btree_t::node_t* r = _btree.clone_nocascade(_btree.first());
            k_right = r->_key;
            _btree.remove(r->_key);

            visit(k, k_left, k_right);
            typename btree_t::node_t* newone = _btree.insert(k, _btree._root);  // merged leaf

            map_pib_t pib = _m.insert(std::make_pair(k, _btree.clone_nocascade(newone)));  // search
            pib.first->second->_left = l;
            pib.first->second->_right = r;
        }
    }

    void build(node_t** root) {
        if (_m.size()) {
            typename btree_t::node_t* p = _m.rbegin()->second;
            _m.erase(p->_key);

            while (_m.size()) {
                build(p);
            }

            *root = p;
        }
    }
    void table(node_t* root, const_hcode_visitor visit) {
        if (root && visit) {
            hcode hc;
            walk(hc, root, visit);
        }
    }
    void clear(node_t*& root) { _btree.clear(root); }

    void encode(byte_t* source, size_t size) {
        byte_t* p = nullptr;
        size_t i = 0;
        maphint<uint8, std::string> hint(_table);
        for (p = source, i = 0; i < size; i++) {
            std::string code;
            hint.find(p[i], &code);
            printf("%s ", code.c_str());
        }
    }

   protected:
    void build(typename btree_t::node_t*& p) {
        if (p) {
            if (p->_left) {
                build(p->_left);
            }
            if (p->_right) {
                build(p->_right);
            }
            typename map_t::iterator iter = _m.find(p->_key);
            if (_m.end() != iter) {
                typename btree_t::node_t* t = iter->second;

                _btree.clear(p);
                p = t;
                _m.erase(iter);
            }
        }
    }
    void walk(hcode& hc, typename btree_t::node_t* t, const_hcode_visitor visit) {
        if (t) {
            hc.depth++;

            hc.code += "0";
            walk(hc, t->_left, visit);
            hc.code.pop_back();

            bool use = false;
            uint8 symbol = 0;
            visit(t->_key, use, symbol, hc.code);
            if (use) {
                _table.insert(std::make_pair(symbol, hc.code));
            }

            hc.code += "1";
            walk(hc, t->_right, visit);
            hc.code.pop_back();

            hc.depth--;
        }
    }

   private:
    measure_tree_t _measure;
    btree_t _btree;
    map_t _m;
    table_t _table;
};
};  // namespace hotplace

void test_huffman_codes() {
    constexpr char sample[] = "still a man hears what he wants to hear and disregards the rest";

    struct testdata {
        uint8 code;
        size_t weight;
        uint32 flags;

        testdata() : code(0), weight(0), flags(0) {}
        testdata(uint8 b) : code(b), weight(0), flags(0) {}
        testdata(uint8 b, size_t f) : code(b), weight(f), flags(0) {}
        testdata(const testdata& rhs) : code(rhs.code), weight(rhs.weight), flags(rhs.flags) {}
        bool operator<(const testdata& rhs) const { return code < rhs.code; }
    };

    huffman_coding<testdata> huff;

    huff << sample;

    huff.merge([](testdata& t, const testdata& lhs, const testdata& rhs) -> void {
        t.code = lhs.code;
        t.weight = lhs.weight + rhs.weight;
        t.flags = 1;  // merged
    });

    huffman_coding<testdata>::node_t* root = nullptr;
    huff.build(&root);
    huff.table(root, [](testdata const& t, bool& use, uint8& symbol, std::string const& code) -> void {
        if (0 == t.flags) {
            // printf("%c (%02x) weight %zi code %s\n", isprint(t.code) ? t.code : '?', t.code, t.weight, code.c_str());
            use = true;
            symbol = t.code;
        }
    });
    huff.clear(root);

    // 010 011 10100 10101 10101 111 100 111 001111 100 0010 111 1011 000 100 1100 010 111 11010 1011 100 011 111 1011 000 111 11010 100 0010 011 010 111 011
    // 00110 111 1011 000 100 1100 111 100 0010 11011 111 11011 10100 010 1100 000 001110 100 1100 11011 010 111 011 1011 000 111 1100 000 010 011
    huff.encode((byte_t*)sample, strlen(sample));
    printf("\n");
}

int main() {
#ifdef __MINGW32__
    setvbuf(stdout, 0, _IOLBF, 1 << 20);
#endif

    test_sharedinstance1();
    test_sharedinstance2();
    test_endian();
    test_convert_endian();
    test_maphint();
    test_btree();
    test_avl_tree();
    test_huffman_codes();

    _test_case.report(5);
    return _test_case.result();
}
