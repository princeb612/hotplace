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

#include <iostream>
#include <sdk/sdk.hpp>

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

int main() {
    test_sharedinstance1();
    test_sharedinstance2();
    test_endian();

    _test_case.report(5);
    return _test_case.result();
}
