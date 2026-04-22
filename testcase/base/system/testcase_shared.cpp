/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/testcase/base/sample.hpp>

int simple_instance1_dtor = 0;
int simple_instance2_dtor = 0;

class simple_instance1 {
   public:
    simple_instance1() {
        _instance.make_share(this);
        _logger->writeln("constructor");
    }
    ~simple_instance1() {
        _logger->writeln("destructor");

        ++simple_instance1_dtor;
    }

    void dosomething() { _logger->writeln("hello world"); }
    int addref() { return _instance.addref(); }
    int release() { return _instance.delref(); }
    int getref() { return _instance.getref(); }

   private:
    t_shared_reference<simple_instance1> _instance;
};

class simple_instance2 {
   public:
    simple_instance2() { _logger->writeln("constructor"); }
    ~simple_instance2() {
        _logger->writeln("destructor");

        ++simple_instance2_dtor;
    }
    void dosomething() { _logger->writeln("hello world"); }
};

void test_sharedinstance1() {
    _test_case.begin("shared instance");
    int ret = 0;

    simple_instance1 *inst = new simple_instance1;  // ++refcounter
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
        t_shared_instance<simple_instance2> inst;
        inst.make_share(new simple_instance2);
        _test_case.assert(1 == inst.getref(), __FUNCTION__, "getref==1");
        inst->dosomething();

        t_shared_instance<simple_instance2> inst2(std::move(inst));
        _test_case.assert(1 == inst2.getref(), __FUNCTION__, "getref==1");
        inst2->dosomething();
    }  // curly brace for instance lifetime
    _test_case.assert(1 == simple_instance2_dtor, __FUNCTION__, "shared instance");
}

void testcase_shared() {
    test_sharedinstance1();
    test_sharedinstance2();
}
