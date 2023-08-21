/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/sdk.hpp>
#include <stdio.h>
#include <iostream>

using namespace hotplace;
using namespace hotplace::io;

test_case _test_case;

class simple_instance1
{
public:
    simple_instance1 ()
    {
        _instance.make_share (this);
        std::cout << "constructor" << std::endl;
    }
    ~simple_instance1 ()
    {
        std::cout << "destructor" << std::endl;
    }

    void dosomething ()
    {
        std::cout << "hello world " << std::endl;
    }
    int addref ()
    {
        return _instance.addref ();
    }
    int release ()
    {
        return _instance.delref ();
    }
private:
    t_shared_reference <simple_instance1> _instance;
};

class simple_instance2
{
public:
    simple_instance2 ()
    {
        std::cout << "constructor" << std::endl;
    }
    ~simple_instance2 ()
    {
        std::cout << "destructor" << std::endl;
    }
    void dosomething ()
    {
        std::cout << "hello world" << std::endl;
    }
};

void test_sharedinstance1 ()
{
    _test_case.start ();

    simple_instance1* inst = new simple_instance1;  // ++refcounter
    inst->addref ();                                // ++refcounter
    inst->dosomething ();
    inst->release ();                               // --refcounter
    inst->dosomething ();
    inst->release ();                               // --refcounter, delete here

    _test_case.assert (true, __FUNCTION__, "shared reference");
}

void test_sharedinstance2 ()
{
    _test_case.start ();
    {
        simple_instance2* object = new simple_instance2;
        t_shared_instance <simple_instance2> inst (object);     // ++refcounter
        inst->dosomething ();
        t_shared_instance <simple_instance2> inst2 (inst);      // ++refcounter
        inst2->dosomething ();
        // delete here (2 times ~t_shared_instance)
    } // curly brace for instance lifetime
    _test_case.assert (true, __FUNCTION__, "shared instance");
}

void test_endian ()
{
    bool ret = false;
    std::string text;
    bool is_be = is_big_endian ();
    bool is_le = is_little_endian ();

#if defined __LITTLE_ENDIAN__
    text = "__LITTLE_ENDIAN__";
    ret = (true == is_le);
#elif defined __BIG_ENDIAN__
    text = "__BIG_ENDIAN__";
    ret = (true == is_be);
#endif
    _test_case.assert ((true == ret), __FUNCTION__, text.c_str ());
}

int main ()
{
    _test_case.begin ("smart pointer");

    test_sharedinstance1 ();
    test_sharedinstance2 ();
    test_endian ();

    _test_case.report ();
    return _test_case.result ();
}
