/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2023.08.13   Soo Han, Kim        reboot (codename.hotplace)
 */

#ifndef __HOTPLACE_SDK_BASE_SYSTEM_SHAREDINSTANCE__
#define __HOTPLACE_SDK_BASE_SYSTEM_SHAREDINSTANCE__

#include <sdk/base/system/atomic.hpp>

namespace hotplace {

/**
 * @brief wanna support c++9x
 * @example
 *      class simple_instance1
 *      {
 *      public:
 *          simple_instance1 ()
 *          {
 *              _instance.make_share (this);
 *          }
 *          ~simple_instance1 ()
 *          {
 *          }
 *
 *          void dosomething ()
 *          {
 *              // do something
 *          }
 *          int addref ()
 *          {
 *              return _instance.addref ();
 *          }
 *          int release ()
 *          {
 *              return _instance.delref ();
 *          }
 *      private:
 *          t_shared_reference <simple_instance1> _instance;
 *      };
 *
 *      void test_sharedinstance1 ()
 *      {
 *          simple_instance1* inst = new simple_instance1; // ++refcounter
 *          inst->addref ();                               // ++refcounter
 *          inst->dosomething ();
 *          inst->release ();                              // --refcounter
 *          inst->dosomething ();
 *          inst->release ();                              // --refcounter
 *      }
 */
template <typename OBJECT_T>
class t_shared_reference {
   public:
    t_shared_reference() : _counter(0), _object(nullptr) {
        // do nothing
    }
    ~t_shared_reference() {
        // do nothing
    }

    void make_share(OBJECT_T* object) {
        if (nullptr == _object) {
            _object = object;
            addref();
        }
    }

    int addref() {
        if (_object) {
            atomic_increment(&_counter);
        }
        return _counter;
    }
    int delref() {
        atomic_decrement(&_counter);
        int ret = _counter;
        if (0 == _counter) {
            delete _object;
            // do not access instance member any more
            // be ware of destructor calling delref
        }
        return ret;
    }
    int getref() { return _counter; }

   private:
    int _counter;
    OBJECT_T* _object;
};

/**
 * @brief smart pointer like share_ptr (shared_ptr since c++11, however wanna support c++9x)
 * @example
 *      class simple_instance
 *      {
 *      public:
 *          simple_instance () { std::cout << "constructor" << std::endl; }
 *          ~simple_instance () { std::cout << "destructor" << std::endl; }
 *          void dosomething () { std::cout << "hello world" << std::endl; }
 *      };
 *
 *      void test_sharedinstance2 ()
 *      {
 *          simple_instance* object = new simple_instance;
 *          t_shared_instance <simple_instance> inst (object);  // ++refcounter
 *          inst->dosomething ();
 *          t_shared_instance <simple_instance> inst2 (inst);   // ++refcounter
 *          inst2->dosomething ();
 *          // delete here (2 times ~t_shared_instance)
 *      }
 */

template <typename OBJECT_T>
class t_shared_instance {
   public:
    t_shared_instance() : _object(nullptr) { _counter = new int(1); }
    t_shared_instance(OBJECT_T* object) : _object(object) { _counter = new int(1); }
    t_shared_instance(const t_shared_instance& inst) : _counter(inst._counter), _object(inst._object) { atomic_increment(_counter); }
    ~t_shared_instance() { delref(); }

    int addref() {
        atomic_increment(_counter);
        int ret = *_counter;
        return ret;
    }
    int delref() {
        atomic_decrement(_counter);
        int ret = *_counter;
        if (0 == ret) {
            if (_object) {
                delete _object;
            }
            delete _counter;
            _counter = nullptr;
            _object = nullptr;
        }
        return ret;
    }
    int getref() {
        int ret = *_counter;

        return ret;
    }

    OBJECT_T* operator->() { return _object; }
    OBJECT_T& operator*() { return *_object; }

    t_shared_instance& make_share(OBJECT_T* object) {
        if (nullptr == _object) {
            _object = object;
        } else {
            throw errorcode_t::already_assigned;
        }
        return *this;
    }
    t_shared_instance& operator=(const t_shared_instance& rhs) {
        delref();

        _counter = rhs._counter;
        _object = rhs._object;
        atomic_increment(_counter);
        return *this;
    }

   private:
    int* _counter;
    OBJECT_T* _object;
};

}  // namespace hotplace

#endif
