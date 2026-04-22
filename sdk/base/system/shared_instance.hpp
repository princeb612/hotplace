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

#include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/base/system/atomic.hpp>
#include <hotplace/sdk/base/system/types.hpp>

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
    t_shared_reference() : _counter(0), _object(nullptr) {}
    t_shared_reference(const t_shared_reference& other) = delete;
    t_shared_reference(t_shared_reference&& other) : _counter(0), _object(nullptr) { *this = std::move(other); }
    ~t_shared_reference() {}

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
        int ret = 0;
        if (_object) {
            if (0 == _counter) {
                throw exception(errorcode_t::bad_request);
            }
            atomic_decrement(&_counter);
            ret = _counter;
            if (0 == _counter) {
                delete _object;
                // do not access instance member any more
                // be ware of destructor calling delref
            }
        }
        return ret;
    }
    int getref() { return _counter; }

    t_shared_reference& operator=(const t_shared_reference& other) = delete;
    t_shared_reference& operator=(t_shared_reference&& other) {
        std::swap(_counter, other._counter);
        std::swap(_object, other._object);
        return *this;
    }

   private:
#if defined __GNUC__
    int _counter;
#elif defined _MSC_VER
    LONG _counter;
#endif
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
 *          t_shared_instance <simple_instance> inst;
 *          inst.make_share(new simple_instance)
 *          inst->dosomething ();
 *          t_shared_instance <simple_instance> inst2;
 *          inst2 = std::move(inst);
 *      }
 */

template <typename OBJECT_T>
class t_shared_instance {
#ifdef _MSC_VER
    typedef LONG counter_type;
#else
    typedef int counter_type;
#endif
   public:
    t_shared_instance() : _object(nullptr) {
        try {
            _counter = new counter_type(1);
        } catch (std::bad_alloc) {
            throw std::runtime_error("t_shared_instance.ctor");
        }
    }
    t_shared_instance(OBJECT_T* object) : _object(object) { _counter = new counter_type(1); }
    t_shared_instance(const t_shared_instance& other) = delete;
    t_shared_instance(t_shared_instance&& other) : _counter(nullptr), _object(nullptr) { *this = std::move(other); }
    ~t_shared_instance() { delref(); }

    int addref() {
        int ret = 0;
        if (_counter) {
            atomic_increment(_counter);
            ret = *_counter;
        }
        return ret;
    }
    int delref() {
        int ret = 0;
        if (_counter) {
            atomic_decrement(_counter);
            ret = *_counter;
            if (0 == ret) {
                if (_object) {
                    delete _object;
                }
                delete _counter;
                _counter = nullptr;
                _object = nullptr;
            }
        }
        return ret;
    }
    int getref() {
        int ret = 0;
        if (_counter) {
            ret = *_counter;
        }
        return ret;
    }

    OBJECT_T* operator->() { return _object; }
    OBJECT_T& operator*() { return *_object; }

    /**
     * @sample
     *  t_shared_instance<object> obj;
     *  obj.make_share(new object);
     *
     *  void test(object* o) { dosomething; }
     *
     *  object* inst1 = &(*obj);
     *  test(int1);
     *
     *  test(obj);
     */
    operator OBJECT_T*() { return _object; }

    t_shared_instance& make_share(OBJECT_T* object) {
        if (nullptr == _object) {
            _object = object;
        } else {
            throw exception(errorcode_t::already_assigned);
        }
        return *this;
    }

    t_shared_instance& operator=(const t_shared_instance& other) = delete;
    t_shared_instance& operator=(t_shared_instance&& other) {
        std::swap(_counter, other._counter);
        std::swap(_object, other._object);
        return *this;
    }

   private:
    counter_type* _counter;
    OBJECT_T* _object;
};

}  // namespace hotplace

#endif
