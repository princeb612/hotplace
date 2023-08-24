/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO_BASIC_MLFQ__
#define __HOTPLACE_SDK_IO_BASIC_MLFQ__

#include <hotplace/sdk/base.hpp>
#include <map>
#include <queue>
#include <set>

namespace hotplace {
namespace io {

enum mlfq_binder_operation_t {
    binder_p    = 0,    /* reference count -- */
    binder_v    = 1,    /* reference count ++ */
};

enum mlfq_mode_t {
    mlfq_block = 1, // 0 block, else unblock
};

/*
 * @brief binder method manipulates the p and v operation.
 * @remarks see t_mlfq (default second template parameter)
 */
template<typename TYPENAME_T> struct mlfq_shared_binder {
    int binder (int mode, TYPENAME_T* source, void* param)
    {
        int ret = 0;

        switch (mode) {
            case mlfq_binder_operation_t::binder_p:
                ret = source->release ();
                break;
            case mlfq_binder_operation_t::binder_v:
                ret = source->addref ();
                break;
        }
        return ret;
    }
};

template<typename TYPENAME_T> struct mlfq_nonshared_binder {
    int binder (int mode, TYPENAME_T* source, void* param)
    {
        // do nothing
        return 0;
    }
};

/*
 * @brief MFQ
 * @param   typename TYPENAME_T [IN] Queue
 * @param   typename BINDER_T [INOPT] binder member manipulates the semaphore operation (p and v).
 *                                    default mlfq_shared_binder<TYPENAME_T>
 * @remarks
 *          refactored NetPriorityQueue
 *          designed MultilevelFeedbackQueue
 *          refactored MultilevelFeedbackQueue and scheduler::schedule_queue
 *
 *          2020.02.22 basically a reference counter is influenced by post and cancel method
 */
template<typename TYPENAME_T, typename BINDER_T = mlfq_shared_binder<TYPENAME_T> >
class t_mlfq
{
public:
    t_mlfq ();
    ~t_mlfq ();

    /*
     * @brief post
     * @param   int pri [IN] priority
     * @param   TYPENAME_T* source  [IN] internally increase reference counter, cannot be null
     * @param   void* param [IN] see binder(..., void* param)
     * @return error code (see error.hpp)
     * @remarks
     *          post and signal with priority, parameter
     */
    return_t post (int pri, TYPENAME_T* source, void* param = nullptr);
    return_t push (int pri, TYPENAME_T* source, void* param = nullptr);

    /*
     * @brief   operator <<
     * @param   TYPENAME_T*   source  [IN] internally increase reference counter, cannot be null
     * @remarks
     *          post source into priority 0 without parameter
     */
    t_mlfq& operator << (TYPENAME_T* source);
    /*
     * @brief   get
     * @param   int*          pri     [IN]
     * @param   TYPENAME_T**  source  [OUT]
     * @param   uint32         msecs   [IN]
     * @return  error code (see error.hpp)
     *          errorcode_t::success
     *          errorcode_t::not_ready no data
     *          ERROR_CAMCELED/errorcode_t::not_found canceled
     * @remarks
     *          wait signal with timeout and pop source from queue
     * @sample
     *          ret = mfq.get(&pri, &source, 10);
     *          if (errorcode_t::success == ret)
     *          {
     *              // ...
     *              source->release();
     *          }
     */
    return_t get (int* pri, TYPENAME_T** source, uint32 msecs);
    return_t pop (int* pri, TYPENAME_T** source, uint32 msecs);

    return_t cancel (TYPENAME_T* source, void* param);

    /*
     * @brief   clear
     * @param   void*             param   [IN] see binder(..., void* param)
     * @return  error code (see error.hpp)
     */
    return_t clear (void* param);

    /*
     * @brief   set
     */
    return_t set (int mode, int value);

    size_t size ();

protected:

    typedef typename std::queue<TYPENAME_T*> mlfq_queue_t; // control by reference counter (see binder operation)
    typedef typename std::set<TYPENAME_T*> mlfq_set_t;
    typedef typename std::map<int, mlfq_queue_t> mlfq_map_t;
    typedef typename std::pair<typename mlfq_map_t::iterator, bool> mlfq_map_pib_t;

    BINDER_T _binder;
    semaphore _semaphore;
    critical_section _lock;
    mlfq_map_t _mfq;
    mlfq_set_t _workingset;
    size_t _size;
    int _mode[5];
};

template<typename TYPENAME_T, typename BINDER_T>
t_mlfq<TYPENAME_T, BINDER_T>::t_mlfq () : _size (0)
{
    memset (_mode, 0xff, sizeof (_mode));
}

template<typename TYPENAME_T, typename BINDER_T>
t_mlfq<TYPENAME_T, BINDER_T>::~t_mlfq ()
{
    clear (nullptr);
}

template<typename TYPENAME_T, typename BINDER_T>
return_t t_mlfq<TYPENAME_T, BINDER_T>::post (int pri, TYPENAME_T* source, void* param)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == source) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        __try2
        {
            _lock.enter ();

            if (0 == _mode [mlfq_mode_t::mlfq_block]) {
                ret = errorcode_t::blocked;
                __leave2;
            }

            _binder.binder (mlfq_binder_operation_t::binder_v, source, param); // reference counter ++
            _size++;

            mlfq_queue_t clean_q;
            mlfq_map_pib_t pib = _mfq.insert (std::make_pair (pri, clean_q));
            typename mlfq_map_t::iterator qit = pib.first;
            mlfq_queue_t& q = qit->second;
            q.push (source);

            _workingset.insert (source);
            _semaphore.signal ();
        }
        __finally2
        {
            _lock.leave ();
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

template<typename TYPENAME_T, typename BINDER_T>
return_t t_mlfq<TYPENAME_T, BINDER_T>::push (int pri, TYPENAME_T* source, void* param)
{
    return post (pri, source, param); // given priority
}

template<typename TYPENAME_T, typename BINDER_T>
t_mlfq<TYPENAME_T, BINDER_T>& t_mlfq<TYPENAME_T, BINDER_T>::operator << (TYPENAME_T* source)
{
    post (0, source, nullptr); // default priority (0)
    return *this;
}

template<typename TYPENAME_T, typename BINDER_T>
return_t t_mlfq<TYPENAME_T, BINDER_T>::get (int* pri, TYPENAME_T** source, uint32 timeout)
{
    return_t ret = errorcode_t::success;

    __try2
    {
        if (nullptr == pri || nullptr == source) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        *source = nullptr;

        uint32 wait = _semaphore.wait (timeout);
        if (0 == wait) {
            ret = errorcode_t::not_found;
            _lock.enter ();
            // greater number mean more priority
            typename mlfq_map_t::reverse_iterator rit;
            for (rit = _mfq.rbegin (); rit != _mfq.rend (); rit++) {
                if (false == rit->second.empty ()) {
                    ret = errorcode_t::success;

                    TYPENAME_T* object = rit->second.front (); // gotcha

                    // search a workingset
                    typename mlfq_set_t::iterator workset_iter = _workingset.find (object);
                    if (_workingset.end () == workset_iter) {
                        ret = errorcode_t::canceled;
                    } else {
                        *pri = rit->first;
                        *source = object;
                    }
                    rit->second.pop (); // remove from queue
                    _size--;

                    if (errorcode_t::success == ret) {
                        break;
                    }
                }
            }
            _lock.leave ();
        } else {
            ret = errorcode_t::not_ready;
        }
    }
    __finally2
    {
        // do nothing
    }
    return ret;
}

template<typename TYPENAME_T, typename BINDER_T>
return_t t_mlfq<TYPENAME_T, BINDER_T>::pop (int* pri, TYPENAME_T** source, uint32 timeout)
{
    return get (pri, source, timeout);
}

template<typename TYPENAME_T, typename BINDER_T>
return_t t_mlfq<TYPENAME_T, BINDER_T>::cancel (TYPENAME_T* source, void* param)
{
    return_t ret = errorcode_t::success;

    // delete from workingset
    _lock.enter ();
    typename mlfq_set_t::iterator iter = _workingset.find (source);
    if (_workingset.end () != iter) {
        _binder.binder (mlfq_binder_operation_t::binder_p, source, param); // reference counter --
        _workingset.erase (iter);
    }
    _lock.leave ();
    return ret;
}

template<typename TYPENAME_T, typename BINDER_T>
size_t t_mlfq<TYPENAME_T, BINDER_T>::size ()
{
    return _size;
}

template<typename TYPENAME_T, typename BINDER_T>
return_t t_mlfq<TYPENAME_T, BINDER_T>::clear (void* param)
{
    return_t ret = errorcode_t::success;

    _lock.enter ();
    for (typename mlfq_map_t::iterator it = _mfq.begin (); it != _mfq.end (); it++) {
        mlfq_queue_t& q = it->second;

        while (false == q.empty ()) {
            TYPENAME_T* source = q.front ();
            q.pop ();

            typename mlfq_set_t::iterator iter = _workingset.find (source);
            if (_workingset.end () != iter) {
                _binder.binder (mlfq_binder_operation_t::binder_p, source, param); // reference counter --
                _workingset.erase (iter);
            }

            // no signals to handler
        }
    }
    _size = 0;
    _workingset.clear ();
    _lock.leave ();
    return ret;
}

template<typename TYPENAME_T, typename BINDER_T>
return_t t_mlfq<TYPENAME_T, BINDER_T>::set (int mode, int value)
{
    return_t ret = errorcode_t::success;

    _lock.enter ();
    switch (mode) {
        case mlfq_mode_t::mlfq_block: // _mode [0]
            _mode [mlfq_mode_t::mlfq_block] = value;
            break;
        default:
            break;
    }
    _lock.leave ();

    return ret;
}

}
}  // namespace

#endif
