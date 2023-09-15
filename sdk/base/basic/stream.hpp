/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file    stream.hpp
 * @brief   stream
 * @author  hush (princeb612.kr@gmail.com)
 */

#ifndef __HOTPLACE_SDK_BASE_BASIC_STREAM__
#define __HOTPLACE_SDK_BASE_BASIC_STREAM__

#include <hotplace/sdk/base/types.hpp>
#include <hotplace/sdk/base/error.hpp>

namespace hotplace {

enum stream_type_t {
    undefined   = 0,
    memory      = 1,
    file        = 2,
};

class stream_t
{
public:
    virtual ~stream_t ()
    {
    }

    virtual byte_t* data () = 0;
    virtual uint64 size () = 0;
    virtual return_t write (void* data, size_t size) = 0;
    virtual return_t fill (size_t l, char c) = 0;
    virtual return_t clear () = 0;

    virtual return_t printf (const char* buf, ...) = 0;
    virtual return_t vprintf (const char* buf, va_list ap) = 0;
};

}

#endif
