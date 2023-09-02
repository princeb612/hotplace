/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#ifndef __HOTPLACE_SDK_IO_STREAM_BUFFERSTREAM__
#define __HOTPLACE_SDK_IO_STREAM_BUFFERSTREAM__

#include <hotplace/sdk/base.hpp>
#include <hotplace/sdk/io/stream/stream.hpp>
#include <hotplace/sdk/io/stream/bufferio.hpp>
#include <stdarg.h>
#include <iostream>

namespace hotplace {
namespace io {

class buffer_stream : public stream_t
{
public:
    buffer_stream (size_t allocsize = (1 << 12), uint32 flags = 0);
    buffer_stream (const char* data);
    buffer_stream (const buffer_stream& stream);
    virtual ~buffer_stream ();

    virtual char* c_str ();
    virtual byte_t* data ();
    virtual uint64 size ();
    virtual return_t write (void* data, size_t size);
    virtual return_t fill (size_t l, char c);
    virtual return_t clear ();

    virtual return_t printf (const char* buf, ...);
    virtual return_t vprintf (const char* buf, va_list ap);
#if defined _WIN32 || defined _WIN64
    virtual return_t printf (const wchar_t* buf, ...);
    virtual return_t vprintf (const wchar_t* buf, va_list ap);
#endif

    buffer_stream& operator = (buffer_stream obj);

    int compare (buffer_stream obj);
    static int compare (buffer_stream lhs, buffer_stream rhs);
    bool operator < (buffer_stream obj);
    bool operator > (buffer_stream obj);

protected:
    bufferio _bio;
    bufferio_context_t* _handle;
};

}
}  // namespace

#endif
