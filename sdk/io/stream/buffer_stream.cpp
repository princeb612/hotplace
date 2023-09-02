/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/io/stream/buffer_stream.hpp>
#include <ctype.h>

namespace hotplace {
namespace io {

buffer_stream::buffer_stream (size_t allocsize, uint32 flags)
    : _handle (nullptr)
{
    _bio.open (&_handle, allocsize, 1, flags);
}

buffer_stream::buffer_stream (const char* data)
    :
    _handle (nullptr)
{
    _bio.open (&_handle, 1 << 10, 1);
    _bio.write (_handle, data, strlen (data));
}

buffer_stream::buffer_stream (const buffer_stream& stream)
    :
    _handle (nullptr)
{
    _bio.open (&_handle, 1 << 10, 1);
    byte_t* data = nullptr;
    size_t size = 0;

    _bio.get (stream._handle, &data, &size);
    write ((void *) data, size);
}

buffer_stream::~buffer_stream ()
{
    _bio.close (_handle);
}

char* buffer_stream::c_str ()
{
    char* data = nullptr;
    size_t size = 0;

    _bio.get (_handle, (byte_t**) &data, &size);
    return data;
}

byte_t* buffer_stream::data ()
{
    byte_t* data = nullptr;
    size_t size = 0;

    _bio.get (_handle, &data, &size);
    return data;
}

uint64 buffer_stream::size ()
{
    byte_t* data = nullptr;
    size_t size = 0;

    _bio.get (_handle, &data, &size);
    return size;
}

return_t buffer_stream::write (void* data, size_t size)
{
    return _bio.write (_handle, data, size);
}

return_t buffer_stream::fill (size_t l, char c)
{
    return_t ret = errorcode_t::success;

    while (l--) {
        _bio.printf (_handle, "%c", c);
    }
    return ret;
}

return_t buffer_stream::clear ()
{
    return _bio.clear (_handle);
}

return_t buffer_stream::printf (const char* buf, ...)
{
    return_t ret = 0;
    va_list ap;

    va_start (ap, buf);
    ret = _bio.vprintf (_handle, buf, ap);
    va_end (ap);
    return ret;
}

return_t buffer_stream::vprintf (const char* buf, va_list ap)
{
    return _bio.vprintf (_handle, buf, ap);
}

#if defined _WIN32 || defined _WIN64
return_t buffer_stream::printf (const wchar_t* buf, ...)
{
    return_t ret = 0;
    va_list ap;

    va_start (ap, buf);
    ret = _bio.vprintf (_handle, buf, ap);
    va_end (ap);
    return ret;
}

return_t buffer_stream::vprintf (const wchar_t* buf, va_list ap)
{
    return _bio.vprintf (_handle, buf, ap);
}
#endif

buffer_stream& buffer_stream::operator = (buffer_stream obj)
{
    clear ();
    write (obj.data (), obj.size ());
    return *this;
}

int buffer_stream::compare (buffer_stream obj)
{
    return strcmp ((*this).c_str (), obj.c_str ());
}

int buffer_stream::compare (buffer_stream lhs, buffer_stream rhs)
{
    return strcmp (lhs.c_str (), rhs.c_str ());
}

bool buffer_stream::operator < (buffer_stream obj)
{
    return 0 < strcmp ((*this).c_str (), obj.c_str ());
}

bool buffer_stream::operator > (buffer_stream obj)
{
    return 0 > strcmp ((*this).c_str (), obj.c_str ());
}

}
}  // namespace
