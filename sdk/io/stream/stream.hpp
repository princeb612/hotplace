/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file    stream.hpp
 * @brief   stream
 * @author  hush (princeb612.kr@gmail.com)
 */

#ifndef __HOTPLACE_SDK_STREAM_STREAM__
#define __HOTPLACE_SDK_STREAM_STREAM__

#include <hotplace/sdk/base.hpp>
#include <hotplace/sdk/io/string/valist.hpp>

namespace hotplace {
namespace io {

enum stream_type_t {
    undefined   = 0,
    memory      = 1,
    file        = 2,
};

enum filestream_flag_t {
    flag_normal                 = 0,
    flag_write                  = 1 << 0,   /* write                */
    flag_exclusive_flock        = 1 << 1,   /* open w/ lock         */
    flag_create_if_not_exist    = 1 << 2,   /* create if not exists */
    flag_create_always          = 1 << 3,   /* always create        */
    flag_share_flock            = 1 << 4,   /* open w/ lock         */

    open_existing               = flag_normal,
    open_readonly               = flag_normal,
    open_create                 = flag_create_if_not_exist | flag_write,
    open_write                  = flag_create_if_not_exist | flag_write,
    open_create_always          = flag_create_always | flag_write,
    exclusive_read              = flag_normal | flag_exclusive_flock,
    exclusive_write             = flag_create_if_not_exist | flag_write | flag_exclusive_flock,
    exclusive_create            = flag_create_always | flag_write | flag_exclusive_flock,
    share_read                  = flag_normal | flag_share_flock,
    share_write                 = flag_create_if_not_exist | flag_write | flag_share_flock,
    share_create                = flag_create_always | flag_write | flag_share_flock,
};

#define FILE_BEGIN 0
#define FILE_CURRENT 1
#define FILE_END 2

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
    virtual return_t flush () = 0;

    virtual return_t printf (const char* buf, ...) = 0;
    virtual return_t vprintf (const char* buf, va_list ap) = 0;
};

#if defined _WIN32 || defined _WIN64
return_t A2W (stream_t* stream, const char* source, uint32 codepage = 0);

return_t W2A (stream_t* stream, const wchar_t* source, uint32 codepage = 0);
#endif

/*
 * @brief   safe format printer
 * @remakrs
 *          format specifier replacement (do not supports %c %s %d, but {1} {2} {3} ... available)
 *          standard vprintf(fmt, ap) supports ordered format specifier {1} {2} {3} ...
 * @sample
 *          buffer_stream bs;
 *          valist va;
 *          va << 1 << "test string"; // argc 2
 *          sprintf (&bs, "value1={1} value2={2}", va); // value1=1 value2=test string
 *          sprintf (&bs, "value1={2} value2={1}", va); // value1=test string value2=1
 *          sprintf (&bs, "value1={2} value2={1} value3={3}", va); // value1=test string value2=1 value3={3}
 */
return_t sprintf (stream_t* stream, const char* fmt, valist va);
/**
 * @brief printf variant_t
 * @sample
 *  buffer_stream bs;
 *  variant_t v;
 *
 *  variant_set_int32 (v, 10);
 *  vtprintf (&bs, v);
 *
 *  variant_set_str_new (v, "sample");
 *  vtprintf (&bs, v);
 *  variant_free (v);
 *
 *  std::cout << bs.c_str () << std::endl;
 */
return_t vtprintf (stream_t* stream, variant_t vt);

//
// part - dump
//

/**
 * @brief dump memory
 * @sample
 *  const char* data = "hello world\n wide world\n";
 *
 *  buffer_stream bs;
 *  dump_memory ((byte_t*) data, strlen (data), &bs, 16, 0, 0x0, dump_memory_flag_t::header);
 *  std::cout << bs.c_str () << std::endl;
 */

enum dump_memory_flag_t {
    header = (1 << 0),
};
return_t dump_memory (const byte_t* dump_address, size_t dump_size, stream_t* stream_object,
                      unsigned hex_part = 16,
                      unsigned indent = 0,
                      size_t rebase = 0x0,
                      int flags = 0);
return_t dump_memory (const std::string& data, stream_t* stream_object,
                      unsigned hex_part = 16,
                      unsigned indent = 0,
                      size_t rebase = 0x0,
                      int flags = 0);
return_t dump_memory (const binary_t& data, stream_t* stream_object,
                      unsigned hex_part = 16,
                      unsigned indent = 0,
                      size_t rebase = 0x0,
                      int flags = 0);

}
}

#endif
