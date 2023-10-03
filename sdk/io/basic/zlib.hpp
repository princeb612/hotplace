/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_IO_BASIC_ZLIB__
#define __HOTPLACE_SDK_IO_BASIC_ZLIB__

#include <hotplace/sdk/base.hpp>
#include <hotplace/sdk/io/stream/stream.hpp>

namespace hotplace {
namespace io {

enum zlib_windowbits_t {
    windowbits_compress = 0,    /* using windowBits MAX_WBITS(15) */
    windowbits_deflate  = 1,    /* RFC1951 : DEFLATE Compressed Data Format Specification version 1.3, using windowBits -MAX_WBITS(-15) */
    windowbits_zlib     = 2,    /* RFC1952 : GZIP file format specification version 4.3, using windowBits MAX_WBITS + 16(31) */
};

return_t zlib_deflate (zlib_windowbits_t windowbits, binary_t const& input, binary_t& output);
return_t zlib_inflate (zlib_windowbits_t windowbits, binary_t const& input, binary_t& output);
return_t zlib_deflate (zlib_windowbits_t windowbits, byte_t const* input, size_t size, binary_t& output);
return_t zlib_inflate (zlib_windowbits_t windowbits, byte_t const* input, size_t size, binary_t& output);
return_t zlib_deflate (zlib_windowbits_t windowbits, stream_t* input, binary_t& output);
return_t zlib_inflate (zlib_windowbits_t windowbits, stream_t* input, binary_t& output);
return_t zlib_deflate (zlib_windowbits_t windowbits, binary_t const& input, stream_t* output);
return_t zlib_inflate (zlib_windowbits_t windowbits, binary_t const& input, stream_t* output);
return_t zlib_deflate (zlib_windowbits_t windowbits, byte_t const* input, size_t size, stream_t* output);
return_t zlib_inflate (zlib_windowbits_t windowbits, byte_t const* input, size_t size, stream_t* output);
return_t zlib_deflate (zlib_windowbits_t windowbits, stream_t* input, stream_t* output);
return_t zlib_inflate (zlib_windowbits_t windowbits, stream_t* input, stream_t* output);
int zlib_def (FILE *source, FILE *dest, int level);
int zlib_inf (FILE *source, FILE *dest);

}
}  // namespace

#endif
