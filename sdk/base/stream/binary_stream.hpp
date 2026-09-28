/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   binary_stream.hpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#ifndef __HOTPLACE_SDK_BASE_STREAM_BINARYSTREAM__
#define __HOTPLACE_SDK_BASE_STREAM_BINARYSTREAM__

#include <stdarg.h>
#include <string.h>

#include <hotplace/sdk/base/nostd/binary.hpp>

namespace hotplace {

class binary_stream {
   public:
    binary_stream();
    binary_stream(const binary_t& other);
    binary_stream(binary_t&& other);
    virtual ~binary_stream() = default;

    binary_stream& operator=(const binary_t& other);
    binary_stream& operator=(binary_t&& other);

    binary_stream& set_endian(bool bigendian);
    const bool is_bigendian() const;

    binary_stream& prefix(int8 value);
    binary_stream& prefix(uint8 value);
    binary_stream& prefix(int16 value);
    binary_stream& prefix(uint16 value);
    binary_stream& prefix(int32 value);
    binary_stream& prefix(uint32 value);
    binary_stream& prefix(int64 value);
    binary_stream& prefix(uint64 value);
    binary_stream& prefix(const binary_t& value);

    binary_stream& append(int8 value);
    binary_stream& append(uint8 value);
    binary_stream& append(int16 value);
    binary_stream& append(uint16 value);
    binary_stream& append(int32 value);
    binary_stream& append(uint32 value);
    binary_stream& append(int64 value);
    binary_stream& append(uint64 value);
    binary_stream& append(const byte_t* p, size_t len);
    binary_stream& append(const std::string& value);
    binary_stream& append(const binary_t& value);

    void clear();
    binary_t& get();
    const binary_t& get() const;
    const size_t size() const;
    const bool empty() const;

   private:
    binary_t _bin;
    bool _bigendian;
};

}  // namespace hotplace

#endif
