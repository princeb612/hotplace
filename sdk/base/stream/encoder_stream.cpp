/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   encoder_stream.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <hotplace/sdk/base/basic/base16.hpp>
#include <hotplace/sdk/base/basic/base64.hpp>
#include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/stream/encoder_stream.hpp>
#include <hotplace/sdk/base/system/endian.hpp>

namespace hotplace {

encoder_stream::encoder_stream(encoding_t enc, bool use_bigendian) : _encoding(enc), _use_bigendian(use_bigendian), _maxsize(1 << 12) {}

encoding_t encoder_stream::get_encoding() { return _encoding; }

encoder_stream& encoder_stream::set_endian(bool use_bigendian) {
    _use_bigendian = use_bigendian;
    return *this;
}

bool encoder_stream::is_bigendian() { return _use_bigendian; }

return_t encoder_stream::write(const byte_t* data, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == data) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        if (size > _maxsize) {
            throw exception(errorcode_t::exceed);
        }

        auto unitsize = _encbuf.unitsize(get_encoding());
        switch (get_encoding()) {
            case encoding_base16: {
                base16_encode(data, size, _buffer, base16_notrunc);
            } break;
            case encoding_base16rfc: {
                std::string buf;
                buf.assign((char*)data, size);
                _buffer += base16_encode_rfc(buf);
            } break;
            case encoding_base64:
            case encoding_base64url: {
                size_t pos = 0;
                // _encbuf
                if (_encbuf.len > 0) {
                    size_t need = _encbuf.free_space(_encoding);
                    if (size >= need) {
                        memcpy(_encbuf.buf + _encbuf.len, data, need);
                        _encbuf.len += need;
                        ret = base64_encode(_encbuf.buf, unitsize, _buffer, _encoding, base16_notrunc);
                        _encbuf.reset();
                        if (errorcode_t::success != ret) {
                            break;
                        }
                        pos += need;
                    } else {
                        memcpy(_encbuf.buf + _encbuf.len, data, size);
                        _encbuf.len += (uint8)size;
                        break;
                    }
                }
                size_t remain = size - pos;
                size_t remainder = remain % unitsize;
                size_t processlen = remain - remainder;
                if (processlen > 0) {
                    ret = base64_encode(data + pos, processlen, _buffer, _encoding, base64_notrunc);
                    if (errorcode_t::success != ret) {
                        break;
                    }
                    pos += processlen;
                }
                if (remainder > 0) {
                    memcpy(_encbuf.buf, data + pos, remainder);
                    _encbuf.len = (uint8)remainder;
                }
            } break;
            default: {
                ret = errorcode_t::not_supported;
            } break;
        }
    }
    __finally2 {}
    return ret;
}

return_t encoder_stream::flush() {
    return_t ret = errorcode_t::success;
    switch (get_encoding()) {
        case encoding_base16: {
            // do nothing
        } break;
        case encoding_base64:
        case encoding_base64url: {
            if (_encbuf.len > 0) {
                ret = base64_encode(_encbuf.buf, _encbuf.len, _buffer, _encoding, base64_notrunc);
                _encbuf.reset();
            }
        } break;
        default: {
            // do nothing
        } break;
    }
    return ret;
}

encoder_stream& encoder_stream::operator<<(const char* value) { return add(value); }

encoder_stream& encoder_stream::operator<<(const std::string& value) { return add(value); }

encoder_stream& encoder_stream::operator<<(const binary_t& value) { return add(value); }

encoder_stream& encoder_stream::operator<<(const basic_stream& value) { return add(value); }

encoder_stream& encoder_stream::add(const char* value) {
    if (value) {
        auto size = strlen(value);
        write((byte_t*)value, size);
    }
    return *this;
}

encoder_stream& encoder_stream::add(const byte_t* data, size_t size) {
    write(data, size);
    return *this;
}

encoder_stream& encoder_stream::add(const std::string& value) {
    write((byte_t*)value.c_str(), value.size());
    return *this;
}

encoder_stream& encoder_stream::add(const binary_t& value) {
    write(value.data(), value.size());
    return *this;
}

encoder_stream& encoder_stream::add(const basic_stream& value) {
    write(value.data(), value.size());
    return *this;
}

encoder_stream& encoder_stream::add(int8 value) {
    write((byte_t*)&value, 1);
    return *this;
}

encoder_stream& encoder_stream::add(int16 value) {
    if (is_bigendian()) {
        auto v = hton16(value);
        write((byte_t*)&v, 2);
    } else {
        write((byte_t*)&value, 2);
    }
    return *this;
}

encoder_stream& encoder_stream::add(int32 value) {
    if (is_bigendian()) {
        auto v = hton32(value);
        write((byte_t*)&v, 4);
    } else {
        write((byte_t*)&value, 4);
    }
    return *this;
}

encoder_stream& encoder_stream::add(int64 value) {
    if (is_bigendian()) {
        auto v = hton64(value);
        write((byte_t*)&v, 8);
    } else {
        write((byte_t*)&value, 8);
    }
    return *this;
}

#if defined __SIZEOF_INT128__
encoder_stream& encoder_stream::add(int128 value) {
    if (is_bigendian()) {
        auto v = hton128(value);
        write((byte_t*)&v, 16);
    } else {
        write((byte_t*)&value, 16);
    }
    return *this;
}
#endif

encoder_stream& encoder_stream::add(uint8 value) {
    write((byte_t*)&value, 1);
    return *this;
}

encoder_stream& encoder_stream::add(uint16 value) {
    if (is_bigendian()) {
        auto v = hton16(value);
        write((byte_t*)&v, 2);
    } else {
        write((byte_t*)&value, 2);
    }
    return *this;
}

encoder_stream& encoder_stream::add(uint32 value) {
    if (is_bigendian()) {
        auto v = hton32(value);
        write((byte_t*)&v, 4);
    } else {
        write((byte_t*)&value, 4);
    }
    return *this;
}

encoder_stream& encoder_stream::add(uint64 value) {
    if (is_bigendian()) {
        auto v = hton64(value);
        write((byte_t*)&v, 8);
    } else {
        write((byte_t*)&value, 8);
    }
    return *this;
}

#if defined __SIZEOF_INT128__
encoder_stream& encoder_stream::add(uint128 value) {
    if (is_bigendian()) {
        auto v = hton128(value);
        write((byte_t*)&v, 16);
    } else {
        write((byte_t*)&value, 16);
    }
    return *this;
}
#endif

encoder_stream& encoder_stream::clear() {
    _buffer.clear();
    _encbuf.reset();
    return *this;
}

std::string encoder_stream::str() {
    flush();
    return _buffer;
}

}  // namespace hotplace
