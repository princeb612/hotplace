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
#include <hotplace/sdk/base/basic/http_huffman_coding.hpp>
#include <hotplace/sdk/base/nostd/exception.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/stream/encoder_stream.hpp>

namespace hotplace {

encoder_stream::encoder_stream(encoding_t enc, bool use_bigendian) : _encoding(enc), _use_bigendian(use_bigendian), _maxsize(1 << 15) {}

encoder_stream& encoder_stream::set_maxsize(size_t size) {
    _maxsize = size;
    return *this;
}

size_t encoder_stream::get_maxsize() { return _maxsize; }

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
        if (_buffer.size() + size > _maxsize) {
            ret = errorcode_t::exceed;
            __leave2;
        }

        auto unitsize = _encbuf.unitsize(get_encoding());
        switch (get_encoding()) {
            case encoding_t::encoding_base16: {
                base16_encode(data, size, _buffer, encoding_notrunc);
            } break;
            case encoding_t::encoding_base16rfc: {
                std::string buf;
                buf.assign((char*)data, size);
                _buffer += base16_encode_rfc(buf);
            } break;
            case encoding_t::encoding_base64:
            case encoding_t::encoding_base64url: {
                size_t pos = 0;
                // _encbuf
                if (_encbuf.len > 0) {
                    auto need = _encbuf.free_space(_encoding);
                    if (size >= need) {
                        memcpy(_encbuf.buf + _encbuf.len, data, need);
                        _encbuf.len += need;
                        ret = base64_encode(_encbuf.buf, unitsize, _buffer, _encoding, encoding_notrunc);
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
                    ret = base64_encode(data + pos, processlen, _buffer, _encoding, encoding_notrunc);
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
            case encoding_t::encoding_h2hcodes: {
                auto* huff = http_huffman_coding::get_instance();
                for (size_t i = 0; i < size; ++i) {
                    uint8 sym = data[i];
                    const auto& cache = huff->get_encode_cache(sym);
                    uint32 bits = cache.bit_code;
                    uint8 len = cache.bit_len;
                    for (int8 b = len - 1; b >= 0; --b) {
                        _bitbuf.buf <<= 1;
                        if ((bits >> b) & 1) _bitbuf.buf |= 1;
                        ++_bitbuf.len;

                        if (8 == _bitbuf.len) {
                            _bin.push_back((char)_bitbuf.buf);
                            _bitbuf.reset();
                        }
                    }
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
        case encoding_t::encoding_base16: {
            // do nothing
        } break;
        case encoding_t::encoding_base64:
        case encoding_t::encoding_base64url: {
            if (_encbuf.len > 0) {
                ret = base64_encode(_encbuf.buf, _encbuf.len, _buffer, _encoding, encoding_notrunc);
                _encbuf.reset();
            }
        } break;
        case encoding_t::encoding_h2hcodes: {
            if (_bitbuf.len > 0) {
                // auto* huff = http_huffman_coding::get_instance();
                uint8 shift = 8 - _bitbuf.len;
                _bitbuf.buf <<= shift;
                _bitbuf.buf |= ((1 << shift) - 1);  // huff->decodable() always true

                _bin.push_back((char)_bitbuf.buf);
                _bitbuf.reset();
            }
        } break;
        default: {
            // do nothing
        } break;
    }
    return ret;
}

encoder_stream& encoder_stream::clear() {
    _buffer.clear();
    _encbuf.reset();
    return *this;
}

std::string encoder_stream::str() {
    flush();
    return _buffer;
}

binary_t encoder_stream::bin() {
    flush();
    return _bin;
}

encoder_stream& encoder_stream::operator<<(bool value) {
    uint8 b = value ? 1 : 0;
    return *this << b;  // unit8 is_integral
}

encoder_stream& encoder_stream::operator<<(const char* value) {
    if (value) {
        write((byte_t*)value, strlen(value));
    }
    return *this;
}

encoder_stream& encoder_stream::operator<<(const std::string& value) {
    write((byte_t*)value.c_str(), value.size());
    return *this;
}

encoder_stream& encoder_stream::operator<<(const binary_t& value) {
    write(value.data(), value.size());
    return *this;
}

encoder_stream& encoder_stream::operator<<(const basic_stream& value) {
    write(value.data(), value.size());
    return *this;
}

}  // namespace hotplace
