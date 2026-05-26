/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   decoder_stream.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <hotplace/sdk/base/basic/base16.hpp>
#include <hotplace/sdk/base/basic/base64.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/stream/encoder_stream.hpp>
#include <hotplace/sdk/base/system/endian.hpp>

namespace hotplace {

decoder_stream::decoder_stream(encoding_t enc) : _encoding(enc), _maxsize(1 << 15) {}

decoder_stream& decoder_stream::set_maxsize(size_t size) {
    _maxsize = size;
    return *this;
}

size_t decoder_stream::get_maxsize() { return _maxsize; }

encoding_t decoder_stream::get_encoding() { return _encoding; }

return_t decoder_stream::write(const char* data, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        if ((nullptr == data) && (size > 0)) {
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
                size_t pos = 0;
                // _encbuf
                if (_encbuf.len > 0) {
                    auto need = _encbuf.free_space(_encoding);
                    if (size >= need) {
                        memcpy(_encbuf.buf + _encbuf.len, data, need);
                        _encbuf.len += need;
                        ret = base16_decode(_encbuf.buf, unitsize, _buffer, encoding_notrunc);
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
                size_t quotient = remain / unitsize;
                size_t remainder = remain % unitsize;
                if (quotient > 0) {
                    ret = base16_decode(data + pos, quotient * unitsize, _buffer, encoding_notrunc);
                    if (errorcode_t::success != ret) {
                        break;
                    }
                    pos += (quotient * unitsize);
                }
                if (remainder > 0) {
                    memcpy(_encbuf.buf, data + pos, remainder);
                    _encbuf.len = (uint8)remainder;
                }
            } break;
            case encoding_t::encoding_base16rfc: {
                ret = errorcode_t::not_supported;
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
                        ret = base64_decode(_encbuf.buf, unitsize, _buffer, _encoding, encoding_notrunc);
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
                    ret = base64_decode(data + pos, processlen, _buffer, _encoding, encoding_notrunc);
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

return_t decoder_stream::flush() {
    return_t ret = errorcode_t::success;
    switch (get_encoding()) {
        case encoding_t::encoding_base16: {
            if (_encbuf.len == 2) {
                ret = base16_decode(_encbuf.buf, _encbuf.len, _buffer, encoding_notrunc);
                _encbuf.reset();
            }
        } break;
        case encoding_t::encoding_base64:
        case encoding_t::encoding_base64url: {
            if (_encbuf.len == 1) {
                _encbuf.reset();
                break;
            }
            if (_encbuf.len > 0) {
                ret = base64_decode(_encbuf.buf, _encbuf.len, _buffer, _encoding, encoding_notrunc);
                _encbuf.reset();
            }
        } break;
        default: {
            // do nothing
        } break;
    }
    return ret;
}

binary_t decoder_stream::data() {
    flush();
    return _buffer;
}

decoder_stream& decoder_stream::add(const char* data, size_t size) {
    write(data, size);
    return *this;
}

decoder_stream& decoder_stream::operator<<(const char* value) {
    if (value) {
        write(value, strlen(value));
    }
    return *this;
}

decoder_stream& decoder_stream::operator<<(const std::string& value) {
    write(value.c_str(), value.size());
    return *this;
}

decoder_stream& decoder_stream::operator<<(const basic_stream& value) {
    write(value.c_str(), value.size());
    return *this;
}

}  // namespace hotplace
