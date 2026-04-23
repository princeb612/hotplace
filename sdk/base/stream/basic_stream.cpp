/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   basic_stream.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <ctype.h>
#include <string.h>

#include <hotplace/sdk/base/basic/valist.hpp>
#include <hotplace/sdk/base/basic/variant.hpp>
#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/stream/printf.hpp>
#include <hotplace/sdk/base/stream/stream_policy.hpp>
#include <hotplace/sdk/base/system/bignumber.hpp>

namespace hotplace {

basic_stream::basic_stream() : stream_t(), _handle(nullptr) {
    size_t allocsize = stream_policy::get_instance()->get_allocsize();
    auto test = bufferio::open(&_handle, allocsize, 1);  // new _handle
    if (errorcode_t::success != test) {
        throw std::runtime_error("basic_stream.ctor");
    }
}

basic_stream::basic_stream(const char* data, ...) : basic_stream() {
    // delegating constructor
    va_list ap;
    va_start(ap, data);
    try {
        bufferio::vprintf(_handle, data, ap);  // consume va_list just one time, so do not va_copy
    } catch (...) {
        va_end(ap);
        throw;
    }
    va_end(ap);
}

basic_stream::basic_stream(const basic_stream& other) : stream_t(), _handle(nullptr) {
    bufferio_context_t* newone = nullptr;
    auto test = bufferio::clone(other._handle, &newone);
    if (errorcode_t::success != test) {
        throw std::runtime_error("basic_stream.ctor.copy");
    }
    _handle = newone;
}

basic_stream::basic_stream(basic_stream&& other) noexcept : stream_t(), _handle(other._handle) { other._handle = nullptr; }

basic_stream::~basic_stream() {
    if (_handle) {
        bufferio::close(_handle);
    }
}

const char* basic_stream::c_str() const {
    char* data = nullptr;
    size_t size = 0;

    bufferio::get(_handle, (byte_t**)&data, &size);
    return data;
}

basic_stream::operator const char*() { return c_str(); }

basic_stream::operator char*() const { return (char*)c_str(); }

byte_t* basic_stream::data() const {
    byte_t* data = nullptr;
    size_t size = 0;

    bufferio::get(_handle, &data, &size);
    return data;
}

uint64 basic_stream::size() const {
    byte_t* data = nullptr;
    size_t size = 0;

    bufferio::get(_handle, &data, &size);
    return size;
}

return_t basic_stream::write(const void* data, size_t size) { return bufferio::write(_handle, data, size); }

return_t basic_stream::cut(uint32 begin_pos, uint32 length) { return bufferio::cut(_handle, begin_pos, length); }

return_t basic_stream::insert(size_t begin, const void* data, size_t data_size) { return bufferio::insert(_handle, begin, data, data_size); }

return_t basic_stream::fill(size_t l, char c) {
    return_t ret = errorcode_t::success;

    if (0 == l) {
        // do nothing
    } else if (l <= 16) {
        while (l--) {
            bufferio::printf(_handle, "%c", c);
        }
    } else {
        const size_t chunk_size = 256;
        char buf[chunk_size];
        memset(buf, c, chunk_size);

        while (l && errorcode_t::success == ret) {
            size_t n = (l < chunk_size) ? l : chunk_size;
            ret = bufferio::write(_handle, buf, n);
            l -= n;
        }
    }

    return ret;
}

return_t basic_stream::clear() { return bufferio::clear(_handle); }

bool basic_stream::empty() { return bufferio::empty(_handle); }

bool basic_stream::occupied() { return bufferio::occupied(_handle); }

return_t basic_stream::printf(const char* buf, ...) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == buf) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        va_list ap;

        va_start(ap, buf);
        ret = bufferio::vprintf(_handle, buf, ap);
        va_end(ap);
    }
    __finally2 {}
    return ret;
}

return_t basic_stream::vprintf(const char* buf, va_list ap) { return bufferio::vprintf(_handle, buf, ap); }

#if defined _WIN32 || defined _WIN64
return_t basic_stream::printf(const wchar_t* buf, ...) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == buf) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        va_list ap;

        va_start(ap, buf);
        ret = bufferio::vprintf(_handle, buf, ap);
        va_end(ap);
    }
    __finally2 {}
    return ret;
}

return_t basic_stream::vprintf(const wchar_t* buf, va_list ap) { return bufferio::vprintf(_handle, buf, ap); }
#endif

return_t basic_stream::println(const char* buf, ...) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == buf) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        va_list ap;

        va_start(ap, buf);
        ret = bufferio::vprintf(_handle, buf, ap);
        va_end(ap);

        bufferio::printf(_handle, "\n");
    }
    __finally2 {}
    return ret;
}

return_t basic_stream::vprintf(const char* fmt, valist ap) {
    return_t ret = errorcode_t::success;
    ret = sprintf(this, fmt, ap);
    return ret;
}

basic_stream& basic_stream::operator=(const basic_stream& other) {
    if (this != &other) {
        basic_stream tmp(other);  // strong exeption guarantee
        std::swap(_handle, tmp._handle);
    }
    return *this;
}

basic_stream& basic_stream::operator=(basic_stream&& other) noexcept {
    if (this != &other) {
        std::swap(_handle, other._handle);
    }
    return *this;
}

basic_stream& basic_stream::operator=(const std::string& other) {
    clear();
    printf(other.c_str());
    return *this;
}

basic_stream& basic_stream::operator=(const char* other) {
    clear();
    if (other) {
        printf(other);
    }
    return *this;
}

basic_stream& basic_stream::operator<<(const char* other) {
    if (other) {
        printf(other);
    }
    return *this;
}

basic_stream& basic_stream::operator<<(char value) {
    printf("%c", value);
    return *this;
}

basic_stream& basic_stream::operator<<(int value) {
    printf("%i", value);
    return *this;
}

basic_stream& basic_stream::operator<<(unsigned int value) {
    printf("%u", value);
    return *this;
}

basic_stream& basic_stream::operator<<(long value) {
    printf("%li", value);
    return *this;
}

basic_stream& basic_stream::operator<<(unsigned long value) {
    printf("%lu", value);
    return *this;
}

basic_stream& basic_stream::operator<<(long long value) {
    printf("%lli", value);
    return *this;
}

basic_stream& basic_stream::operator<<(unsigned long long value) {
    printf("%llu", value);
    return *this;
}

#if defined __SIZEOF_INT128__
basic_stream& basic_stream::operator<<(int128 value) {
    printf("%I128i", value);
    return *this;
}

basic_stream& basic_stream::operator<<(uint128 value) {
    printf("%I128u", value);
    return *this;
}
#endif

basic_stream& basic_stream::operator<<(float value) {
    printf("%f", value);
    return *this;
}

basic_stream& basic_stream::operator<<(double value) {
    printf("%lf", value);
    return *this;
}

basic_stream& basic_stream::operator<<(const variant& value) {
    vtprintf(this, value, vtprintf_style_debugmode);
    return *this;
}

basic_stream& basic_stream::operator<<(const basic_stream& value) {
    write(value.data(), value.size());
    return *this;
}

basic_stream& basic_stream::operator<<(const std::string& value) {
    printf("%s", value.c_str());
    return *this;
}

basic_stream& basic_stream::operator<<(const binary_t& value) {
    write(value.data(), value.size());
    return *this;
}

basic_stream& basic_stream::operator<<(const bignumber& value) {
    printf("%s", value.str().c_str());
    return *this;
}

int basic_stream::compare(const basic_stream& other) { return compare(*this, other.c_str()); }

int basic_stream::compare(const basic_stream& lhs, const basic_stream& rhs) const { return compare(lhs, rhs.c_str()); }

int basic_stream::compare(const basic_stream& lhs, const char* rhs) const {
    int ret = -1;
    if (rhs) {
        auto ldata = lhs.data();
        auto lsize = lhs.size();
        auto rdata = rhs;
        auto rsize = strlen(rhs);
        if (lsize == rsize) {
            ret = memcmp(ldata, rdata, lsize);  // string and binary
        } else {
            ret = (lsize < rsize) ? -1 : 1;
        }
    }
    return ret;
}

bool basic_stream::operator<(const basic_stream& other) const { return compare(*this, other) < 0; }

bool basic_stream::operator>(const basic_stream& other) const { return compare(*this, other) > 0; }

bool basic_stream::operator==(const basic_stream& other) const { return compare(*this, other) == 0; }

bool basic_stream::operator==(const char* other) const { return compare(*this, other) == 0; }

bool basic_stream::operator==(const std::string& other) const { return compare(*this, other.c_str()) == 0; }

bool basic_stream::operator!=(const basic_stream& other) const { return compare(*this, other) != 0; }

bool basic_stream::operator!=(const char* other) const { return compare(*this, other) != 0; }

bool basic_stream::operator!=(const std::string& other) const { return compare(*this, other.c_str()) != 0; }

std::string& operator+=(std::string& lhs, const basic_stream& rhs) { return lhs += rhs.c_str(); }

std::string& operator<<(std::string& lhs, const basic_stream& rhs) { return lhs += rhs.c_str(); }

std::ostream& operator<<(std::ostream& lhs, const basic_stream& rhs) { return lhs << rhs.c_str(); }

void basic_stream::autoindent(uint8 indent) {
    bufferio::autoindent(_handle, indent);
    if (indent) {
        fill(indent, ' ');
    } else {
        *this << '\r';
    }
}

void basic_stream::resize(size_t s) {
    auto z = size();
    if (0 == s) {
        clear();
    } else if (z > s) {
        // cut
        cut(s, z - s);
    } else {
        // extend
        fill(s - z, 0);
    }
}

}  // namespace hotplace
