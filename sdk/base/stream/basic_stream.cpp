/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
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
#include <hotplace/sdk/base/system/bignumber.hpp>

namespace hotplace {

basic_stream::basic_stream() : _handle(nullptr) {
    size_t allocsize = stream_policy::get_instance()->get_allocsize();
    _bio.open(&_handle, allocsize, 1);
}

basic_stream::basic_stream(const char* data, ...) : _handle(nullptr) {
    size_t allocsize = stream_policy::get_instance()->get_allocsize();
    va_list ap;
    va_start(ap, data);
    _bio.open(&_handle, allocsize, 1);
    _bio.vprintf(_handle, data, ap);
    va_end(ap);
}

basic_stream::basic_stream(const basic_stream& other) : _handle(nullptr) {
    size_t allocsize = stream_policy::get_instance()->get_allocsize();

    _bio.open(&_handle, allocsize, 1);

    byte_t* data = nullptr;
    size_t size = 0;
    _bio.get(other._handle, &data, &size);
    write((void*)data, size);
}

basic_stream::basic_stream(basic_stream&& other) : _handle(nullptr) {
    std::swap(_handle, other._handle);
    other._handle = nullptr;
}

basic_stream::~basic_stream() { _bio.close(_handle); }

const char* basic_stream::c_str() const {
    char* data = nullptr;
    size_t size = 0;

    _bio.get(_handle, (byte_t**)&data, &size);
    return data;
}

basic_stream::operator const char*() { return c_str(); }

basic_stream::operator char*() const { return (char*)c_str(); }

byte_t* basic_stream::data() const {
    byte_t* data = nullptr;
    size_t size = 0;

    _bio.get(_handle, &data, &size);
    return data;
}

uint64 basic_stream::size() const {
    byte_t* data = nullptr;
    size_t size = 0;

    _bio.get(_handle, &data, &size);
    return size;
}

return_t basic_stream::write(const void* data, size_t size) { return _bio.write(_handle, data, size); }

return_t basic_stream::cut(uint32 begin_pos, uint32 length) { return _bio.cut(_handle, begin_pos, length); }

return_t basic_stream::insert(size_t begin, const void* data, size_t data_size) { return _bio.insert(_handle, begin, data, data_size); }

return_t basic_stream::fill(size_t l, char c) {
    return_t ret = errorcode_t::success;

    if (0 == l) {
        // do nothing
    } else if (l <= 16) {
        while (l--) {
            _bio.printf(_handle, "%c", c);
        }
    } else {
        const size_t chunk_size = 256;
        char buf[chunk_size];
        memset(buf, c, chunk_size);

        while (l && errorcode_t::success == ret) {
            size_t n = (l < chunk_size) ? l : chunk_size;
            ret = _bio.write(_handle, buf, n);
            l -= n;
        }
    }

    return ret;
}

return_t basic_stream::clear() { return _bio.clear(_handle); }

bool basic_stream::empty() { return _bio.empty(_handle); }

bool basic_stream::occupied() { return _bio.occupied(_handle); }

return_t basic_stream::printf(const char* buf, ...) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == buf) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        va_list ap;

        va_start(ap, buf);
        ret = _bio.vprintf(_handle, buf, ap);
        va_end(ap);
    }
    __finally2 {}
    return ret;
}

return_t basic_stream::vprintf(const char* buf, va_list ap) { return _bio.vprintf(_handle, buf, ap); }

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
        ret = _bio.vprintf(_handle, buf, ap);
        va_end(ap);
    }
    __finally2 {}
    return ret;
}

return_t basic_stream::vprintf(const wchar_t* buf, va_list ap) { return _bio.vprintf(_handle, buf, ap); }
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
        ret = _bio.vprintf(_handle, buf, ap);
        va_end(ap);

        _bio.printf(_handle, "\n");
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
    clear();
    write(other.data(), other.size());
    return *this;
}

basic_stream& basic_stream::operator=(basic_stream&& other) {
    clear();
    std::swap(_handle, other._handle);
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

int basic_stream::compare(const basic_stream& other) { return compare(*this, other); }

int basic_stream::compare(const basic_stream& lhs, const basic_stream& rhs) {
    int ret = -1;
    auto ldata = lhs.data();
    auto lsize = lhs.size();
    auto rdata = rhs.data();
    auto rsize = rhs.size();
    if (lsize == rsize) {
        ret = memcmp(ldata, rdata, lsize);
    } else {
        ret = (lsize < rsize) ? -1 : 1;
    }
    return ret;
}

bool basic_stream::operator<(const basic_stream& other) const { return 0 > compare(*this, other); }

bool basic_stream::operator>(const basic_stream& other) const { return 0 < compare(*this, other); }

bool basic_stream::operator==(const basic_stream& other) const { return 0 == compare(*this, other); }

bool basic_stream::operator==(const char* other) const {
    bool ret = false;
    if (other) {
        auto ldata = data();
        auto lsize = size();
        auto rdata = other;
        auto rsize = strlen(other);
        if (lsize == rsize) {
            ret = (0 == memcmp(ldata, rdata, lsize));
        } else {
            ret = (lsize < rsize) ? -1 : 1;
        }
    }
    return ret;
}

bool basic_stream::operator==(const std::string& other) const { return *this == other.c_str(); }

std::string& operator+=(std::string& lhs, const basic_stream& rhs) {
    lhs += rhs.c_str();
    return lhs;
}

std::string& operator<<(std::string& lhs, const basic_stream& rhs) {
    lhs += rhs.c_str();
    return lhs;
}

std::ostream& operator<<(std::ostream& lhs, const basic_stream& rhs) {
    lhs << rhs.c_str();
    return lhs;
}

void basic_stream::autoindent(uint8 indent) {
    _bio.autoindent(_handle, indent);
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
