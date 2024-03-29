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

#include <sdk/base/stream/basic_stream.hpp>

namespace hotplace {

basic_stream::basic_stream(size_t allocsize, uint32 flags) : _handle(nullptr) { _bio.open(&_handle, allocsize, 1, flags); }

basic_stream::basic_stream(const char* data, ...) : _handle(nullptr) {
    va_list ap;
    va_start(ap, data);
    _bio.open(&_handle, 1 << 10, 1);
    _bio.vprintf(_handle, data, ap);
    va_end(ap);
}

basic_stream::basic_stream(const basic_stream& stream) : _handle(nullptr) {
    _bio.open(&_handle, 1 << 10, 1);
    byte_t* data = nullptr;
    size_t size = 0;

    _bio.get(stream._handle, &data, &size);
    write((void*)data, size);
}

basic_stream::~basic_stream() { _bio.close(_handle); }

const char* basic_stream::c_str() const {
    char* data = nullptr;
    size_t size = 0;

    _bio.get(_handle, (byte_t**)&data, &size);
    return data;
}

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

    while (l--) {
        _bio.printf(_handle, "%c", c);
    }
    return ret;
}

return_t basic_stream::clear() { return _bio.clear(_handle); }

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
    __finally2 {
        // do nothing
    }
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
    __finally2 {
        // do nothing
    }
    return ret;
}

return_t basic_stream::vprintf(const wchar_t* buf, va_list ap) { return _bio.vprintf(_handle, buf, ap); }
#endif

basic_stream& basic_stream::operator=(basic_stream const& obj) {
    clear();
    write(obj.data(), obj.size());
    return *this;
}

basic_stream& basic_stream::operator=(std::string const& str) {
    clear();
    printf(str.c_str());
    return *this;
}

basic_stream& basic_stream::operator=(const char* str) {
    clear();
    if (str) {
        printf(str);
    }
    return *this;
}

basic_stream& basic_stream::operator<<(const char* str) {
    if (str) {
        printf(str);
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

basic_stream& basic_stream::operator<<(unsigned long long value) {
    printf("%llu", value);
    return *this;
}

basic_stream& basic_stream::operator<<(basic_stream const& value) {
    write(value.data(), value.size());
    return *this;
}

basic_stream& basic_stream::operator<<(std::string const& value) {
    printf("%s", value.c_str());
    return *this;
}

int basic_stream::compare(basic_stream const& obj) { return strcmp((*this).c_str(), obj.c_str()); }

int basic_stream::compare(basic_stream& lhs, basic_stream& rhs) { return strcmp(lhs.c_str(), rhs.c_str()); }

bool basic_stream::operator<(basic_stream& obj) { return 0 < strcmp((*this).c_str(), obj.c_str()); }

bool basic_stream::operator>(basic_stream& obj) { return 0 > strcmp((*this).c_str(), obj.c_str()); }

bool basic_stream::operator==(basic_stream& obj) { return 0 == strcmp((*this).c_str(), obj.c_str()); }

}  // namespace hotplace
