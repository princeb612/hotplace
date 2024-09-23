/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/basic/valist.hpp>
#include <sdk/base/stream/printf.hpp>
#include <sdk/base/stream/tstring.hpp>
#include <sdk/base/string/string.hpp>

namespace hotplace {

ansi_string::ansi_string() {
    size_t allocsize = stream_policy::get_instance()->get_allocsize();
    _bio.open(&_handle, allocsize, sizeof(char), bufferio_context_flag_t::memzero_free);
}

ansi_string::ansi_string(const char* data) {
    size_t allocsize = stream_policy::get_instance()->get_allocsize();

    _bio.open(&_handle, allocsize, sizeof(char), bufferio_context_flag_t::memzero_free);
    _bio.write(_handle, data, strlen(data));
}

ansi_string::ansi_string(const ansi_string& rhs) {
    size_t allocsize = stream_policy::get_instance()->get_allocsize();

    _bio.open(&_handle, allocsize, sizeof(char), bufferio_context_flag_t::memzero_free);
    byte_t* data = nullptr;
    size_t size = 0;

    _bio.get(rhs._handle, &data, &size);
    write((void*)data, size);
}

ansi_string::ansi_string(ansi_string&& rhs) {
    size_t allocsize = stream_policy::get_instance()->get_allocsize();
    _bio.open(&_handle, allocsize, sizeof(char), bufferio_context_flag_t::memzero_free);

    std::swap(_handle, rhs._handle);
}

ansi_string::~ansi_string() { _bio.close(_handle); }

byte_t* ansi_string::data() const {
    byte_t* data = nullptr;
    size_t size = 0;

    _bio.get(_handle, &data, &size);
    return data;
}

uint64 ansi_string::size() const {
    byte_t* data = nullptr;
    size_t size = 0;

    _bio.get(_handle, &data, &size);
    return size;
}

return_t ansi_string::write(const void* data, size_t size) { return _bio.write(_handle, data, size); }

return_t ansi_string::fill(size_t l, char c) {
    return_t ret = errorcode_t::success;

    while (l--) {
        _bio.printf(_handle, "%c", c);
    }
    return ret;
}

return_t ansi_string::clear() { return _bio.clear(_handle); }

bool ansi_string::empty() { return _bio.empty(_handle); }

bool ansi_string::occupied() { return _bio.occupied(_handle); }

return_t ansi_string::printf(const char* buf, ...) {
    return_t ret = errorcode_t::success;
    va_list ap;

    va_start(ap, buf);
    ret = _bio.vprintf(_handle, buf, ap);
    va_end(ap);
    return ret;
}

return_t ansi_string::vprintf(const char* buf, va_list ap) {
    return_t ret = errorcode_t::success;

    ret = _bio.vprintf(_handle, buf, ap);
    return ret;
}

#if defined _WIN32 || defined _WIN64
return_t ansi_string::printf(const wchar_t* buf, ...) {
    return_t ret = errorcode_t::success;
    va_list ap;
    basic_stream bs;

    va_start(ap, buf);
    bs.vprintf(buf, ap);
    va_end(ap);
    ret = W2A(this, (wchar_t*)bs.data());
    return ret;
}

return_t ansi_string::vprintf(const wchar_t* buf, va_list ap) {
    return_t ret = errorcode_t::success;
    basic_stream bs;

    bs.vprintf(buf, ap);
    ret = W2A(this, (wchar_t*)bs.data());
    return ret;
}
#endif

return_t ansi_string::vprintf(const char* fmt, valist ap) {
    return_t ret = errorcode_t::success;
    ret = sprintf(this, fmt, ap);
    return ret;
}

const char* ansi_string::c_str() const {
    char* data = nullptr;
    size_t size = 0;

    _bio.get(_handle, (byte_t**)&data, &size);
    return data ? const_cast<const char*>(data) : "";
}

size_t ansi_string::find(char* data) { return _bio.find_first_of(_handle, data); }

return_t ansi_string::replace(const char* from, const char* to, size_t begin, int flag) { return _bio.replace(_handle, from, to, begin, flag); }

ansi_string ansi_string::substr(size_t begin, size_t len) {
    ansi_string stream;

    _bio.lock(_handle);
    stream.printf("%.*s", len, c_str() + begin);
    _bio.unlock(_handle);
    return stream;
}

return_t ansi_string::cut(size_t begin, size_t len) { return _bio.cut(_handle, begin, len); }

return_t ansi_string::trim() {
    return_t ret = errorcode_t::success;

    ltrim();
    rtrim();
    return ret;
}

return_t ansi_string::ltrim() {
    return_t ret = errorcode_t::success;
    size_t begin = _bio.find_not_first_of(_handle, isspace, 0);

    if ((size_t)-1 != begin) {
        _bio.cut(_handle, 0, begin);
    }
    return ret;
}

return_t ansi_string::rtrim() {
    return_t ret = errorcode_t::success;
    size_t len = 0;
    size_t end = _bio.find_not_last_of(_handle, isspace);

    _bio.size(_handle, &len);
    if ((size_t)-1 != end) {
        _bio.cut(_handle, end, len - end);  // base
    }
    return ret;
}

size_t ansi_string::find_first_of(const char* find, size_t offset) { return _bio.find_first_of(_handle, find, offset); }

size_t ansi_string::find_not_first_of(const char* find, size_t offset) { return _bio.find_not_first_of(_handle, find, offset); }

size_t ansi_string::find_last_of(const char* find) { return _bio.find_last_of(_handle, find); }

size_t ansi_string::find_not_last_of(const char* find) { return _bio.find_not_last_of(_handle, find); }

static int isnewline(int c) {
    int ret_value = 0;

    // match \f, \v, \r, \n
    // except space, \t
    if (0x20 != c && 0x9 != c) {
        ret_value = isspace(c);
    }
    return ret_value;
}

return_t ansi_string::getline(size_t pos, size_t* brk, ansi_string& line) {
    return_t ret = errorcode_t::success;

    line.clear();

    __try2 {
        if (nullptr == brk) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const char* p = (const char*)data();

        _bio.lock(_handle);
        ret = scan(p, size(), pos, brk, isnewline);
        if (errorcode_t::success == ret) {
            line.write((void*)(p + pos), *brk - pos);
            line.trim();
        }
        _bio.unlock(_handle);
    }
    __finally2 {
        // do nothing
    }

    return ret;
}

ansi_string& ansi_string::operator=(const char* buf) {
    clear();
    if (buf) {
        printf("%s", buf);
    }
    return *this;
}

#if defined _WIN32 || defined _WIN64
ansi_string& ansi_string::operator=(const wchar_t* buf) {
    clear();
    if (nullptr != buf) {
        W2A(this, buf);
    }
    return *this;
}
#endif

ansi_string& ansi_string::operator=(char buf) {
    clear();
    printf("%c", buf);
    return *this;
}

ansi_string& ansi_string::operator=(byte_t buf) {
    clear();
    printf("%c", buf);
    return *this;
}

ansi_string& ansi_string::operator=(uint16 buf) {
    clear();
    printf("%i", buf);
    return *this;
}

ansi_string& ansi_string::operator=(uint32 buf) {
    clear();
    printf("%i", buf);
    return *this;
}

ansi_string& ansi_string::operator=(uint64 buf) {
    clear();
    printf("%I64i", buf);
    return *this;
}

ansi_string& ansi_string::operator=(float buf) {
    clear();
    printf("%f", buf);
    return *this;
}

ansi_string& ansi_string::operator=(double buf) {
    clear();
    printf("%l", buf);
    return *this;
}

ansi_string& ansi_string::operator=(const ansi_string& rhs) {
    clear();
    write(rhs.data(), rhs.size());
    return *this;
}

ansi_string& ansi_string::operator=(ansi_string&& rhs) {
    clear();
    std::swap(_handle, rhs._handle);
    return *this;
}

ansi_string& ansi_string::operator+=(const char* buf) {
    if (buf) {
        printf("%s", buf);
    }
    return *this;
}

#if defined _WIN32 || defined _WIN64
ansi_string& ansi_string::operator+=(const wchar_t* buf) {
    if (buf) {
        W2A(this, buf);
    }
    return *this;
}
#endif

ansi_string& ansi_string::operator+=(char buf) {
    printf("%c", buf);
    return *this;
}

ansi_string& ansi_string::operator+=(byte_t buf) {
    printf("%c", buf);
    return *this;
}

ansi_string& ansi_string::operator+=(uint16 buf) {
    printf("%i", buf);
    return *this;
}

ansi_string& ansi_string::operator+=(uint32 buf) {
    printf("%i", buf);
    return *this;
}

ansi_string& ansi_string::operator+=(uint64 buf) {
    printf("%I64i", buf);
    return *this;
}

ansi_string& ansi_string::operator+=(float buf) {
    printf("%f", buf);
    return *this;
}

ansi_string& ansi_string::operator+=(double buf) {
    printf("%l", buf);
    return *this;
}

ansi_string& ansi_string::operator+=(const ansi_string& buf) {
    write(buf.data(), buf.size());
    return *this;
}

ansi_string& ansi_string::operator<<(const char* buf) {
    if (buf) {
        printf("%s", buf);
    }
    return *this;
}

#if defined _WIN32 || defined _WIN64
ansi_string& ansi_string::operator<<(const wchar_t* buf) {
    if (buf) {
        W2A(this, buf);
    }
    return *this;
}
#endif

ansi_string& ansi_string::operator<<(char buf) {
    printf("%c", buf);
    return *this;
}

ansi_string& ansi_string::operator<<(byte_t buf) {
    printf("%c", buf);
    return *this;
}

ansi_string& ansi_string::operator<<(uint16 buf) {
    printf("%i", buf);
    return *this;
}

ansi_string& ansi_string::operator<<(uint32 buf) {
    printf("%i", buf);
    return *this;
}

ansi_string& ansi_string::operator<<(uint64 buf) {
    printf("%I64i", buf);
    return *this;
}

ansi_string& ansi_string::operator<<(float buf) {
    printf("%f", buf);
    return *this;
}

ansi_string& ansi_string::operator<<(double buf) {
    printf("%l", buf);
    return *this;
}

ansi_string& ansi_string::operator<<(const ansi_string& buf) {
    write(buf.data(), buf.size());
    return *this;
}

#if defined __SIZEOF_INT128__
ansi_string& ansi_string::operator=(uint128 buf) {
    clear();
    printf("%I128i", buf);
    return *this;
}

ansi_string& ansi_string::operator+=(uint128 buf) {
    printf("%I128i", buf);
    return *this;
}

ansi_string& ansi_string::operator<<(uint128 buf) {
    printf("%I128i", buf);
    return *this;
}

#endif

int ansi_string::compare(const ansi_string& rhs) { return strcmp(c_str(), rhs.c_str()); }

int ansi_string::compare(const ansi_string& lhs, const ansi_string& rhs) { return strcmp(lhs.c_str(), rhs.c_str()); }

bool ansi_string::operator<(const ansi_string& rhs) const { return 0 > strcmp(c_str(), rhs.c_str()); }

bool ansi_string::operator>(const ansi_string& rhs) const { return 0 < strcmp(c_str(), rhs.c_str()); }

bool ansi_string::operator==(const ansi_string& rhs) const {
    bool ret = false;

    if (size() == rhs.size()) {
        int cmp = memcmp(data(), rhs.data(), size());
        ret = (0 == cmp);
    }
    return ret;
}

bool ansi_string::operator!=(const ansi_string& rhs) const {
    bool ret = true;

    if (size() == rhs.size()) {
        int cmp = memcmp(data(), rhs.data(), size());
        ret = (0 != cmp);
    }
    return ret;
}

bool ansi_string::operator==(const char* input) {
    bool ret = false;

    if (input) {
        size_t len = strlen(input);
        if (size() == len) {
            int cmp = memcmp(data(), input, len);
            ret = (0 == cmp);
        }
    }
    return ret;
}

bool ansi_string::operator!=(const char* input) {
    bool ret = true;

    if (input) {
        size_t len = strlen(input);
        if (size() == len) {
            int cmp = memcmp(data(), input, len);
            ret = (0 != cmp);
        }
    }
    return ret;
}

std::string& operator+=(std::string& lhs, const ansi_string& rhs) {
    lhs += rhs.c_str();
    return lhs;
}

std::string& operator<<(std::string& lhs, const ansi_string& rhs) {
    lhs += rhs.c_str();
    return lhs;
}

std::ostream& operator<<(std::ostream& lhs, const ansi_string& rhs) {
    lhs << rhs.c_str();
    return lhs;
}

}  // namespace hotplace
