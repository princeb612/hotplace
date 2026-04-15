/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/base/basic/valist.hpp>
#include <hotplace/sdk/base/stream/printf.hpp>
#include <hotplace/sdk/base/stream/stream_policy.hpp>
#include <hotplace/sdk/base/stream/tstring.hpp>
#include <hotplace/sdk/base/string/string.hpp>

namespace hotplace {

ansi_string::ansi_string() : stream_t(), _handle(nullptr) {
    size_t allocsize = stream_policy::get_instance()->get_allocsize();
    auto test = bufferio::open(&_handle, allocsize, sizeof(char), bufferio_context_flag_t::memzero_free);
    if (errorcode_t::success != test) {
        throw std::runtime_error("ansi_string.ctor");
    }
}

ansi_string::ansi_string(const char* data, ...) : ansi_string() {
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

ansi_string::ansi_string(const ansi_string& other) : stream_t(), _handle(nullptr) {
    bufferio_context_t* newone = nullptr;
    auto test = bufferio::clone(other._handle, &newone);
    if (errorcode_t::success != test) {
        throw std::runtime_error("ansi_string.ctor.copy");
    }
    _handle = newone;
}

ansi_string::ansi_string(ansi_string&& other) : stream_t(), _handle(other._handle) { other._handle = nullptr; }

ansi_string::~ansi_string() {
    if (_handle) {
        bufferio::close(_handle);
    }
}

byte_t* ansi_string::data() const {
    byte_t* data = nullptr;
    size_t size = 0;

    bufferio::get(_handle, &data, &size);
    return data;
}

uint64 ansi_string::size() const {
    byte_t* data = nullptr;
    size_t size = 0;

    bufferio::get(_handle, &data, &size);
    return size;
}

return_t ansi_string::write(const void* data, size_t size) { return bufferio::write(_handle, data, size); }

return_t ansi_string::fill(size_t l, char c) {
    return_t ret = errorcode_t::success;

    while (l--) {
        bufferio::printf(_handle, "%c", c);
    }
    return ret;
}

return_t ansi_string::clear() { return bufferio::clear(_handle); }

bool ansi_string::empty() { return bufferio::empty(_handle); }

bool ansi_string::occupied() { return bufferio::occupied(_handle); }

return_t ansi_string::printf(const char* buf, ...) {
    return_t ret = errorcode_t::success;
    va_list ap;

    va_start(ap, buf);
    ret = bufferio::vprintf(_handle, buf, ap);
    va_end(ap);
    return ret;
}

return_t ansi_string::vprintf(const char* buf, va_list ap) {
    return_t ret = errorcode_t::success;

    ret = bufferio::vprintf(_handle, buf, ap);
    return ret;
}

#if defined _WIN32 || defined _WIN64
return_t ansi_string::printf(const wchar_t* buf, ...) {
    return_t ret = errorcode_t::success;
    va_list ap;
    wide_string ws;
    va_start(ap, buf);
    ws.vprintf(buf, ap);
    va_end(ap);
    ret = W2A(this, (wchar_t*)ws.data());
    return ret;
}

return_t ansi_string::vprintf(const wchar_t* buf, va_list ap) {
    return_t ret = errorcode_t::success;
    wide_string ws;
    ws.vprintf(buf, ap);
    ret = W2A(this, (wchar_t*)ws.data());
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

    bufferio::get(_handle, (byte_t**)&data, &size);
    return data ? const_cast<const char*>(data) : "";
}

size_t ansi_string::find(char* data) { return bufferio::find_first_of(_handle, data); }

return_t ansi_string::replace(const char* from, const char* to, size_t begin, int flag) { return bufferio::replace(_handle, from, to, begin, flag); }

ansi_string ansi_string::substr(size_t begin, size_t len) {
    ansi_string stream;

    bufferio::lock(_handle);
    stream.printf("%.*s", len, c_str() + begin);
    bufferio::unlock(_handle);
    return stream;
}

return_t ansi_string::cut(size_t begin, size_t len) { return bufferio::cut(_handle, begin, len); }

return_t ansi_string::trim() {
    return_t ret = errorcode_t::success;

    ltrim();
    rtrim();
    return ret;
}

return_t ansi_string::ltrim() {
    return_t ret = errorcode_t::success;
    size_t begin = bufferio::find_not_first_of(_handle, isspace, 0);

    if ((size_t)-1 != begin) {
        bufferio::cut(_handle, 0, begin);
    }
    return ret;
}

return_t ansi_string::rtrim() {
    return_t ret = errorcode_t::success;
    size_t len = 0;
    size_t end = bufferio::find_not_last_of(_handle, isspace);

    bufferio::size(_handle, &len);
    if ((size_t)-1 != end) {
        bufferio::cut(_handle, end, len - end);  // base
    }
    return ret;
}

size_t ansi_string::find_first_of(const char* find, size_t offset) { return bufferio::find_first_of(_handle, find, offset); }

size_t ansi_string::find_not_first_of(const char* find, size_t offset) { return bufferio::find_not_first_of(_handle, find, offset); }

size_t ansi_string::find_last_of(const char* find) { return bufferio::find_last_of(_handle, find); }

size_t ansi_string::find_not_last_of(const char* find) { return bufferio::find_not_last_of(_handle, find); }

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

        bufferio::lock(_handle);
        ret = scan(p, size(), pos, brk, isnewline);
        if (errorcode_t::success == ret) {
            line.write((void*)(p + pos), *brk - pos);
            line.trim();
        }
        bufferio::unlock(_handle);
    }
    __finally2 {}

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

ansi_string& ansi_string::operator=(const ansi_string& other) {
    if (this != &other) {
        ansi_string tmp(other);  // strong exeption guarantee
        std::swap(_handle, tmp._handle);
    }
    return *this;
}

ansi_string& ansi_string::operator=(ansi_string&& other) {
    if (this != &other) {
        std::swap(_handle, other._handle);
    }
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

int ansi_string::compare(const ansi_string& other) { return strcmp(c_str(), other.c_str()); }

int ansi_string::compare(const ansi_string& lhs, const ansi_string& rhs) { return strcmp(lhs.c_str(), rhs.c_str()); }

bool ansi_string::operator<(const ansi_string& other) const { return strcmp(c_str(), other.c_str()) < 0; }

bool ansi_string::operator>(const ansi_string& other) const { return strcmp(c_str(), other.c_str()) > 0; }

bool ansi_string::operator==(const ansi_string& other) const { return strcmp(c_str(), other.c_str()) == 0; }

bool ansi_string::operator!=(const ansi_string& other) const { return strcmp(c_str(), other.c_str()) != 0; }

bool ansi_string::operator==(const char* other) { return strcmp(c_str(), other) == 0; }

bool ansi_string::operator!=(const char* other) { return strcmp(c_str(), other) != 0; }

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

void ansi_string::autoindent(uint8 indent) {
    bufferio::autoindent(_handle, indent);
    if (indent) {
        fill(indent, ' ');
    } else {
        *this << '\r';
    }
}

}  // namespace hotplace
