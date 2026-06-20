/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   wide_string.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2026.05.22   Soo Han and Gemini  Refined with guidance and collaboration from Gemini
 *
 */

#include <hotplace/sdk/base/stream/ansi_string.hpp>
#include <hotplace/sdk/base/stream/stream_policy.hpp>
#include <hotplace/sdk/base/stream/unicode/wide_string.hpp>
#include <hotplace/sdk/base/string/string.hpp>

namespace hotplace {

wide_string::wide_string() : stream_t(), _handle(nullptr) {
    size_t allocsize = stream_policy::get_instance()->get_allocsize();
    auto test = bufferio::open(&_handle, allocsize, sizeof(wchar_t), bufferio_context_flag_t::memzero_free);
    if (errorcode_t::success != test) {
        throw std::runtime_error("wide_string.ctor");
    }
}

wide_string::wide_string(const wchar_t* data, ...) : wide_string() {
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

wide_string::wide_string(const wide_string& other) : stream_t(), _handle(nullptr) {
    bufferio_context_t* newone = nullptr;
    auto test = bufferio::clone(other._handle, &newone);
    if (errorcode_t::success != test) {
        throw std::runtime_error("basic_stream.ctor.copy");
    }
    _handle = newone;
}

wide_string::wide_string(wide_string&& other) : stream_t(), _handle(other._handle) { other._handle = nullptr; }

wide_string& wide_string::operator=(const wide_string& other) {
    if (this != &other) {
        wide_string tmp(other);  // strong exception guarantee
        std::swap(_handle, tmp._handle);
    }
    return *this;
}

wide_string& wide_string::operator=(wide_string&& other) {
    if (this != &other) {
        std::swap(_handle, other._handle);
    }
    return *this;
}

wide_string::~wide_string() {
    if (_handle) {
        bufferio::close(_handle);
    }
}

byte_t* wide_string::data() const {
    byte_t* data = nullptr;
    size_t size = 0;

    bufferio::get(_handle, &data, &size);
    return data;
}

uint64 wide_string::size() const {
    byte_t* data = nullptr;
    size_t size = 0;

    bufferio::get(_handle, &data, &size);
    return size;
}

return_t wide_string::write(const void* data, size_t size) { return bufferio::write(_handle, data, size); }

return_t wide_string::fill(size_t l, char c) {
    return_t ret = errorcode_t::success;

    while (l--) {
        bufferio::printf(_handle, L"%c", c);
    }
    return ret;
}

return_t wide_string::clear() { return bufferio::clear(_handle); }

bool wide_string::empty() { return bufferio::empty(_handle); }

bool wide_string::occupied() { return bufferio::occupied(_handle); }

return_t wide_string::printf(const char* buf, ...) {
    return_t ret = errorcode_t::success;
    va_list ap;
    ansi_string as;
    va_start(ap, buf);
    as.vprintf(buf, ap);
    va_end(ap);
    ret = A2W(this, (char*)as.data());
    return ret;
}

return_t wide_string::vprintf(const char* buf, va_list ap) {
    return_t ret = errorcode_t::success;
    ansi_string as;
    as.vprintf(buf, ap);
    ret = A2W(this, (char*)as.data());
    return ret;
}

#if defined _WIN32 || defined _WIN64
return_t wide_string::printf(const wchar_t* buf, ...) {
    return_t ret = errorcode_t::success;
    va_list ap;
    va_start(ap, buf);
    ret = bufferio::vprintf(_handle, buf, ap);
    va_end(ap);
    return ret;
}

return_t wide_string::vprintf(const wchar_t* buf, va_list ap) {
    return_t ret = errorcode_t::success;
    ret = bufferio::vprintf(_handle, buf, ap);
    return ret;
}
#endif

const wchar_t* wide_string::c_str() const {
    wchar_t* data = nullptr;
    size_t size = 0;

    bufferio::get(_handle, (byte_t**)&data, &size);
    return data ? const_cast<const wchar_t*>(data) : L"";
}

size_t wide_string::find(wchar_t* data) { return bufferio::wfind_first_of(_handle, data); }

return_t wide_string::replace(const wchar_t* from, const wchar_t* to, size_t begin, int flag) { return bufferio::wreplace(_handle, from, to, begin, flag); }

wide_string wide_string::substr(size_t begin, size_t len) {
    wide_string stream;

    bufferio::lock(_handle);
    stream.printf(L"%.*s", len, c_str() + begin);
    bufferio::unlock(_handle);
    return stream;
}

return_t wide_string::cut(size_t begin, size_t len) { return bufferio::cut(_handle, begin * sizeof(wchar_t), len * sizeof(wchar_t)); }

return_t wide_string::trim() {
    return_t ret = errorcode_t::success;

    ltrim();
    rtrim();
    return ret;
}

return_t wide_string::ltrim() {
    return_t ret = errorcode_t::success;
    size_t begin = bufferio::wfind_not_first_of(_handle, iswspace, 0);

    if ((size_t)-1 != begin) {
        bufferio::cut(_handle, 0, begin * sizeof(wchar_t));
    }
    return ret;
}

return_t wide_string::rtrim() {
    return_t ret = errorcode_t::success;
    size_t len = 0;
    size_t end = bufferio::wfind_not_last_of(_handle, iswspace);

    bufferio::size(_handle, &len);
    if ((size_t)-1 != end) {
        bufferio::cut(_handle, (end) * sizeof(wchar_t), len - (end * sizeof(wchar_t)));
    }
    return ret;
}

size_t wide_string::find_first_of(const wchar_t* find, size_t offset) { return bufferio::wfind_first_of(_handle, find, offset); }

size_t wide_string::find_not_first_of(const wchar_t* find, size_t offset) { return bufferio::wfind_not_first_of(_handle, find, offset); }

size_t wide_string::find_last_of(const wchar_t* find) { return bufferio::wfind_last_of(_handle, find); }

size_t wide_string::find_not_last_of(const wchar_t* find) { return bufferio::wfind_not_last_of(_handle, find); }

// getline subfunction
static int isnewline(int c) {
    int ret_value = 0;

    // match \f, \v, \r, \n
    // except space, \t
    if (0x20 != c && 0x9 != c) {  // L" ", L"\t"
        ret_value = iswspace(c);
    }
    return ret_value;
}

return_t wide_string::getline(size_t pos, size_t* brk, wide_string& line) {
    return_t ret = errorcode_t::success;

    line.clear();

    __try2 {
        if (nullptr == brk) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        const wchar_t* p = (const wchar_t*)data();
        size_t datasize = size();

        bufferio::lock(_handle);
        ret = scan(p, datasize, pos, brk, &isnewline);
        if (errorcode_t::success == ret) {
            line.write((void*)(p + pos), *brk - pos);
            line.trim();
        }
        bufferio::unlock(_handle);
    }
    __finally2 {}

    return ret;
}

int wide_string::compare(const wide_string& other) { return wcscmp(c_str(), other.c_str()); }

int wide_string::compare(const wide_string& lhs, const wide_string& rhs) { return wcscmp(lhs.c_str(), rhs.c_str()); }

void wide_string::autoindent(uint8 indent) {
    bufferio::autoindent(_handle, indent);
    if (indent) {
        fill(indent, L' ');
    } else {
        write(L"\r", sizeof(wchar_t));
    }
}

void wide_string::resize(size_t bytes) {
    auto z = size();
    auto s = bytes * sizeof(TCHAR);
    if (0 == s) {
        clear();
    } else if (z > s) {
        // cut
        cut(s, (z - s));
    } else {
        // extend
        fill(s - z, L'\0');
    }
}

wide_string& wide_string::operator<<(const char value) {
    printf("%c", value);
    return *this;
}

wide_string& wide_string::operator<<(const char* value) {
    if (nullptr != value) {
        A2W(this, value);
    }
    return *this;
}

wide_string& wide_string::operator<<(const wchar_t value) {
    write(&value, sizeof(wchar_t));
    return *this;
}

wide_string& wide_string::operator<<(const wchar_t* value) {
    if (value) {
        auto len = wcslen(value);
        write(value, len * sizeof(wchar_t));
    }
    return *this;
}

wide_string& wide_string::operator<<(const wide_string& value) {
    write(value.data(), value.size());
    return *this;
}

bool wide_string::operator<(const wide_string& other) const { return wcscmp(c_str(), other.c_str()) < 0; }

bool wide_string::operator>(const wide_string& other) const { return wcscmp(c_str(), other.c_str()) > 0; }

bool wide_string::operator==(const wide_string& other) const { return wcscmp(c_str(), other.c_str()) == 0; }

bool wide_string::operator!=(const wide_string& other) const { return wcscmp(c_str(), other.c_str()) != 0; }

bool wide_string::operator==(const wchar_t* other) { return wcscmp(c_str(), other) == 0; }

bool wide_string::operator!=(const wchar_t* other) { return wcscmp(c_str(), other) != 0; }

std::wstring& operator+=(std::wstring& lhs, const wide_string& rhs) {
    lhs += rhs.c_str();
    return lhs;
}

std::wstring& operator<<(std::wstring& lhs, const wide_string& rhs) {
    lhs += rhs.c_str();
    return lhs;
}

std::ostream& operator<<(std::ostream& lhs, const wide_string& rhs) {
    ansi_string as;
    W2A(&as, rhs.c_str());
    lhs << as.c_str();
    return lhs;
}

}  // namespace hotplace
