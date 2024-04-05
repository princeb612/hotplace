/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <sdk/base/stream/basic_stream.hpp>
#include <sdk/io/stream/string.hpp>
#include <sdk/io/string/string.hpp>

namespace hotplace {
namespace io {

wide_string::wide_string(size_t allocsize, uint32 flags) { _bio.open(&_handle, allocsize, sizeof(wchar_t), flags | bufferio_context_flag_t::memzero_free); }

wide_string::wide_string(const wchar_t* data) {
    _bio.open(&_handle, 1 << 10, sizeof(wchar_t), bufferio_context_flag_t::memzero_free);
    _bio.write(_handle, data, wcslen(data) * sizeof(wchar_t));
}

wide_string::wide_string(const wide_string& stream) {
    _bio.open(&_handle, 1 << 10, sizeof(wchar_t), bufferio_context_flag_t::memzero_free);
    byte_t* data = nullptr;
    size_t size = 0;

    _bio.get(stream._handle, &data, &size);
    write((void*)data, size);
}

wide_string::~wide_string() { _bio.close(_handle); }

byte_t* wide_string::data() const {
    byte_t* data = nullptr;
    size_t size = 0;

    _bio.get(_handle, &data, &size);
    return data;
}

uint64 wide_string::size() const {
    byte_t* data = nullptr;
    size_t size = 0;

    _bio.get(_handle, &data, &size);
    return size;
}

return_t wide_string::write(const void* data, size_t size) { return _bio.write(_handle, data, size); }

return_t wide_string::fill(size_t l, char c) {
    return_t ret = errorcode_t::success;

    while (l--) {
        _bio.printf(_handle, L"%c", c);
    }
    return ret;
}

return_t wide_string::clear() { return _bio.clear(_handle); }

return_t wide_string::printf(const char* buf, ...) {
    return_t ret = errorcode_t::success;
    va_list ap;
    basic_stream bs;

    va_start(ap, buf);
    bs.vprintf(buf, ap);
    va_end(ap);
    ret = A2W(this, (char*)bs.data());
    return ret;
}

return_t wide_string::vprintf(const char* buf, va_list ap) {
    return_t ret = errorcode_t::success;
    basic_stream bs;

    bs.vprintf(buf, ap);
    ret = A2W(this, (char*)bs.data());
    return ret;
}

#if defined _WIN32 || defined _WIN64
return_t wide_string::printf(const wchar_t* buf, ...) {
    return_t ret = errorcode_t::success;
    va_list ap;

    va_start(ap, buf);
    ret = _bio.vprintf(_handle, buf, ap);
    va_end(ap);
    return ret;
}

return_t wide_string::vprintf(const wchar_t* buf, va_list ap) {
    return_t ret = errorcode_t::success;

    ret = _bio.vprintf(_handle, buf, ap);
    return ret;
}
#endif

const wchar_t* wide_string::c_str() const {
    wchar_t* data = nullptr;
    size_t size = 0;

    _bio.get(_handle, (byte_t**)&data, &size);
    return data ? const_cast<const wchar_t*>(data) : L"";
}

size_t wide_string::find(wchar_t* data) { return _bio.wfind_first_of(_handle, data); }

return_t wide_string::replace(const wchar_t* from, const wchar_t* to, size_t begin, int flag) { return _bio.wreplace(_handle, from, to, begin, flag); }

wide_string wide_string::substr(size_t begin, size_t len) {
    wide_string stream;

    _bio.lock(_handle);
    stream.printf(L"%.*s", len, c_str() + begin);
    _bio.unlock(_handle);
    return stream;
}

return_t wide_string::cut(size_t begin, size_t len) { return _bio.cut(_handle, begin * sizeof(wchar_t), len * sizeof(wchar_t)); }

return_t wide_string::trim() {
    return_t ret = errorcode_t::success;

    ltrim();
    rtrim();
    return ret;
}

return_t wide_string::ltrim() {
    return_t ret = errorcode_t::success;
    size_t begin = _bio.wfind_not_first_of(_handle, iswspace, 0);

    if ((size_t)-1 != begin) {
        _bio.cut(_handle, 0, begin * sizeof(wchar_t));
    }
    return ret;
}

return_t wide_string::rtrim() {
    return_t ret = errorcode_t::success;
    size_t len = 0;
    size_t end = _bio.wfind_not_last_of(_handle, iswspace);

    _bio.size(_handle, &len);
    if ((size_t)-1 != end) {
        _bio.cut(_handle, (end) * sizeof(wchar_t), len - (end * sizeof(wchar_t)));
    }
    return ret;
}

size_t wide_string::find_first_of(const wchar_t* find, size_t offset) { return _bio.wfind_first_of(_handle, find, offset); }

size_t wide_string::find_not_first_of(const wchar_t* find, size_t offset) { return _bio.wfind_not_first_of(_handle, find, offset); }

size_t wide_string::find_last_of(const wchar_t* find) { return _bio.wfind_last_of(_handle, find); }

size_t wide_string::find_not_last_of(const wchar_t* find) { return _bio.wfind_not_last_of(_handle, find); }

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

        _bio.lock(_handle);
        ret = scan(p, datasize, pos, brk, &isnewline);
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

wide_string& wide_string::operator=(const char* buf) {
    clear();
    if (nullptr != buf) {
        A2W(this, buf);
    }
    return *this;
}

wide_string& wide_string::operator=(const wchar_t* buf) {
    clear();
    if (buf) {
        printf(L"%s", buf);
    }
    return *this;
}

wide_string& wide_string::operator=(wchar_t buf) {
    clear();
    printf(L"%c", buf);
    return *this;
}

wide_string& wide_string::operator=(byte_t buf) {
    clear();
    printf(L"%c", buf);
    return *this;
}

wide_string& wide_string::operator=(uint16 buf) {
    clear();
    printf(L"%i", buf);
    return *this;
}

wide_string& wide_string::operator=(uint32 buf) {
    clear();
    printf(L"%i", buf);
    return *this;
}

wide_string& wide_string::operator=(uint64 buf) {
    clear();
    printf(L"%I64i", buf);
    return *this;
}

#if defined __SIZEOF_INT128__
wide_string& wide_string::operator=(uint128 buf) {
    clear();
    printf(L"%I128i", buf);
    return *this;
}
#endif

wide_string& wide_string::operator=(float buf) {
    clear();
    printf(L"%f", buf);
    return *this;
}

wide_string& wide_string::operator=(double buf) {
    clear();
    printf(L"%l", buf);
    return *this;
}

wide_string& wide_string::operator=(wide_string& buf) {
    clear();
    write(buf.data(), buf.size());
    return *this;
}

wide_string& wide_string::operator+=(const char* buf) {
    if (buf) {
        A2W(this, buf);
    }
    return *this;
}

wide_string& wide_string::operator+=(const wchar_t* buf) {
    if (buf) {
        printf(L"%s", buf);
    }
    return *this;
}

wide_string& wide_string::operator+=(wchar_t buf) {
    printf(L"%c", buf);
    return *this;
}

wide_string& wide_string::operator+=(byte_t buf) {
    printf(L"%c", buf);
    return *this;
}

wide_string& wide_string::operator+=(uint16 buf) {
    printf(L"%i", buf);
    return *this;
}

wide_string& wide_string::operator+=(uint32 buf) {
    printf(L"%i", buf);
    return *this;
}

wide_string& wide_string::operator+=(uint64 buf) {
    printf(L"%I64i", buf);
    return *this;
}

#if defined __SIZEOF_INT128__
wide_string& wide_string::operator+=(uint128 buf) {
    printf(L"%I128i", buf);
    return *this;
}
#endif

wide_string& wide_string::operator+=(float buf) {
    printf(L"%f", buf);
    return *this;
}

wide_string& wide_string::operator+=(double buf) {
    printf(L"%l", buf);
    return *this;
}

wide_string& wide_string::operator+=(wide_string& buf) {
    write(buf.data(), buf.size());
    return *this;
}

wide_string& wide_string::operator<<(const char* buf) {
    if (nullptr != buf) {
        A2W(this, buf);
    }
    return *this;
}

wide_string& wide_string::operator<<(const wchar_t* buf) {
    if (buf) {
        printf(L"%s", buf);
    }
    return *this;
}

wide_string& wide_string::operator<<(wchar_t buf) {
    printf(L"%c", buf);
    return *this;
}

wide_string& wide_string::operator<<(byte_t buf) {
    printf(L"%c", buf);
    return *this;
}

wide_string& wide_string::operator<<(uint16 buf) {
    printf(L"%i", buf);
    return *this;
}

wide_string& wide_string::operator<<(uint32 buf) {
    printf(L"%i", buf);
    return *this;
}

wide_string& wide_string::operator<<(uint64 buf) {
    printf(L"%I64i", buf);
    return *this;
}

#if defined __SIZEOF_INT128__
wide_string& wide_string::operator<<(uint128 buf) {
    printf(L"%I128i", buf);
    return *this;
}
#endif

wide_string& wide_string::operator<<(float buf) {
    printf(L"%f", buf);
    return *this;
}

wide_string& wide_string::operator<<(double buf) {
    printf(L"%l", buf);
    return *this;
}

wide_string& wide_string::operator<<(wide_string& buf) {
    write(buf.data(), buf.size());
    return *this;
}

int wide_string::compare(wide_string& buf) { return wcscmp(c_str(), buf.c_str()); }

int wide_string::compare(wide_string& lhs, wide_string& rhs) { return wcscmp(lhs.c_str(), rhs.c_str()); }

bool wide_string::operator<(const wide_string& buf) const { return 0 < wcscmp(c_str(), buf.c_str()); }

bool wide_string::operator>(const wide_string& buf) const { return 0 > wcscmp(c_str(), buf.c_str()); }

bool wide_string::operator==(const wide_string& buf) const {
    bool ret = false;

    if (size() == buf.size()) {
        int cmp = memcmp(data(), buf.data(), size());
        ret = (0 == cmp);
    }
    return ret;
}

bool wide_string::operator!=(const wide_string& buf) const {
    bool ret = true;

    if (size() == buf.size()) {
        int cmp = memcmp(data(), buf.data(), size());
        ret = (0 != cmp);
    }
    return ret;
}

bool wide_string::operator==(const wchar_t* input) {
    bool ret = false;

    if (input) {
        size_t len = wcslen(input);
        if (size() == len) {
            int cmp = memcmp(data(), input, len * sizeof(wchar_t));
            ret = (0 == cmp);
        }
    }
    return ret;
}

bool wide_string::operator!=(const wchar_t* input) {
    bool ret = true;

    if (input) {
        size_t len = wcslen(input);
        if (size() == len) {
            int cmp = memcmp(data(), input, len * sizeof(wchar_t));
            ret = (0 != cmp);
        }
    }
    return ret;
}

}  // namespace io
}  // namespace hotplace
