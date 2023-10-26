/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <string.h>

#include <sdk/base/basic/obfuscate_string.hpp>
#include <set>

namespace hotplace {

enum obfuscate_flag_t {
    obfuscate_set_factor = (1 << 0),
};

obfuscate_string::obfuscate_string() : _flags(0) {
    // do nothing
}

obfuscate_string::obfuscate_string(const char* source) : _flags(0) {
    size_t len = 0;

    if (source) {
        len = strlen(source);
    }
    assign(source, len);
}

obfuscate_string::obfuscate_string(std::string& source) : _flags(0) { assign(source.c_str(), source.size()); }

obfuscate_string::obfuscate_string(basic_stream& source) : _flags(0) { assign(source.c_str(), source.size()); }

obfuscate_string::~obfuscate_string() { cleanup(); }

obfuscate_string& obfuscate_string::assign(const char* source, size_t size) {
    startup();
    if (source && size) {
        _contents.resize(size);

        byte_t* psrc = (byte_t*)source;
        byte_t* pdest = &_contents[0];
        while (size--) {
            *pdest++ = (*psrc++) + _factor;
        }
    }
    return *this;
}

obfuscate_string& obfuscate_string::append(const char* source, size_t size) {
    startup();
    if (source && size) {
        size_t size_older = _contents.size();
        _contents.resize(size_older + size);

        byte_t* psrc = (byte_t*)source;
        byte_t* pdest = &_contents[size_older];
        while (size--) {
            *pdest++ = (*psrc++) + _factor;
        }
    }
    return *this;
}

size_t obfuscate_string::size() { return _contents.size(); }

bool obfuscate_string::empty() { return (0 == _contents.size()) ? true : false; }

bool obfuscate_string::compare(obfuscate_string& o) {
    bool ret = false;

    if (size() == o.size()) {
        binary_t::iterator lit, rit;
        typedef std::set<byte_t> differ_set_t;
        std::pair<differ_set_t::iterator, bool> differ_set_pib_t;
        differ_set_t differ_set;
        for (lit = _contents.begin(), rit = o._contents.begin(); (lit != _contents.end()) && (rit != o._contents.end()); lit++, rit++) {
            byte_t diff = *lit - *rit;

            differ_set.insert(diff);
            if (differ_set.size() > 1) {
                break;
            }
        }
        byte_t diff_fact = (byte_t)(_factor - o._factor);
        if ((1 == differ_set.size()) && (*differ_set.begin() == (diff_fact))) {
            ret = true;
        }
    }

    return ret;
}

obfuscate_string& obfuscate_string::operator=(const char* source) {
    size_t len = 0;

    if (source) {
        len = strlen(source);
    }
    assign(source, len);
    return *this;
}

obfuscate_string& obfuscate_string::operator=(std::string& source) {
    assign(source.c_str(), source.size());
    return *this;
}

obfuscate_string& obfuscate_string::operator=(basic_stream& source) {
    assign(source.c_str(), source.size());
    return *this;
}

obfuscate_string& obfuscate_string::operator+=(const char* source) {
    size_t len = 0;

    if (source) {
        len = strlen(source);
    }
    append(source, len);
    return *this;
}

obfuscate_string& obfuscate_string::operator+=(std::string& source) {
    append(source.c_str(), source.size());
    return *this;
}

obfuscate_string& obfuscate_string::operator+=(basic_stream& source) {
    append(source.c_str(), source.size());
    return *this;
}

obfuscate_string& obfuscate_string::operator<<(const char* source) {
    size_t len = 0;

    if (source) {
        len = strlen(source);
    }
    append(source, len);
    return *this;
}

obfuscate_string& obfuscate_string::operator<<(std::string& source) {
    append(source.c_str(), source.size());
    return *this;
}

obfuscate_string& obfuscate_string::operator<<(basic_stream& source) {
    append(source.c_str(), source.size());
    return *this;
}

bool obfuscate_string::operator==(obfuscate_string& o) { return true == compare(o); }

bool obfuscate_string::operator!=(obfuscate_string& o) { return false == compare(o); }

std::string& operator<<(std::string& lhs, obfuscate_string const& rhs) {
    binary_t::const_iterator it;

    for (it = rhs._contents.begin(); it != rhs._contents.end(); it++) {
        lhs += (*it - rhs._factor);
    }
    return lhs;
}

basic_stream& operator<<(basic_stream& lhs, obfuscate_string const& rhs) {
    binary_t::const_iterator it;

    for (it = rhs._contents.begin(); it != rhs._contents.end(); it++) {
        lhs << (byte_t)(*it - rhs._factor);
    }
    return lhs;
}

binary_t& operator<<(binary_t& lhs, obfuscate_string const& rhs) {
    binary_t::const_iterator it;

    for (it = rhs._contents.begin(); it != rhs._contents.end(); it++) {
        lhs.insert(lhs.end(), *it - rhs._factor);
    }
    return lhs;
}

void obfuscate_string::startup() {
    if (0 == (obfuscate_flag_t::obfuscate_set_factor & _flags)) {
        _factor = 0x30 + (rand() % 0x50);
        _flags |= obfuscate_flag_t::obfuscate_set_factor;
    }
}

void obfuscate_string::cleanup() { memset(&_contents[0], 0, _contents.size()); }

}  // namespace hotplace
