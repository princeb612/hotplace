/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   lexical_token.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <hotplace/sdk/io/parser/lexical_analyzer.hpp>

namespace hotplace {
namespace io {

lexical_token::lexical_token() : _tokenid(0), /*_tag(0),*/ _pos(0), _size(0), _line(1), _index(-1) {}

lexical_token::lexical_token(const lexical_token& other)
    : _tokenid(other._tokenid), /*_tag(other._tag),*/ _pos(other._pos), _size(other._size), _line(other._line), _index(other._index) {}

lexical_token& lexical_token::init() {
    _tokenid = 0;
    // _tag = 0;
    _pos = 0;
    _size = 0;
    _line = 1;
    _index = -1;
    return *this;
}

lexical_token& lexical_token::increase() {
    _size++;
    return *this;
}

lexical_token& lexical_token::set_type(uint32 type) {
    _tokenid = type;
    return *this;
}

// lexical_token& lexical_token::set_tag(uint32 tag) {
//     _tag = tag;
//     return *this;
// }

lexical_token& lexical_token::update_pos(size_t pos) {
    _pos = pos;
    return *this;
}

lexical_token& lexical_token::update_size(size_t size) {
    _size = size;
    return *this;
}

lexical_token& lexical_token::newline() {
    _line++;
    return *this;
}

lexical_token& lexical_token::set_index(uint32 idx) {
    _index = idx;
    return *this;
}

uint32 lexical_token::get_index() const { return _index; }

uint32 lexical_token::get_tokenid() const { return _tokenid; }

// uint32 lexical_token::get_tag() const { return _tag; }

size_t lexical_token::get_pos() const { return _pos; }

size_t lexical_token::get_size() const { return _size; }

size_t lexical_token::get_line() const { return _line; }

bool lexical_token::empty() const { return 0 == _size; }

size_t lexical_token::size() const { return _size; }

std::string lexical_token::as_string(const char* p) const {
    std::string obj;
    if (p) {
        obj.insert(obj.end(), p + _pos, p + _pos + _size);
    }
    return obj;
}

bool lexical_token::visit(const char* p, std::function<bool(const lexical_token* t)> f) const {
    bool ret = false;
    if (p && f) {
        ret = f(this);
    }
    return ret;
}

lexical_token* lexical_token::clone() const { return new lexical_token(*this); }

}  // namespace io
}  // namespace hotplace
