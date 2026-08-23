/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   parser_token.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * comments
 *  concept rule-based parser
 *
 */

#include <hotplace/sdk/io/basic/parser.hpp>

namespace hotplace {
namespace io {

parser_token::parser_token() : _tokenid(0), /*_tag(0),*/ _pos(0), _size(0), _line(1), _index(-1) {}

parser_token::parser_token(const parser_token& other)
    : _tokenid(other._tokenid), /*_tag(other._tag),*/ _pos(other._pos), _size(other._size), _line(other._line), _index(other._index) {}

parser_token& parser_token::init() {
    _tokenid = 0;
    // _tag = 0;
    _pos = 0;
    _size = 0;
    _line = 1;
    _index = -1;
    return *this;
}

parser_token& parser_token::increase() {
    _size++;
    return *this;
}

parser_token& parser_token::set_type(uint32 type) {
    _tokenid = type;
    return *this;
}

// parser_token& parser_token::set_tag(uint32 tag) {
//     _tag = tag;
//     return *this;
// }

parser_token& parser_token::update_pos(size_t pos) {
    _pos = pos;
    return *this;
}

parser_token& parser_token::update_size(size_t size) {
    _size = size;
    return *this;
}

parser_token& parser_token::newline() {
    _line++;
    return *this;
}

parser_token& parser_token::set_index(uint32 idx) {
    _index = idx;
    return *this;
}

uint32 parser_token::get_index() const { return _index; }

uint32 parser_token::get_tokenid() const { return _tokenid; }

// uint32 parser_token::get_tag() const { return _tag; }

size_t parser_token::get_pos() const { return _pos; }

size_t parser_token::get_size() const { return _size; }

size_t parser_token::get_line() const { return _line; }

bool parser_token::empty() const { return 0 == _size; }

size_t parser_token::size() const { return _size; }

std::string parser_token::as_string(const char* p) const {
    std::string obj;
    if (p) {
        obj.insert(obj.end(), p + _pos, p + _pos + _size);
    }
    return obj;
}

void parser_token::visit(const char* p, std::function<void(const parser_token* t)> f) const {
    if (p && f) {
        f(this);
    }
}

parser_token* parser_token::clone() { return new parser_token(*this); }

}  // namespace io
}  // namespace hotplace
