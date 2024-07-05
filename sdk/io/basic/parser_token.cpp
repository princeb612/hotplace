/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
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

#include <sdk/io/basic/parser.hpp>

namespace hotplace {
namespace io {

parser::token::token() : _type(0), _tag(0), _pos(0), _size(0), _line(1), _index(-1) {}

parser::token::token(const parser::token& rhs) : _type(rhs._type), _tag(rhs._tag), _pos(rhs._pos), _size(rhs._size), _line(rhs._line), _index(rhs._index) {}

parser::token& parser::token::init() {
    _type = 0;
    _tag = 0;
    _pos = 0;
    _size = 0;
    _line = 1;
    _index = -1;
    return *this;
}

parser::token& parser::token::increase() {
    _size++;
    return *this;
}

parser::token& parser::token::set_type(uint32 type) {
    _type = type;
    return *this;
}

parser::token& parser::token::set_tag(uint32 tag) {
    _tag = tag;
    return *this;
}

parser::token& parser::token::update_pos(size_t pos) {
    _pos = pos;
    return *this;
}

parser::token& parser::token::update_size(size_t size) {
    _size = size;
    return *this;
}

parser::token& parser::token::newline() {
    _line++;
    return *this;
}

parser::token& parser::token::set_index(uint32 idx) {
    _index = idx;
    return *this;
}

uint32 parser::token::get_index() const { return _index; }

uint32 parser::token::get_type() const { return _type; }

uint32 parser::token::get_tag() const { return _tag; }

size_t parser::token::get_pos() const { return _pos; }

size_t parser::token::get_size() const { return _size; }

size_t parser::token::get_line() const { return _line; }

bool parser::token::empty() { return 0 == _size; }

size_t parser::token::size() { return _size; }

std::string parser::token::as_string(const char* p) {
    std::string obj;
    if (p) {
        obj.insert(obj.end(), p + _pos, p + _pos + _size);
    }
    return obj;
}

void parser::token::visit(const char* p, std::function<void(const parser::token* t)> f) {
    if (p && f) {
        f(this);
    }
}

parser::token* parser::token::clone() { return new parser::token(*this); }

}  // namespace io
}  // namespace hotplace
