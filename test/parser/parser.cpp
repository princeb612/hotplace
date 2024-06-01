/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * lexical ... done
 * syntax  ... in progress
 *
 */

#include "parser.hpp"

namespace hotplace {
namespace io {

#define TOKEN_ENTRY(c, s, d) \
    { c, s, d }

struct ascii_token_table {
    uint8 code;
    const char* symbol;
    token_t type;
} _ascii_token_table[256]{
    TOKEN_ENTRY(0x00, "NUL", token_unknown), TOKEN_ENTRY(0x01, "SOH", token_unknown),  TOKEN_ENTRY(0x02, "STX", token_unknown),
    TOKEN_ENTRY(0x03, "ETX", token_unknown), TOKEN_ENTRY(0x04, "EOT", token_unknown),  TOKEN_ENTRY(0x05, "ENQ", token_unknown),
    TOKEN_ENTRY(0x06, "ACK", token_unknown), TOKEN_ENTRY(0x07, "BEL", token_unknown),  TOKEN_ENTRY(0x08, "BS", token_unknown),
    TOKEN_ENTRY(0x09, "HT", token_unknown),  TOKEN_ENTRY(0x0A, "LF", token_newline),   TOKEN_ENTRY(0x0B, "VT", token_unknown),
    TOKEN_ENTRY(0x0C, "FF", token_unknown),  TOKEN_ENTRY(0x0D, "CR", token_unknown),   TOKEN_ENTRY(0x0E, "SO", token_unknown),
    TOKEN_ENTRY(0x0F, "SI", token_unknown),  TOKEN_ENTRY(0x10, "DLE", token_unknown),  TOKEN_ENTRY(0x11, "DC1", token_unknown),
    TOKEN_ENTRY(0x12, "DC2", token_unknown), TOKEN_ENTRY(0x13, "DC3", token_unknown),  TOKEN_ENTRY(0x14, "DC4", token_unknown),
    TOKEN_ENTRY(0x15, "NAK", token_unknown), TOKEN_ENTRY(0x16, "SYN", token_unknown),  TOKEN_ENTRY(0x17, "ETB", token_unknown),
    TOKEN_ENTRY(0x18, "CAN", token_unknown), TOKEN_ENTRY(0x19, "EM", token_unknown),   TOKEN_ENTRY(0x1A, "SUB", token_unknown),
    TOKEN_ENTRY(0x1B, "ESC", token_unknown), TOKEN_ENTRY(0x1C, "FS", token_unknown),   TOKEN_ENTRY(0x1D, "GS", token_unknown),
    TOKEN_ENTRY(0x1E, "RS", token_unknown),  TOKEN_ENTRY(0x1F, "US", token_unknown),   TOKEN_ENTRY(0x20, "SP", token_space),
    TOKEN_ENTRY(0x21, "!", token_unknown),   TOKEN_ENTRY(0x22, "\"", token_dquote),    TOKEN_ENTRY(0x23, "#", token_unknown),
    TOKEN_ENTRY(0x24, "$", token_unknown),   TOKEN_ENTRY(0x25, "%", token_unknown),    TOKEN_ENTRY(0x26, "&", token_unknown),
    TOKEN_ENTRY(0x27, "'", token_squote),    TOKEN_ENTRY(0x28, "(", token_lparen),     TOKEN_ENTRY(0x29, ")", token_rparen),
    TOKEN_ENTRY(0x2A, "*", token_multi),     TOKEN_ENTRY(0x2B, "+", token_plus),       TOKEN_ENTRY(0x2C, ",", token_unknown),
    TOKEN_ENTRY(0x2D, "-", token_minus),     TOKEN_ENTRY(0x2E, ".", token_dot),        TOKEN_ENTRY(0x2F, "/", token_divide),
    TOKEN_ENTRY(0x30, "0", token_number),    TOKEN_ENTRY(0x31, "1", token_number),     TOKEN_ENTRY(0x32, "2", token_number),
    TOKEN_ENTRY(0x33, "3", token_number),    TOKEN_ENTRY(0x34, "4", token_number),     TOKEN_ENTRY(0x35, "5", token_number),
    TOKEN_ENTRY(0x36, "6", token_number),    TOKEN_ENTRY(0x37, "7", token_number),     TOKEN_ENTRY(0x38, "8", token_number),
    TOKEN_ENTRY(0x39, "9", token_number),    TOKEN_ENTRY(0x3A, ":", token_colon),      TOKEN_ENTRY(0x3B, ";", token_semicolon),
    TOKEN_ENTRY(0x3C, "<", token_lesser),    TOKEN_ENTRY(0x3D, "=", token_equal),      TOKEN_ENTRY(0x3E, ">", token_greater),
    TOKEN_ENTRY(0x3F, "?", token_unknown),   TOKEN_ENTRY(0x40, "@", token_unknown),    TOKEN_ENTRY(0x41, "A", token_alpha),
    TOKEN_ENTRY(0x42, "B", token_alpha),     TOKEN_ENTRY(0x43, "C", token_alpha),      TOKEN_ENTRY(0x44, "D", token_alpha),
    TOKEN_ENTRY(0x45, "E", token_alpha),     TOKEN_ENTRY(0x46, "F", token_alpha),      TOKEN_ENTRY(0x47, "G", token_alpha),
    TOKEN_ENTRY(0x48, "H", token_alpha),     TOKEN_ENTRY(0x49, "I", token_alpha),      TOKEN_ENTRY(0x4A, "J", token_alpha),
    TOKEN_ENTRY(0x4B, "K", token_alpha),     TOKEN_ENTRY(0x4C, "L", token_alpha),      TOKEN_ENTRY(0x4D, "M", token_alpha),
    TOKEN_ENTRY(0x4E, "N", token_alpha),     TOKEN_ENTRY(0x4F, "O", token_alpha),      TOKEN_ENTRY(0x50, "P", token_alpha),
    TOKEN_ENTRY(0x51, "Q", token_alpha),     TOKEN_ENTRY(0x52, "R", token_alpha),      TOKEN_ENTRY(0x53, "S", token_alpha),
    TOKEN_ENTRY(0x54, "T", token_alpha),     TOKEN_ENTRY(0x55, "U", token_alpha),      TOKEN_ENTRY(0x56, "V", token_alpha),
    TOKEN_ENTRY(0x57, "W", token_alpha),     TOKEN_ENTRY(0x58, "X", token_alpha),      TOKEN_ENTRY(0x59, "Y", token_alpha),
    TOKEN_ENTRY(0x5A, "Z", token_alpha),     TOKEN_ENTRY(0x5B, "[", token_lbracket),   TOKEN_ENTRY(0x5C, "\\", token_unknown),
    TOKEN_ENTRY(0x5D, "]", token_rbracket),  TOKEN_ENTRY(0x5E, "^", token_unknown),    TOKEN_ENTRY(0x5F, "_", token_unknown),
    TOKEN_ENTRY(0x60, "`", token_unknown),   TOKEN_ENTRY(0x61, "a", token_alpha),      TOKEN_ENTRY(0x62, "b", token_alpha),
    TOKEN_ENTRY(0x63, "c", token_alpha),     TOKEN_ENTRY(0x64, "d", token_alpha),      TOKEN_ENTRY(0x65, "e", token_alpha),
    TOKEN_ENTRY(0x66, "f", token_alpha),     TOKEN_ENTRY(0x67, "g", token_alpha),      TOKEN_ENTRY(0x68, "h", token_alpha),
    TOKEN_ENTRY(0x69, "i", token_alpha),     TOKEN_ENTRY(0x6A, "j", token_alpha),      TOKEN_ENTRY(0x6B, "k", token_alpha),
    TOKEN_ENTRY(0x6C, "l", token_alpha),     TOKEN_ENTRY(0x6D, "m", token_alpha),      TOKEN_ENTRY(0x6E, "n", token_alpha),
    TOKEN_ENTRY(0x6F, "o", token_alpha),     TOKEN_ENTRY(0x70, "p", token_alpha),      TOKEN_ENTRY(0x71, "q", token_alpha),
    TOKEN_ENTRY(0x72, "r", token_alpha),     TOKEN_ENTRY(0x73, "s", token_alpha),      TOKEN_ENTRY(0x74, "t", token_alpha),
    TOKEN_ENTRY(0x75, "u", token_alpha),     TOKEN_ENTRY(0x76, "v", token_alpha),      TOKEN_ENTRY(0x77, "w", token_alpha),
    TOKEN_ENTRY(0x78, "x", token_alpha),     TOKEN_ENTRY(0x79, "y", token_alpha),      TOKEN_ENTRY(0x7A, "z", token_alpha),
    TOKEN_ENTRY(0x7B, "{", token_lbrace),    TOKEN_ENTRY(0x7C, "|", token_unknown),    TOKEN_ENTRY(0x7D, "}", token_rbrace),
    TOKEN_ENTRY(0x7E, "~", token_unknown),   TOKEN_ENTRY(0x7F, "DEL", token_unknown),  TOKEN_ENTRY(0x80, "€", token_unknown),
    TOKEN_ENTRY(0x81, "", token_unknown),    TOKEN_ENTRY(0x82, "‚", token_unknown),    TOKEN_ENTRY(0x83, "ƒ", token_unknown),
    TOKEN_ENTRY(0x84, "„", token_unknown),   TOKEN_ENTRY(0x85, "…", token_unknown),    TOKEN_ENTRY(0x86, "†", token_unknown),
    TOKEN_ENTRY(0x87, "‡", token_unknown),   TOKEN_ENTRY(0x88, "ˆ", token_unknown),    TOKEN_ENTRY(0x89, "‰", token_unknown),
    TOKEN_ENTRY(0x8A, "Š", token_unknown),   TOKEN_ENTRY(0x8B, "‹", token_unknown),    TOKEN_ENTRY(0x8C, "Œ", token_unknown),
    TOKEN_ENTRY(0x8D, "", token_unknown),    TOKEN_ENTRY(0x8E, "Ž", token_unknown),    TOKEN_ENTRY(0x8F, "", token_unknown),
    TOKEN_ENTRY(0x90, "", token_unknown),    TOKEN_ENTRY(0x91, "‘", token_unknown),    TOKEN_ENTRY(0x92, "’", token_unknown),
    TOKEN_ENTRY(0x93, "“", token_unknown),   TOKEN_ENTRY(0x94, "”", token_unknown),    TOKEN_ENTRY(0x95, "•", token_unknown),
    TOKEN_ENTRY(0x96, "–", token_unknown),   TOKEN_ENTRY(0x97, "—", token_unknown),    TOKEN_ENTRY(0x98, "˜", token_unknown),
    TOKEN_ENTRY(0x99, "™", token_unknown),   TOKEN_ENTRY(0x9A, "š", token_unknown),    TOKEN_ENTRY(0x9B, "›", token_unknown),
    TOKEN_ENTRY(0x9C, "œ", token_unknown),   TOKEN_ENTRY(0x9D, "", token_unknown),     TOKEN_ENTRY(0x9E, "ž", token_unknown),
    TOKEN_ENTRY(0x9F, "Ÿ", token_unknown),   TOKEN_ENTRY(0xA0, "NBSP", token_unknown), TOKEN_ENTRY(0xA1, "¡", token_unknown),
    TOKEN_ENTRY(0xA2, "¢", token_unknown),   TOKEN_ENTRY(0xA3, "£", token_unknown),    TOKEN_ENTRY(0xA4, "¤", token_unknown),
    TOKEN_ENTRY(0xA5, "¥", token_unknown),   TOKEN_ENTRY(0xA6, "¦", token_unknown),    TOKEN_ENTRY(0xA7, "§", token_unknown),
    TOKEN_ENTRY(0xA8, "¨", token_unknown),   TOKEN_ENTRY(0xA9, "©", token_unknown),    TOKEN_ENTRY(0xAA, "ª", token_unknown),
    TOKEN_ENTRY(0xAB, "«", token_unknown),   TOKEN_ENTRY(0xAC, "¬", token_unknown),    TOKEN_ENTRY(0xAD, "­SHY", token_unknown),
    TOKEN_ENTRY(0xAE, "®", token_unknown),   TOKEN_ENTRY(0xAF, "¯", token_unknown),    TOKEN_ENTRY(0xB0, "°", token_unknown),
    TOKEN_ENTRY(0xB1, "±", token_unknown),   TOKEN_ENTRY(0xB2, "²", token_unknown),    TOKEN_ENTRY(0xB3, "³", token_unknown),
    TOKEN_ENTRY(0xB4, "´", token_unknown),   TOKEN_ENTRY(0xB5, "µ", token_unknown),    TOKEN_ENTRY(0xB6, "¶", token_unknown),
    TOKEN_ENTRY(0xB7, "·", token_unknown),   TOKEN_ENTRY(0xB8, "¸", token_unknown),    TOKEN_ENTRY(0xB9, "¹", token_unknown),
    TOKEN_ENTRY(0xBA, "º", token_unknown),   TOKEN_ENTRY(0xBB, "»", token_unknown),    TOKEN_ENTRY(0xBC, "¼", token_unknown),
    TOKEN_ENTRY(0xBD, "½", token_unknown),   TOKEN_ENTRY(0xBE, "¾", token_unknown),    TOKEN_ENTRY(0xBF, "¿", token_unknown),
    TOKEN_ENTRY(0xC0, "À", token_unknown),   TOKEN_ENTRY(0xC1, "Á", token_unknown),    TOKEN_ENTRY(0xC2, "Â", token_unknown),
    TOKEN_ENTRY(0xC3, "Ã", token_unknown),   TOKEN_ENTRY(0xC4, "Ä", token_unknown),    TOKEN_ENTRY(0xC5, "Å", token_unknown),
    TOKEN_ENTRY(0xC6, "Æ", token_unknown),   TOKEN_ENTRY(0xC7, "Ç", token_unknown),    TOKEN_ENTRY(0xC8, "È", token_unknown),
    TOKEN_ENTRY(0xC9, "É", token_unknown),   TOKEN_ENTRY(0xCA, "Ê", token_unknown),    TOKEN_ENTRY(0xCB, "Ë", token_unknown),
    TOKEN_ENTRY(0xCC, "Ì", token_unknown),   TOKEN_ENTRY(0xCD, "Í", token_unknown),    TOKEN_ENTRY(0xCE, "Î", token_unknown),
    TOKEN_ENTRY(0xCF, "Ï", token_unknown),   TOKEN_ENTRY(0xD0, "Ð", token_unknown),    TOKEN_ENTRY(0xD1, "Ñ", token_unknown),
    TOKEN_ENTRY(0xD2, "Ò", token_unknown),   TOKEN_ENTRY(0xD3, "Ó", token_unknown),    TOKEN_ENTRY(0xD4, "Ô", token_unknown),
    TOKEN_ENTRY(0xD5, "Õ", token_unknown),   TOKEN_ENTRY(0xD6, "Ö", token_unknown),    TOKEN_ENTRY(0xD7, "×", token_unknown),
    TOKEN_ENTRY(0xD8, "Ø", token_unknown),   TOKEN_ENTRY(0xD9, "Ù", token_unknown),    TOKEN_ENTRY(0xDA, "Ú", token_unknown),
    TOKEN_ENTRY(0xDB, "Û", token_unknown),   TOKEN_ENTRY(0xDC, "Ü", token_unknown),    TOKEN_ENTRY(0xDD, "Ý", token_unknown),
    TOKEN_ENTRY(0xDE, "Þ", token_unknown),   TOKEN_ENTRY(0xDF, "ß", token_unknown),    TOKEN_ENTRY(0xE0, "à", token_unknown),
    TOKEN_ENTRY(0xE1, "á", token_unknown),   TOKEN_ENTRY(0xE2, "â", token_unknown),    TOKEN_ENTRY(0xE3, "ã", token_unknown),
    TOKEN_ENTRY(0xE4, "ä", token_unknown),   TOKEN_ENTRY(0xE5, "å", token_unknown),    TOKEN_ENTRY(0xE6, "æ", token_unknown),
    TOKEN_ENTRY(0xE7, "ç", token_unknown),   TOKEN_ENTRY(0xE8, "è", token_unknown),    TOKEN_ENTRY(0xE9, "é", token_unknown),
    TOKEN_ENTRY(0xEA, "ê", token_unknown),   TOKEN_ENTRY(0xEB, "ë", token_unknown),    TOKEN_ENTRY(0xEC, "ì", token_unknown),
    TOKEN_ENTRY(0xED, "í", token_unknown),   TOKEN_ENTRY(0xEE, "î", token_unknown),    TOKEN_ENTRY(0xEF, "ï", token_unknown),
    TOKEN_ENTRY(0xF0, "ð", token_unknown),   TOKEN_ENTRY(0xF1, "ñ", token_unknown),    TOKEN_ENTRY(0xF2, "ò", token_unknown),
    TOKEN_ENTRY(0xF3, "ó", token_unknown),   TOKEN_ENTRY(0xF4, "ô", token_unknown),    TOKEN_ENTRY(0xF5, "õ", token_unknown),
    TOKEN_ENTRY(0xF6, "ö", token_unknown),   TOKEN_ENTRY(0xF7, "÷", token_unknown),    TOKEN_ENTRY(0xF8, "ø", token_unknown),
    TOKEN_ENTRY(0xF9, "ù", token_unknown),   TOKEN_ENTRY(0xFA, "ú", token_unknown),    TOKEN_ENTRY(0xFB, "û", token_unknown),
    TOKEN_ENTRY(0xFC, "ü", token_unknown),   TOKEN_ENTRY(0xFD, "ý", token_unknown),    TOKEN_ENTRY(0xFE, "þ", token_unknown),
    TOKEN_ENTRY(0xFF, "ÿ", token_unknown),
};

parser_context::token::token() : _type(0), _pos(0), _size(0), _line(1), _id(-1) {}

parser_context::token::token(const token& rhs) : _type(rhs._type), _pos(rhs._pos), _size(rhs._size), _line(rhs._line), _id(rhs._id) {}

parser_context::token& parser_context::token::init() {
    _type = 0;
    _pos = 0;
    _size = 0;
    _line = 1;
    _id = -1;
    return *this;
}

parser_context::token& parser_context::token::increase() {
    _size++;
    return *this;
}

parser_context::token& parser_context::token::set_type(uint32 type) {
    _type = type;
    return *this;
}

parser_context::token& parser_context::token::update_pos(size_t pos) {
    _pos = pos;
    return *this;
}

parser_context::token& parser_context::token::update_size(size_t size) {
    _size = size;
    return *this;
}

parser_context::token& parser_context::token::newline() {
    _line++;
    return *this;
}

parser_context::token& parser_context::token::set_index(uint32 id) {
    _id = id;
    return *this;
}

uint32 parser_context::token::get_index() const { return _id; }

uint32 parser_context::token::get_type() const { return _type; }

size_t parser_context::token::get_pos() const { return _pos; }

size_t parser_context::token::get_size() const { return _size; }

size_t parser_context::token::get_line() const { return _line; }

bool parser_context::token::empty() { return 0 == _size; }

size_t parser_context::token::size() { return _size; }

std::string parser_context::token::as_string(const char* p) {
    std::string obj;
    if (p) {
        obj.insert(obj.end(), p + _pos, p + _pos + _size);
    }
    return obj;
}

void parser_context::learn() {
    //
}

void parser_context::token::visit(const char* p, std::function<void(const token* t)> f) {
    if (p && f) {
        f(this);
    }
}

parser_context::token* parser_context::token::clone() {
    token* p = new token(*this);
    return p;
}

parser_context::parser_context() : _p(nullptr), _size(0) {}

parser_context::~parser_context() { clear(); }

return_t parser_context::init(const char* p, size_t size) {
    return_t ret = errorcode_t::success;
    _p = p;
    _size = size;
    get_token().init();
    clear();
    return ret;
}

return_t parser_context::add_token_if(std::function<void(token*)> hook) {
    return_t ret = errorcode_t::success;
    if (get_token().size()) {
        token* newone = get_token().clone();
        _tokens.push_back(newone);
        if (hook) {
            hook(newone);
        }
    } else {
        ret = errorcode_t::empty;
    }
    return ret;
}

void parser_context::clear() {
    for (auto item : _tokens) {
        delete item;
    }
    _tokens.clear();
}

parser_context::token& parser_context::get_token() { return _token; }

void parser_context::for_each(std::function<void(const token_description* desc)> f) {
    if (_p && f) {
        auto handler = [&](const token* t) -> void {
            // compact parameter
            token_description desc;
            desc.type = t->get_type();
            desc.pos = t->get_pos();
            desc.size = t->get_size();
            desc.line = t->get_line();
            desc.index = t->get_index();
            desc.p = _p + t->get_pos();
            f(&desc);
        };

        for (auto item : _tokens) {
            item->visit(_p, handler);
        }
    }
}

parser::parser() {
    get_config().set("handle_comments", 1);
    get_config().set("handle_quoted", 1);
    get_config().set("handle_token", 1);
}

return_t parser::parse(parser_context& context, const char* p, size_t size) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == p) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        uint16 handle_comments = get_config().get("handle_comments");
        uint16 handle_quoted = get_config().get("handle_quoted");
        uint16 handle_token = get_config().get("handle_token");

        context.init(p, size);

        auto type_of = [&](char c) -> token_t { return _ascii_token_table[c].type; };
        auto hook = [&](parser_context::token* t) -> void {
            int entry_no = 0;
            switch (t->get_type()) {
                case token_quot_string:
                    // do not lookup
                    entry_no = -1;
                    break;
                default:
                    lookup(t->as_string(p), entry_no);
                    break;
            }
            t->set_index(entry_no);
        };

        bool comments = false;
        bool quot = false;

        for (size_t pos = 0; pos < size; pos++) {
            char c = p[pos];
            token_t type = type_of(c);

            // comments
            if (comments && handle_comments) {
                if (token_newline == type) {
                    comments = false;

                    context.add_token_if(hook);
                    context.get_token().update_pos(pos + 1).update_size(0);
                } else {
                    context.get_token().increase();
                }
                continue;
            }

            // token
            if (handle_token) {
                bool match = false;
                tokens_t::iterator lbound = _tokens.lower_bound(c);
                tokens_t::iterator ubound = _tokens.upper_bound(c);
                for (auto iter = lbound; iter != ubound; iter++) {
                    const std::string& item = iter->second.first;

                    if (0 == strncmp(p + pos, item.c_str(), item.size())) {
                        int token_attr = iter->second.second;

                        context.add_token_if(hook);

                        if ((parser_attr_comments == token_attr) && handle_comments) {
                            comments = true;
                            context.get_token().set_type(token_comments);
                        } else {
                            context.get_token().update_pos(pos).update_size(item.size());
                            context.add_token_if(hook);
                            pos += (item.size() - 1);
                            context.get_token().update_pos(pos + 1).update_size(0);
                        }

                        match = true;

                        break;
                    }
                }

                if (match) {
                    continue;
                }
            }

            // quoted string
            if (handle_quoted) {
                if (token_dquote == type) {
                    quot = !quot;
                    if (quot) {
                        context.add_token_if(hook);

                        context.get_token().set_type(token_quot_string).update_pos(pos).update_size(1);
                    } else {
                        context.get_token().increase();
                        context.add_token_if(hook);
                        context.get_token().update_pos(pos + 1).update_size(0);
                    }
                    continue;
                }
            }

            if (quot) {
                context.get_token().increase();
            } else {
                // tokenize
                switch (type) {
                    case token_alpha:
                    case token_number:
                        context.get_token().set_type(token_identifier).increase();
                        break;
                    case token_space:
                        context.add_token_if(hook);

                        context.get_token().update_pos(pos + 1).update_size(0);
                        break;
                    case token_newline:
                        context.add_token_if(hook);

                        context.get_token().update_pos(pos + 1).update_size(0).newline();
                        break;
                    case token_dquote:
                    default:
                        if ((token_dquote == type) && (true == handle_quoted)) {
                            break;
                        }

                        context.add_token_if(hook);

                        context.get_token().set_type(type).update_pos(pos).update_size(1);
                        context.add_token_if(hook);
                        context.get_token().update_pos(pos + 1).update_size(0);
                        break;
                }
            }
        }
        context.add_token_if(hook);
    }
    __finally2 {
        //
    }
    return ret;
}

// parser& parser::apply(parser_context& context) {
//     //
//     return *this;
// }

parser& parser::add_token(const std::string token, int attr) {
    if (false == token.empty()) {
        _tokens.insert({token[0], {token, attr}});
        //_tokens.insert({token, attr});
    }
    return *this;
}

parser& parser::add_rule(const std::string rule) {
    //
    return *this;
}

// parser& parser::learn() {
//     for (auto item : _tokens) {
//         //
//     }
//     return *this;
// }

t_key_value<std::string, uint16>& parser::get_config() { return _keyvalue; }

void parser::lookup(const std::string& word, int& idx) {
    size_t entry_no = _dictionary.size() + 1;  // entry 0 reserved
    std::pair<dictionary_t::iterator, bool> pib = _dictionary.insert({word, entry_no});
    if (pib.second) {
        idx = entry_no;
    } else {
        idx = pib.first->second;
    }
}

}  // namespace io
}  // namespace hotplace
