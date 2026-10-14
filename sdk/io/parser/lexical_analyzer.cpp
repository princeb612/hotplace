/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   lexical_analyzer.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2009.11.23   Soo Han, Kim        created (codename.merlin)
 * 2024.06.06   Soo Han, Kim        reboot (codename.hotplace)
 * 2026.09.06   Soo Han, Kim        optimize the tokenization loop step by pre-scanning and batch processing the chunk_size upon entering alpha/number tokens.
 *
 * comments
 *
 */

#include <deque>
#include <hotplace/sdk/base/encoding/base16.hpp>
#include <hotplace/sdk/base/string/string.hpp>
#include <hotplace/sdk/io/parser/lexical_analyzer.hpp>
#include <hotplace/sdk/io/parser/parser_resource.hpp>

namespace hotplace {
namespace io {

lexical_analyzer::lexical_analyzer() : _load(0) {}

lexical_analyzer::~lexical_analyzer() {}

lexical_analyzer& lexical_analyzer::add_token(const std::string& token_name, uint32 token) {
    _lextoken.add(token_name.c_str(), token_name.size(), new token_attr_tag(token));
    _token_dbg.emplace(token, token_name);  // do not overwrite
    return *this;
}

std::string lexical_analyzer::nameof_token(uint32 token) {
    std::string id;
    auto iter = _token_dbg.find(token);
    if (_token_dbg.end() != iter) {
        id = iter->second;
    }
    return id;
}

lexical_analyzer& lexical_analyzer::clear() {
    critical_section_guard guard(_lock);
    _lextoken.reset();
    _dictionary.reset();
    return *this;
}

lexical_analyzer& lexical_analyzer::prepare() {
    if (0 == _load) {
        critical_section_guard guard(_lock);
        if (0 == _load) {
            get_config().set("handle_comments", 1).set("handle_squoted", 1).set("handle_quoted", 1).set("handle_token", 1);

            auto resource = parser_resource::get_instance();
            resource->for_each(resource_type_t::token_type_symbol, [this](uint32 token, const std::string& name) -> void { _token_dbg.emplace(token, name); });
            resource->for_each(resource_type_t::token_type_basic, [this](uint32 token, const std::string& name) -> void { add_token(name, token); });

            _load = 1;
        }
    }
    return *this;
}

t_key_value<std::string, uint16>& lexical_analyzer::get_config() { return _keyvalue; }

bool lexical_analyzer::lookup(const std::string& word, int& index, uint32 flags) {
    bool ret = true;
    int idx = -1;

    critical_section_guard guard(_lock);

    if (flat_lookup_readonly & flags) {
        idx = _dictionary.find(word.c_str(), word.size());
        if (-1 == idx) {
            ret = false;
        } else {
            index = idx;
        }
    } else {
        auto node = _dictionary.insert(word.c_str(), word.size());
        index = node->index;
    }
    return ret;
}

bool lexical_analyzer::rlookup(int index, std::string& word) {
    bool ret = true;
    std::vector<char> arr;

    critical_section_guard guard(_lock);

    ret = _dictionary.lookup(index, arr);
    if (ret) {
        word.assign(arr.data(), arr.size());
    }
    return ret;
}

bool lexical_analyzer::lookup(const char* p, size_t size, std::string& token_name, uint32& token_type /*, uint32& token_tag*/) {
    bool ret = false;
    __try2 {
        if (nullptr == p) {
            __leave2;
        }

        token_type = 0;
        // token_tag = 0;
        token_attr_tag* tag = nullptr;

        critical_section_guard guard(_lock);

        size_t len = _lextoken.lookup(p, size, &tag);
        if (len) {
            token_name.assign(p, len);
            if (tag) {
                token_type = tag->attr;
                // token_tag = tag->tag;
            }
            ret = true;
        }
    }
    __finally2 {}
    return ret;
}

void lexical_analyzer::dump(const lexical_context& context, basic_stream& bs) {
    size_t line = 1;
    std::map<int, std::string> color;
    color.emplace(token_lvalue, "1;34");
    color.emplace(token_assign, "1;33");
    color.emplace(token_or, "1;32");
    color.emplace(token_word, "1;37");
    color.emplace(token_comments, "0;37");
    color.emplace(token_emphasis, "1;35");
    color.emplace(token_type, "1;36");

    auto dump_handler = [&](const token_description* desc) -> bool {
        if (line != desc->line) {
            bs.printf("\n");
            line = desc->line;
        }
        std::string code = "0;37";
        auto iter = color.find(desc->type);
        if (color.end() != iter) {
            code = iter->second;
            bs.printf(ANSI_ESCAPE "%sm%.*s" ANSI_ESCAPE "0m ", code.c_str(), (unsigned)desc->size, desc->p);
        } else {
            bs.printf("%.*s ", (unsigned)desc->size, desc->p);
        }
        return true;
    };

    context.for_each(dump_handler);
    bs.printf("\n");
}

}  // namespace io
}  // namespace hotplace
