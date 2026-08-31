/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   parser_resource.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <hotplace/sdk/io/parser/parser_resource.hpp>

namespace hotplace {
namespace io {

parser_resource parser_resource::_instance;

parser_resource* parser_resource::get_instance() {
    _instance.load();
    return &_instance;
}

parser_resource::parser_resource() {}

void parser_resource::load() {
    if (_token_names.empty()) {
        critical_section_guard guard(_lock);
        if (_token_names.empty()) {
            load_basic_tokens();
            load_asn1_tokens();
        }
    }
}

void parser_resource::load_basic_tokens() {
    for_each(parser_resource_type_t::token_type_basic, [this](uint32 token, const std::string& name) -> void { _token_names.emplace(token, name); });
}

void parser_resource::load_asn1_tokens() {
    for_each(parser_resource_type_t::token_type_asn1, [this](uint32 token, const std::string& name) -> void { _token_names.emplace(token, name); });
}

std::string parser_resource::nameof(uint32 token) const {
    std::string value;
    auto iter = _token_names.find(token);
    if (_token_names.end() != iter) {
        value = iter->second;
    }
    return value;
}

}  // namespace io
}  // namespace hotplace
