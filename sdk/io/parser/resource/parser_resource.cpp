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

parser_resource::parser_resource() : _load(false) {}

void parser_resource::load() {
    if (false == _load) {
        critical_section_guard guard(_lock);
        if (false == _load) {
            load_basic_tokens();
            _load = true;
        }
    }
}

void parser_resource::load_basic_tokens() {
    auto lambda = [this](resource_type_t type, uint32 token, const std::string& name) -> void { _token_names.emplace(token, std::make_pair(type, name)); };

    for_each(resource_type_t::token_type_symbol,
             [this, lambda](uint32 token, const std::string& name) -> void { lambda(resource_type_t::token_type_symbol, token, name); });
    for_each(resource_type_t::token_type_basic,
             [this, lambda](uint32 token, const std::string& name) -> void { lambda(resource_type_t::token_type_symbol, token, name); });
    for_each(resource_type_t::token_type_asn1,
             [this, lambda](uint32 token, const std::string& name) -> void { lambda(resource_type_t::token_type_symbol, token, name); });
}

std::string parser_resource::nameof(uint32 token) const {
    critical_section_guard guard(_lock);
    std::string value;
    auto range = _token_names.equal_range(token);
    if (range.first != range.second) {  // not empty
        auto iter = range.second;
        --iter;
        value = iter->second.second;
    }
    return value;
}

std::string parser_resource::nameof(resource_type_t type, uint32 token) const {
    critical_section_guard guard(_lock);
    std::string value;
    auto range = _token_names.equal_range(token);
    for (auto iter = range.first; iter != range.second; ++iter) {
        auto pair = iter->second;
        if (type == pair.first) {
            value = pair.second;
        }
    }
    return value;
}

}  // namespace io
}  // namespace hotplace
