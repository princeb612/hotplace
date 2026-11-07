/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   oid_dictionary.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/sdk/io/basic/oid_dictionary.hpp>

namespace hotplace {
namespace io {

oid_dictionary* oid_dictionary::get_instance() {
    static oid_dictionary inst;
    inst.load();
    return &inst;
}

oid_dictionary::oid_dictionary() {}

oid_dictionary::~oid_dictionary() {}

void oid_dictionary::insert(const std::string& oidstr, const std::string& name, const std::string& description) {
    std::vector<uint32> oid;
    str_to_oid(oidstr, oid);
    if (false == oid.empty()) {
        oid_metadata* meta = new oid_metadata{name, description};
        _trie.add(oid, meta);
    }
}

void oid_dictionary::insert(const oid_t& oid, const std::string& name, const std::string& description) {
    if (false == oid.empty()) {
        oid_metadata* meta = new oid_metadata{name, description};
        _trie.add(oid, meta);
    }
}

bool oid_dictionary::lookup(const std::string& oidstr, oid_metadata& metadata) const {
    std::vector<uint32> oid;
    str_to_oid(oidstr, oid);
    if (oid.empty()) return false;

    oid_metadata* meta = nullptr;
    if (_trie.search(oid, &meta) && meta != nullptr) {
        metadata = *meta;
        return true;
    }
    return false;
}

bool oid_dictionary::lookup(const oid_t& oid, oid_metadata& metadata) const {
    if (oid.empty()) return false;

    oid_metadata* meta = nullptr;
    if (_trie.search(oid, &meta) && meta != nullptr) {
        metadata = *meta;
        return true;
    }
    return false;
}

bool oid_dictionary::oid2asn1(const oid_t& oid, basic_stream& notation) const {
    notation.clear();

    std::list<oid_elem> asn1text;

    auto lambda = [&asn1text](uint32 arc, oid_metadata* metadata) -> void {
        asn1text.push_back({arc, metadata ? metadata->name : ""});
    };

    int test = _trie.trace(oid, lambda);
    if ((-1 == test) || asn1text.empty()) return false;

    notation << "{";
    for (auto iter = asn1text.begin(); iter != asn1text.end(); ++iter) {
        if (asn1text.begin() != iter) notation << " ";
        if (iter->name.empty())
            notation << iter->arc;
        else
            notation << iter->name << "(" << iter->arc << ")";
    }
    notation << "}";
    return true;
}

}  // namespace io
}  // namespace hotplace
