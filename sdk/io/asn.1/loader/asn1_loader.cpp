/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_loader.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <hotplace/sdk/io/asn.1/loader/asn1_loader.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_parser.hpp>
// #include <hotplace/sdk/io/asn.1/runtime/asn1_publisher.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_runtime.hpp>
#include <hotplace/sdk/io/parser/lexical_analyzer.hpp>
#include <hotplace/sdk/io/parser/parse_tree.hpp>
#include <hotplace/sdk/io/stream/file_stream.hpp>

namespace hotplace {
namespace io {

asn1_loader::asn1_loader() {}

asn1_loader::~asn1_loader() {}

return_t asn1_loader::load_file(const char* asn1file, parse_tree* pt) {
    asn1_parser parser;
    std::vector<parser_token> tokens;
    asn1file_to_tokens(&parser, asn1file, tokens);
    return parser.to_parsetree(tokens, pt);
}

return_t asn1_loader::load(const char* asn1, size_t size, parse_tree* pt) {
    asn1_parser parser;
    return parser.parse(asn1, size, pt);
}

return_t asn1_loader::asn1file_to_tokens(asn1_parser* parser, const char* asn1file, std::vector<parser_token>& tokens) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == parser || nullptr == asn1file) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        file_stream fs;
        ret = fs.open(asn1file);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = fs.begin_mmap();
        if (errorcode_t::success != ret) {
            __leave2;
        }

        auto stream = fs.data();
        auto size = fs.size();
        ret = parser->to_tokens((char*)stream, size, tokens);
    }
    __finally2 {}
    return ret;
}

return_t asn1_loader::asn1_to_tokens(asn1_parser* parser, const char* asn1, size_t size, std::vector<parser_token>& tokens) {
    if (nullptr == parser) return errorcode_t::invalid_parameter;
    return parser->to_tokens(asn1, size, tokens);
}

}  // namespace io
}  // namespace hotplace
