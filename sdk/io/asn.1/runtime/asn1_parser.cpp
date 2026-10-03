/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1_parser.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 * see README.md
 */

#include <hotplace/sdk/base/stream/basic_stream.hpp>
#include <hotplace/sdk/base/system/trace.hpp>
#include <hotplace/sdk/io/asn.1/asn1_resource.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_parser.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_publisher.hpp>
#include <hotplace/sdk/io/parser/parser_resource.hpp>

namespace hotplace {
namespace io {

asn1_parser::asn1_parser() : _ready(0) {}

return_t asn1_parser::parse(const char* notation, parse_tree* pt) {
    return_t ret = errorcode_t::success;
    __try2 {
        load();

        if (nullptr == notation) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = get_lexer().parse(_lexcontext, notation);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        // LALR tokens
        std::vector<parser_token> tokens;
#if defined DEBUG
        uint32 cnt = 0;
#endif

        auto resource = parser_resource::get_instance();
        auto symid = resource->nameof(token_identifier);  // "identifier"
        auto symuser = resource->nameof(token_usertype);  // "usertype"

        auto lambda = [&](const token_description* desc) -> bool {
            bool test = true;
            const auto& type = desc->type;
            std::string token(desc->p, desc->size);
            switch (type) {
                case token_lvalue: {
                    tokens.push_back({token_identifier, symid});
                } break;
                case token_comments:
                    break;
                default: {
                    tokens.push_back({type, token});
                    break;
                }
            }

#if defined DEBUG
            if (token_comments != type) {
                if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_trace)) {
                    trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal, [&](basic_stream& dbs) -> void {
                        dbs.println("[%03u] line %zi type %d(%s) index %d pos %zi len %zi (%.*s)", cnt, desc->line, desc->type,
                                    get_lexer().nameof_token(desc->type).c_str(), desc->index, desc->pos, desc->size, (unsigned)desc->size, desc->p);
                        cnt = tokens.size();
                    });
                }
            }
#endif

            return test;
        };
        _lexcontext.for_each(lambda);
        tokens.push_back({token_eof, "$"});

        // LALR(1) parse
        ret = get_parser().parse(tokens, pt);
    }
    __finally2 {}
    return ret;
}

return_t asn1_parser::parse(const char* notation, asn1_build_resultset& result) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == notation) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }
        parse_tree pt;
        ret = parse(notation, &pt);
        if (errorcode_t::success != ret) {
            __leave2;
        }

        asn1_publisher publisher;
        ret = publisher.build(&pt, result);
    }
    __finally2 {}
    return ret;
}

lexical_analyzer& asn1_parser::get_lexer() { return _lex; }

parser_t& asn1_parser::get_parser() {
    // return get_lalr1_parser_asn1_notation_by_build();
    // return get_lalr1_parser_asn1_notation_by_import();
    // return get_glr_parser_asn1_by_build();
    return get_glr_parser_asn1_by_import();
}

void asn1_parser::load() {
    if (0 == _ready) {
        auto& lex = get_lexer();
        // handle_quoted to 1
        lex.get_config().set("handle_comments", 1).set("handle_quoted", 1).set("handle_token", 1).set("handle_lvalue_usertype", 1).set("handle_asn1parameterized", 1);
        lex.prepare();

        // ASN.1 tokens
        auto resource = parser_resource::get_instance();
        resource->for_each(resource_type_t::token_type_asn1, [&lex](uint32 token, const std::string& name) -> void { lex.add_token(name, token); });

        _ready = 1;
    }
}

}  // namespace io
}  // namespace hotplace
