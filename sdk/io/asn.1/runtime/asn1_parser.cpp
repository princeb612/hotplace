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
#include <hotplace/sdk/io/asn.1/basic/asn1_resource.hpp>
#include <hotplace/sdk/io/asn.1/runtime/asn1_parser.hpp>
#include <hotplace/sdk/io/parser/parser_resource.hpp>

namespace hotplace {
namespace io {

asn1_parser asn1_parser::_instance;

asn1_parser* asn1_parser::get_instance() {
    _instance.load();
    return &_instance;
}

asn1_parser::asn1_parser() : _flag(0) {}

void asn1_parser::load() {
    if (0 == _flag) {
        critical_section_guard guard(_lock);
        if (0 == _flag) {
            prepare();
            _flag = 1;
        }
    }
}

return_t asn1_parser::parse(asn1_runtime* runtime, const char* notation, parse_tree* pt) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == runtime || nullptr == notation) {
            ret = errorcode_t::invalid_parameter;
        }

        lexical_context context;
        ret = parse(runtime, context, notation, pt);
    }
    __finally2 {}
    return ret;
}

return_t asn1_parser::parse(asn1_runtime* runtime, lexical_context& context, const char* notation, parse_tree* pt) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == runtime || nullptr == notation) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        ret = get_lex().parse(context, notation);
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
                    ret = false;  // stop at comments
                    break;
                default: {
                    tokens.push_back({type, token});
                }
            }

#if defined DEBUG
            if (istraceable(trace_category_t::trace_category_internal, loglevel_t::loglevel_trace)) {
                trace_debug_event(trace_category_t::trace_category_internal, trace_event_t::trace_event_internal, [&](basic_stream& dbs) -> void {
                    dbs.println("[%03u] line %zi type %d(%s) index %d pos %zi len %zi (%.*s)", cnt++, desc->line, desc->type, get_lex().nameof_token(desc->type).c_str(),
                                desc->index, desc->pos, desc->size, (unsigned)desc->size, desc->p);
                });
            }
#endif

            return test;
        };
        context.for_each(lambda);
        tokens.push_back({token_eof, "$"});

        // LALR(1) parse
        ret = get_lalr().parse(tokens, pt);

        // TODO new asn1_object at runtime ...
    }
    __finally2 {}
    return ret;
}

lexical_analyzer& asn1_parser::get_lex() { return _lex; }

lalr_parser& asn1_parser::get_lalr() { return _lalr; }

}  // namespace io
}  // namespace hotplace
