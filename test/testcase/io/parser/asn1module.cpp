/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   asn1module.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2023.09.01   Soo Han, Kim        refactor
 */

#include <hotplace/test/testcase/io/sample.hpp>

return_t prepare_lexer_asn1(lexical_analyzer& lexer) {
    lexer.clear().prepare();
    auto resource = asn1_resource::get_instance();
    resource->for_each(resource_type_t::token_type_asn1, [&lexer](uint32 token, const std::string& name) -> void { lexer.add_token(name, token); });
    lexer.get_config().set("handle_comments", 1).set("handle_quoted", 1).set("handle_token", 1);
    return errorcode_t::success;
}

return_t prepare_lexer_asn1_usertype(lexical_analyzer& lexer) {
    prepare_lexer_asn1(lexer);
    lexer.get_config().set("handle_lvalue_usertype", 1);
    return errorcode_t::success;
}

void prepare_asn1module_reducer(asn1module_reducer_t& ac) {
    ac.set_group(vtoken_symbol, {token_identifier, token_usertype});

    ac.insert_as(vtoken_header_block_start, {vtoken_symbol, token_definitions});
    // id { oid } DEFINITIONS
    // - the id { form is a very common pattern, so we need to organize it in a bit more detail...
    ac.insert_as(vtoken_header_block_start, {vtoken_symbol, token_lbrace, token_identifier, token_lparen, token_number, token_rparen});
    ac.insert_as(vtoken_header_block_end, {token_assign, token_begin});
    ac.insert_as(vtoken_exports_clause_start, {token_exports});
    ac.insert_as(vtoken_imports_clause_start, {token_imports});
    ac.insert_as(vtoken_exports_clause_end, {token_semicolon});

    ac.treat_as(vtoken_header_clause, {vtoken_header_block_start}, {vtoken_header_block_end});
    ac.treat_as(vtoken_exports_clause, {vtoken_exports_clause_start}, {vtoken_exports_clause_end});
    ac.treat_as(vtoken_imports_clause, {vtoken_imports_clause_start}, {vtoken_exports_clause_end});

    ac.build();
    ac.set_greedy_filter(true);
}

return_t ac_search(const asn1module_reducer_t& ac, const char* input, std::vector<parser_token>& tokens, std::multimap<range_t, size_t>& search_results) {
    return_t ret = errorcode_t::success;

    __try2 {
        if (nullptr == input) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tokens.clear();
        search_results.clear();

        lexical_analyzer lexer;
        lexical_context context;

        // set up tokens
        prepare_lexer_asn1_usertype(lexer);

        // lexer
        lexer.parse(context, input);  // ASN1 file

        // make tokens
        uint32 cnt = 0;
        auto lambda = [&](const token_description* desc) -> bool {
            bool ret = true;
            const auto& type = desc->type;
            std::string token(desc->p, desc->size);
            switch (type) {
                case token_lvalue: {
                    tokens.push_back({token_identifier, token});
                } break;
                case token_comments:
                    // do not push into tokens
                    break;
                default: {
                    tokens.push_back({type, token});
                }
            }
            _logger->writeln("[%03u] line %zi type %d(%s) index %d pos %zi len %zi line %zi (%.*s)", cnt++, desc->line, desc->type,
                             lexer.nameof_token(desc->type).c_str(), desc->index, desc->pos, desc->size, desc->line, (unsigned)desc->size, desc->p);
            return ret;
        };
        context.for_each(lambda);

        // search
        search_results = ac.search(tokens.data(), tokens.size());
    }
    __finally2 {}

    return ret;
}

return_t ac_printall(const asn1module_reducer_t& ac, const std::vector<parser_token>& tokens, const std::multimap<range_t, size_t>& search_results) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (true == search_results.empty()) {
            ret = errorcode_t::no_data;
            _logger->writeln("no patterns matched.");
            __leave2;
        }

        print_style_t style;
        style.use_naked();

        auto lambda_dump = [&](const std::multimap<range_t, size_t>& input) -> void {
            _logger->write([&](basic_stream& dbs) -> void {
                auto lambda_print = [&](typename std::multimap<range_t, size_t>::const_iterator iter, basic_stream& dbs) -> void {
                    const range_t& range = iter->first;
                    size_t pattern_id = iter->second;

                    bool is_virtual = ac.is_virtual_pattern(pattern_id);
                    uint32 vtoken = ac.get_virtual_token(pattern_id);

                    dbs << "range [" << range.begin << " .. " << range.end << "] " << "pattern id: " << pattern_id;
                    if (true == is_virtual) {
                        dbs << " (virtual token: " << vtoken << ")";
                    }
                    dbs << "\n  matched tokens: ";
                    for (size_t i = range.begin; i <= range.end; ++i) {
                        dbs << "[" << tokens[i].value << "]";
                    }
                    dbs << "\n";
                };
                print_pair(input, dbs, lambda_print, style);
            });
        };

        _logger->writeln("matched pattern results (greedy filter : %s)", ac.apply_greedy_filter() ? "true" : "false");
        lambda_dump(search_results);
        if (false == ac.apply_greedy_filter()) {
            _logger->writeln("longest pattern results");
            auto results = ac.greedy_filter(search_results);
            lambda_dump(results);
        }
    }
    __finally2 {}
    return ret;
}

return_t ac_search_and_printall(const asn1module_reducer_t& ac, const char* input) {
    return_t ret = errorcode_t::success;
    __try2 {
        std::vector<parser_token> tokens;
        std::multimap<range_t, size_t> results;
        ret = ac_search(ac, input, tokens, results);
        if (errorcode_t::success != ret) {
            __leave2;
        }
        ret = ac_printall(ac, tokens, results);
        if (errorcode_t::success != ret) {
            __leave2;
        }
    }
    __finally2 {}
    return ret;
}
