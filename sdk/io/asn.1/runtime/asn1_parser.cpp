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

#include <hotplace/sdk/io/asn.1/runtime/asn1_parser.hpp>

namespace hotplace {
namespace io {

asn1_parser::asn1_parser() { prepare(); }

parser& asn1_parser::get_parser() { return _parser; }

void asn1_parser::prepare() {
    auto& p = _parser;

    p.add_token("BOOLEAN", token_bool);
    p.add_token("INTEGER", token_int);
    p.add_token("BIT STRING", token_bitstring);
    p.add_token("OCTET STRING", token_octstring);
    p.add_token("NULL", token_null);
    p.add_token("OBJECT IDENTIFIER", token_oid);
    p.add_token("ObjectDescriptor", token_objdesc);
    p.add_token("EXTERNAL", token_extern);
    p.add_token("REAL", token_real);
    p.add_token("ENUMERATED", token_enum);
    p.add_token("EMBEDDED PDV", token_embedpdv);
    p.add_token("UTF8String", token_utf8string);
    p.add_token("RELATIVE-OID", token_reloid);
    p.add_token("OF", token_of);
    p.add_token("SEQUENCE", token_sequence);
    p.add_token("SET", token_set);
    p.add_token("NumericString", token_numstring);
    p.add_token("PrintableString", token_printstring);
    p.add_token("TeletexString", token_t61string);
    p.add_token("VideotexString", token_visiblestring);
    p.add_token("IA5String", token_ia5string);
    p.add_token("UTCTime", token_utctime);
    p.add_token("GeneralizedTime", token_generalizedtime);
    p.add_token("GraphicString", token_graphicstring);
    p.add_token("VisibleString", token_visiblestring);
    p.add_token("GeneralString", token_genaralstring);
    p.add_token("UniversalString", token_universalstring);
    p.add_token("CHARACTER STRING", token_cstring);
    p.add_token("BMPString", token_bmpstring);
    p.add_token("DATE", token_date);
    p.add_token("TIME-OF-DAY", token_timeofday);
    p.add_token("DATE-TIME", token_datetime);
    p.add_token("DURATION", token_duration);
    p.add_token("CHOICE", token_choice);
    p.add_token("ANY", token_any);

    p.add_token("::=", token_assign);
    p.add_token("--", token_comments);
    p.add_token("TRUE", token_true);
    p.add_token("FALSE", token_false);
    p.add_token("tagged mode", token_taggedmode);
    p.add_token("class", token_class);
    p.add_token("UNIVERSAL", token_universal);
    p.add_token("APPLICATION", token_application);
    p.add_token("PRIVATE", token_private);
    p.add_token("IMPLICIT", token_implicit);
    p.add_token("EXPLICIT", token_explicit);
    p.add_token("|", token_union);
    p.add_token("INTERSECTION", token_intersection);
    p.add_token("EXCEPT", token_except);
    p.add_token("ALL EXCEPT", token_allexcept);
    p.add_token("DEFAULT", token_default);

    auto ac = p.get_ac();

    enum token_userdeined {
        token_sequencebody = token_userdefine,
        token_setbody,
        token_namednumberlist,
        token_namednumberelement,
        token_enumelement,
        token_enumerations,
        token_enumbody,
        token_sequenceofbody,
        token_setofbody,
        token_defaultval,
        token_builtintype_default,
        token_usertype_default,
        token_sequenceof_default,
        token_setof_default,
    };

    ac->set_group(token_builtintype, {token_bool, token_int, token_null, token_oid, token_real, token_utf8string, token_visiblestring});
    ac->set_group(token_class, {token_application, token_private, token_universal});
    ac->set_group(token_taggedmode, {token_implicit, token_explicit});

    ac->insert_as(token_tag, {token_lbracket, token_number, token_rbracket});                                 // pattern 0
    ac->insert_as(token_tag, {token_lbracket, token_class, token_number, token_rbracket});                    // pattern 1
    ac->insert_as(token_tag, {token_lbracket, token_number, token_rbracket, token_taggedmode});               // pattern 2
    ac->insert_as(token_tag, {token_lbracket, token_class, token_number, token_rbracket, token_taggedmode});  // pattern 3
    ac->insert_as(token_defaultval, {token_default, token_lbrace, token_rbrace});                             // pattern 4
    ac->insert_as(token_builtintype_default, {token_builtintype, token_defaultval});                          // pattern 5
    ac->insert_as(token_usertype_default, {token_usertype, token_defaultval});                                // pattern 6
    ac->insert_as(token_taggedtype, {token_tag, token_builtintype});                                          // pattern 7
    ac->insert_as(token_taggedtype, {token_tag, token_usertype});                                             // pattern 8
    ac->insert_as(token_namedtype, {token_identifier, token_builtintype});                                    // pattern 9
    ac->insert_as(token_namedtype, {token_identifier, token_builtintype_default});                            // pattern 10
    ac->insert_as(token_namedtype, {token_identifier, token_taggedtype});                                     // pattern 11
    ac->insert_as(token_namedtype, {token_identifier, token_usertype});                                       // pattern 12
    ac->insert_as(token_namedtype, {token_identifier, token_usertype_default});                               // pattern 13
    ac->repeat_as(token_element, token_comma, {token_namedtype, token_taggedtype});                           //
    ac->insert_as(token_sequencebody, {token_sequence, token_lbrace, token_element, token_rbrace});           // pattern 14
    ac->insert_as(token_setbody, {token_set, token_lbrace, token_element, token_rbrace});                     // pattern 15
    ac->insert_as(token_taggedmode, {token_tag, token_sequencebody});                                         // pattern 16
    ac->insert_as(token_taggedmode, {token_tag, token_setbody});                                              // pattern 17
    ac->insert_as(token_namednumberelement, {token_identifier, token_lparen, token_number, token_rparen});    // pattern 18
    ac->repeat_as(token_namednumberlist, token_comma, {token_namednumberelement});                            //
    ac->insert_as(token_int, {token_int, token_lbrace, token_namednumberlist, token_rbrace});                 // pattern 19
    ac->insert_as(token_enumbody, {token_enum, token_lbrace, token_namednumberlist, token_rbrace});           // pattern 20
    ac->insert_as(token_namedtype, {token_identifier, token_enumbody});                                       // pattern 21
    ac->insert_as(token_sequenceofbody, {token_sequence, token_of, token_builtintype});                       // pattern 22
    ac->insert_as(token_sequenceofbody, {token_sequence, token_of, token_usertype});                          // pattern 23
    ac->insert_as(token_sequenceof_default, {token_sequenceofbody, token_defaultval});                        // pattern 24
    ac->insert_as(token_setofbody, {token_set, token_of, token_builtintype});                                 // pattern 25
    ac->insert_as(token_setofbody, {token_set, token_of, token_usertype});                                    // pattern 26
    ac->insert_as(token_setof_default, {token_setofbody, token_defaultval});                                  // pattern 27
    ac->insert_as(token_namedtype, {token_identifier, token_sequenceof_default});                             // pattern 28
    ac->insert_as(token_namedtype, {token_identifier, token_setof_default});                                  // pattern 29
    ac->insert_as(token_taggedtype, {token_tag, token_usertype});                                             // pattern 30
    ac->insert_as(token_taggedtype, {token_tag, token_sequencebody});                                         // pattern 31
    ac->insert_as(token_taggedtype, {token_tag, token_setbody});                                              // pattern 32
    ac->insert_as(token_taggedtype, {token_tag, token_sequenceof_default});                                   // pattern 33
    ac->insert_as(token_taggedtype, {token_tag, token_setof_default});                                        // pattern 34

    ac->build();
}

return_t asn1_parser::parse(asn1_runtime* runtime, const char* notation) {
    if (nullptr == runtime || nullptr == notation) return errorcode_t::invalid_parameter;
    return errorcode_t::success;
}

}  // namespace io
}  // namespace hotplace
