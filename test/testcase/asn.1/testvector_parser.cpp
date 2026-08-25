/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testvector_parser.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 * 2023.09.01   Soo Han, Kim        refactor
 */

#include "sample.hpp"

void test_yaml_testvector_parser() {
    _test_case.begin("Parser YAML");

    t_key_value<uint32, uint32> frequency;

    auto lambda_yaml_asn1parser = [&frequency](const YAML::Node& example, const YAML::Node& items) -> void {
        asn1_value value(nullptr);

        auto values = example["values"];
        if (values && values.IsSequence()) {
            for (const auto& item : values) {
                auto vitem = item["item"].as<std::string>("");
                auto vtype = item["type"].as<std::string>("");
                if (vtype == "string") {
                    auto vvalue = item["value"].as<std::string>("");
                    value.set(vitem, vvalue);
                } else if (vtype == "int") {
                    auto vvalue = item["value"].as<int>(0);
                    value.set(vitem, vvalue);
                } else if (vtype == "float") {
                    auto vvalue = item["value"].as<float>(0.0);
                    value.set(vitem, vvalue);
                } else if (vtype == "bool") {
                    auto vvalue = item["value"].as<bool>(false);
                    value.set(vitem, vvalue);
                } else if (vtype == "stringarray") {
                    std::vector<std::string> vvalue = item["value"].as<std::vector<std::string>>();
                    value.set(vitem, vvalue);
                } else if (vtype == "intarray") {
                    std::vector<int> vvalue = item["value"].as<std::vector<int>>();
                    value.set(vitem, vvalue);
                } else if (vtype == "any") {
                    auto vvalue = item["value"].as<std::string>("");
                    value.set(vitem, variant(base16_decode(vvalue)));
                }
            }
        }

        asn1_parser asn1p;
        auto& p = asn1p.get_parser();

        for (const auto& item : items) {
            std::string text_item = item["item"].as<std::string>("");
            std::string text_der = item["der"].as<std::string>("");
            binary_t bin = base16_decode_rfc(text_der);

            {
                parser_context context;
                p.parse(context, text_item);

                std::vector<uint32> pattern;
                auto dump_handler = [&p, &pattern](const token_description* desc) -> void {
                    pattern.push_back(desc->type);
                    _logger->writeln("[%02zu] line %zi type %d(%s) index %d pos %zi len %zi (%.*s)", desc->idx, desc->line, desc->type,
                                     p.nameof_token(desc->type).c_str(), desc->index, desc->pos, desc->size, (unsigned)desc->size, desc->p);
                };
                context.for_each(dump_handler);

                auto ac = p.get_ac();
                auto res = ac->search(pattern);
                _logger->writeln(ANSI_ESCAPE "1;34mpattern matching" ANSI_ESCAPE "0m");
                if (res.empty()) {
                    _logger->writeln("> no data");
                } else {
                    for (auto& pair : res) {
                        // pair(pos_occurrence, id_pattern)
                        const auto& range = pair.first;
                        const auto& pid = pair.second;
                        frequency.access(pid, true);
                        _logger->writeln("> pos [%2zi..%2zi] pattern[%i]", range.begin, range.end, pid);
                    }
                }
            }
            {
                asn1_runtime reader;
                size_t pos = 0;
                auto stream = bin.data();
                auto size = bin.size();
                auto test = reader.read_weakly_typed(stream, size, pos);

                basic_stream bs_type;
                basic_stream bs_value;
                binary_t bin_encoded;
                reader.notation(&bs_type);
                reader.publish(&bs_value);
                reader.publish(&bin_encoded);

                _logger->write([&](basic_stream& dbs) -> void {
                    valist va;
                    va << bs_type << bs_value << bin_encoded;
                    dbs.println("decode and encode");
                    dbs.vaprintln("> notation {1}", va);
                    dbs.vaprintln("> value    {2}", va);
                    dbs.vaprintln("> DER      {3:x}", va);
                });
                _logger->dump(bin_encoded);

                _test_case.test(test, __FUNCTION__, R"(read and decode "%s")", text_item.c_str());
                _test_case.assert(pos == size, __FUNCTION__, R"(complete stream consumed "%s")", text_item.c_str());
            }
        }
    };

    yaml_testcase test;
    test.add("ASN.1", lambda_yaml_asn1parser).run("testvector_parser.yml");

    _logger->writeln("pattern frequency ... statistics for rule optimization");
    frequency.for_each([](uint32 pid, uint32 cnt) -> void { _logger->writeln("> pattern id %u : %u", pid, cnt); });
}

void testcase_testvector_parser() { test_yaml_testvector_parser(); }
