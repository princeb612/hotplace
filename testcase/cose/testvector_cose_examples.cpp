/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testvector_cose_examples.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include "sample.hpp"

void test_yaml_testvector_cose_examples() {
    _test_case.begin("https://github.com/cose-wg/Examples YAML");

    const OPTION& option = _cmdline->value();

    cbor_web_key cwk;
    std::map<std::string, crypto_key> keymapper;
    keymapper["rfc8152_privkeys"] = rfc8152_privkeys;
    keymapper["rfc8152_pubkeys"] = rfc8152_pubkeys;
    keymapper["rfc8152_privkeys_c4"] = rfc8152_privkeys_c4;

    size_t i = 0;
    cbor_encode e;

    std::map<std::string, cbor_tag_t> dictionary;
    cbor_tag_t table[] = {
        cbor_tag_t::encrypt0,  // 16
        cbor_tag_t::mac0,      // 17
        cbor_tag_t::sign1,     // 18
        cbor_tag_t::encrypt,   // 96
        cbor_tag_t::mac,       // 97
        cbor_tag_t::sign,      // 98
    };
    for (i = 0; i < RTL_NUMBER_OF(table); i++) {
        binary_t bin;
        e.encode(bin, cbor_major_t::tag, (uint8)table[i]);
        std::string keyword = uppername(base16_encode(bin));
        dictionary.emplace(keyword, table[i]);
        _logger->writeln("%s => %i", keyword.c_str(), table[i]);
    }

    _test_case.reset_time();

    cbor_object_signing_encryption cose;

    auto lambda_load_keys = [&](const YAML::Node& items) -> void {
        if (items && items.IsSequence()) {
            for (const auto& item : items) {
                auto text_item = item["item"].as<std::string>("");
                auto keyset = item["keyset"].as<std::string>("");
                auto encoding = item["encoding"].as<std::string>("");
                auto kty = item["kty"].as<std::string>("");

                auto node_keyalg = item["keyalg"];
                auto node_keyuse = item["keyuse"];

                encoding_t enctype = encoding_t::encoding_base16;
                if (encoding == "base16") {
                    enctype = encoding_t::encoding_base16;
                } else if (encoding == "base16rfc") {
                    enctype = encoding_t::encoding_base16rfc;
                } else if (encoding == "base64") {
                    enctype = encoding_t::encoding_base64;
                } else if (encoding == "base64url") {
                    enctype = encoding_t::encoding_base64url;
                } else {
                    break;
                }

                keydesc desc(text_item);
                if (node_keyalg) {
                    auto keyalg = node_keyalg.as<std::string>("");
                    desc.set_alg(keyalg);
                }
                if (node_keyuse) {
                    auto keyuse = node_keyuse.as<std::string>("");
                    if (keyuse == "enc") {
                        desc.set_use_enc();
                    }
                }

                auto& key = keymapper[keyset];

                if (kty == "oct") {
                    auto k = item["k"].as<std::string>("");
                    cwk.add_oct(&key, enctype, k.c_str(), desc);
                } else if (kty == "ec") {
                    auto crv = item["crv"].as<std::string>("");
                    auto x = item["x"].as<std::string>("");
                    auto y = item["y"].as<std::string>("");
                    auto d = item["d"].as<std::string>("");
                    cwk.add_ec(&key, crv.c_str(), enctype, x.c_str(), y.c_str(), d.c_str(), desc);
                } else if (kty == "okp") {
                    auto crv = item["crv"].as<std::string>("");
                    auto x = item["x"].as<std::string>("");
                    auto d = item["d"].as<std::string>("");
                    cwk.add_okp(&key, crv.c_str(), enctype, x.c_str(), d.c_str(), desc);
                } else if (kty == "rsa") {
                    auto n = item["n"].as<std::string>("");
                    auto e = item["e"].as<std::string>("");
                    auto d = item["d"].as<std::string>("");
                    cwk.add_rsa(&key, nid_rsa, enctype, n.c_str(), e.c_str(), d.c_str(), desc);
                }
            }
        }
    };

    auto lambda_itemnode_as_bool = [&](const YAML::Node& node) -> bool {
        bool rc = false;
        if (node && node.IsScalar()) {
            rc = node.as<int>();
        }
        return rc;
    };
    auto lambda_dump_subnode = [&](const char* header, const YAML::Node& node, const char* name) {
        if (node && node.IsMap()) {
            auto sub = node[name];
            if (sub && sub.IsScalar()) {
                if (option.verbose) {
                    _logger->write([&](basic_stream& bs) -> void {
                        auto value = sub.as<std::string>("");
                        bs.printf("> %s %s\n", header, value.c_str());
                        dump_memory(base16_decode(value), &bs, 16, 2, 0, dump_notrunc);
                    });
                }
            }
        }
    };
    auto lambda_set_param = [&](const char* header, const YAML::Node& node, const char* name, cose_context_t* handle, cose_param_t id, basic_stream& properties) {
        if (node && node.IsMap()) {
            auto sub = node[name];
            if (sub && sub.IsScalar()) {
                auto value = sub.as<std::string>("");
                binary_t bin_value = base16_decode(value);
                cose.set(handle, id, bin_value);
                properties << name << " ";

                if (option.verbose) {
                    _logger->write([&](basic_stream& bs) -> void {
                        bs.printf("> %s %s\n", header, value.c_str());
                        dump_memory(bin_value, &bs, 16, 2, 0, dump_notrunc);
                    });
                }
            }
        }
    };
    auto lambda_yaml_cose_examples = [&](const YAML::Node& items) -> void {
        if (items && items.IsSequence()) {
            for (const auto& item : items) {
                auto text_item = item["item"].as<std::string>("");
                auto text_keyset = item["keyset"].as<std::string>("");
                auto text_cbor = item["cbor"].as<std::string>("");

                _logger->colorln("item: %s", text_item.c_str());
                _logger->writeln("keyset: %s", text_keyset.c_str());
                _logger->writeln("cbor: %s", text_cbor.c_str());

                auto flag_skip = lambda_itemnode_as_bool(item["skip"]);
                if (flag_skip) {
                    continue;
                }
                auto flag_debug = lambda_itemnode_as_bool(item["debug"]);
                if (flag_debug) {
                    int break_point_here = 1;
                    UNREFERENCED_PARAMETER(break_point_here);
                }
                auto flag_untagged = lambda_itemnode_as_bool(item["untagged"]);

                binary_t cbor = base16_decode(text_cbor);
                crypto_key& mapped_key = keymapper[text_keyset];

                mapped_key.for_each(dump_crypto_key, nullptr);

                binary_t bin_cbor;
                basic_stream diagnostic;
                cbor_reader reader;
                cbor_reader_context_t* reader_handle = nullptr;
                reader.open(&reader_handle);
                reader.parse(reader_handle, cbor);
                reader.publish(reader_handle, &diagnostic);
                reader.publish(reader_handle, &bin_cbor);
                reader.close(reader_handle);
                if (option.verbose) {
                    _logger->writeln([&](basic_stream& bs) -> void {
                        bs.printf("cbor\n");
                        dump_memory(bin_cbor, &bs, 16, 2, dump_notrunc);
                    });
                    _logger->writeln("diagnostic\n  %s", diagnostic.c_str());

                    cbor_publisher publisher;
                    cose_composer composer;
                    basic_stream bs_diagnostic_composed;
                    binary_t bin_composed;
                    cbor_array* cbor_newone = nullptr;

                    composer.parse(cbor);
                    composer.compose(&cbor_newone, bin_composed, flag_untagged ? false : true);

                    publisher.publish(cbor_newone, &bs_diagnostic_composed);
                    dump_test_data("compose", bs_diagnostic_composed);
                    _test_case.assert(bin_composed == bin_cbor, __FUNCTION__, "compose.parse %s", text_item.c_str());

                    cbor_newone->release();
                }

                basic_stream properties;
                basic_stream reason;
                basic_stream debug_stream;
                return_t ret = errorcode_t::success;

                auto node_enc = item["enc"];
                auto node_shared = item["shared"];

                cose_context_t* handle = nullptr;
                cose.open(&handle);

                lambda_dump_subnode("AAD", node_enc, "aad");
                lambda_dump_subnode("CEK", node_enc, "cek");
                lambda_dump_subnode("tomac", node_enc, "tomac");

                lambda_set_param("external", node_shared, "external", handle, cose_param_external, properties);
                lambda_set_param("unsent iv", node_shared, "iv", handle, cose_param_unsent_iv, properties);
                lambda_set_param("unsent partyu id", node_shared, "apu_id", handle, cose_param_unsent_apu_id, properties);
                lambda_set_param("unsent partyu nonce", node_shared, "apu_nonce", handle, cose_param_unsent_apu_nonce, properties);
                lambda_set_param("unsent partyu other", node_shared, "apu_other", handle, cose_param_unsent_apu_other, properties);
                lambda_set_param("unsent partyv id", node_shared, "apv_id", handle, cose_param_unsent_apv_id, properties);
                lambda_set_param("unsent partyv nonce", node_shared, "apv_nonce", handle, cose_param_unsent_apv_nonce, properties);
                lambda_set_param("unsent partyv other", node_shared, "apv_other", handle, cose_param_unsent_apv_other, properties);
                lambda_set_param("unsent pub other", node_shared, "pub_other", handle, cose_param_unsent_pub_other, properties);
                lambda_set_param("unsent private", node_shared, "priv", handle, cose_param_unsent_priv_other, properties);

                binary_t output;
                ret = cose.process(handle, &mapped_key, cbor, output);

                if (option.verbose) {
                    uint32 flags = 0;
                    uint32 debug_flags = 0;
                    cose.get(handle, flags, debug_flags);
                    if (debug_flags & cose_flag_t::debug_notfound_key) {
                        reason << "!key ";
                    }
                    if (debug_flags & cose_flag_t::debug_partial_iv) {
                        reason << "partial_iv ";
                    }
                    if (debug_flags & cose_flag_t::debug_counter_sig) {
                        reason << "counter_sig ";
                    }
                    debug_stream = handle->debug_stream;
                    if (output.size()) {
                        _logger->writeln([&](basic_stream& bs) -> void {
                            bs << "decrypted\n";
                            dump_memory(output, &bs, 16, 4, dump_notrunc);
                            bs << base16_encode(output);
                        });
                    }
                }

                cose.close(handle);

                basic_stream dbg;
                dbg << text_item << " " << properties;
                if (false == reason.empty()) {
                    dbg << "[ debug : " << reason << "] " << debug_stream;
                }
                _test_case.test(ret, __FUNCTION__, dbg.c_str());
            }
        }
    };

    YAML::Node testvector = YAML::LoadFile("testvector_cose_examples.yml");
    auto examples = testvector["testvector"];
    if (examples && examples.IsSequence()) {
        for (const auto& example : examples) {
            auto schema = example["schema"].as<std::string>("");

            if (schema == "COSE EXAMPLES") {
                auto keys = example["keys"];
                lambda_load_keys(keys);

                auto items = example["items"];
                lambda_yaml_cose_examples(items);
            } else {
                _test_case.assert(false, __FUNCTION__, "bad message format");
            }
        }
    }
}

void testcase_testvector_cose_examples() { test_yaml_testvector_cose_examples(); }
