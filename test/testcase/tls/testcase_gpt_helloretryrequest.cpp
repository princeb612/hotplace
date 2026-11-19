/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_gpt_helloretryrequest.cpp
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc   TLS HelloRetryRequest, key-share validation, and post-HRR handshake tests.
 * @remarks
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include <algorithm>
#include <chrono>

#include "sample.hpp"

static return_t do_test_construct_client_hello(tls_session* session, tls_direction_t dir, const char* group, binary_t& bin, const char* omit_supported_group = nullptr,
                                               bool include_key_share = true, bool include_psk = false) {
    return_t ret = errorcode_t::success;

    __try2 {
        // tls_advisor* tlsadvisor = tls_advisor::get_instance();
        tls_record_handshake record(session);

        ret = record
                  .add(tls_handshake_type_t::client_hello, session,
                       [&](tls_handshake* hs) -> return_t {
                           auto handshake = (tls_handshake_client_hello*)hs;

                           {
                               openssl_prng prng;

                               binary_t random;  // gmt_unix_time(4 bytes) + random(28 bytes)
                               time_t gmt_unix_time = time(nullptr);
                               binary_append(random, gmt_unix_time, hton64);
                               random.resize(sizeof(uint32));
                               binary_t temp;
                               prng.random(temp, 28);
                               binary_append(random, temp);
                               handshake->set_random(random);

                               binary_t session_id;
                               prng.random(session_id, 32);
                               handshake->set_session_id(session_id);
                           }

                           handshake->add_ciphersuites("TLS_AES_128_GCM_SHA256");

                           handshake->get_extensions()
                               .add(tls_extension_type_t::server_name, dir, handshake,
                                    [](tls_extension* extension) -> return_t {
                                        (*(tls_extension_sni*)extension).set_hostname("test.server.com");
                                        return errorcode_t::success;
                                    })
                               .add(tls_extension_type_t::ec_point_formats, dir, handshake,
                                    [](tls_extension* extension) -> return_t {
                                        // RFC 9325 4.2.1
                                        // Note that [RFC8422] deprecates all but the uncompressed point format.
                                        // Therefore, if the client sends an ec_point_formats extension, the ECPointFormatList MUST contain a single element,
                                        // "uncompressed".
                                        (*(tls_extension_ec_point_formats*)extension).add("uncompressed");
                                        return errorcode_t::success;
                                    })
                               .add(tls_extension_type_t::supported_groups, dir, handshake,
                                    [&](tls_extension* extension) -> return_t {
                                        // Clients and servers SHOULD support the NIST P-256 (secp256r1) [RFC8422] and X25519 (x25519) [RFC7748] curves
                                        auto supported_groups = (tls_extension_supported_groups*)extension;
                                        auto add_group = [&](const char* candidate) -> void {
                                            if ((nullptr == omit_supported_group) || (std::string(omit_supported_group) != candidate)) {
                                                supported_groups->add(candidate);
                                            }
                                        };
                                        add_group("x25519");
                                        add_group("secp256r1");
                                        add_group("x448");
                                        add_group("secp521r1");
                                        add_group("secp384r1");
                                        add_group("ffdhe2048");
                                        add_group("ffdhe3072");
                                        add_group("ffdhe4096");
                                        add_group("ffdhe6144");
                                        add_group("ffdhe8192");
                                        return errorcode_t::success;
                                    })
                               .add(tls_extension_type_t::encrypt_then_mac, dir, handshake, nullptr)
                               .add(tls_extension_type_t::extended_master_secret, dir, handshake, nullptr)
                               .add(tls_extension_type_t::signature_algorithms, dir, handshake,
                                    [](tls_extension* extension) -> return_t {
                                        (*(tls_extension_signature_algorithms*)extension)
                                            .add("ecdsa_secp256r1_sha256")
                                            .add("ecdsa_secp384r1_sha384")
                                            .add("ecdsa_secp521r1_sha512")
                                            .add("ed25519")
                                            .add("ed448")
                                            .add("rsa_pkcs1_sha256")
                                            .add("rsa_pkcs1_sha384")
                                            .add("rsa_pkcs1_sha512")
                                            .add("rsa_pss_pss_sha256")
                                            .add("rsa_pss_pss_sha384")
                                            .add("rsa_pss_pss_sha512")
                                            .add("rsa_pss_rsae_sha256")
                                            .add("rsa_pss_rsae_sha384")
                                            .add("rsa_pss_rsae_sha512");
                                        return errorcode_t::success;
                                    })
                               .add(tls_extension_type_t::psk_key_exchange_modes, dir, handshake,
                                    [](tls_extension* extension) -> return_t {
                                        (*(tls_extension_psk_key_exchange_modes*)extension).add("psk_dhe_ke");
                                        return errorcode_t::success;
                                    })
                               .add(tls_extension_type_t::supported_versions, dir, handshake, [&](tls_extension* extension) -> return_t {
                                   (*(tls_extension_client_supported_versions*)extension).add(tls_13);
                                   return errorcode_t::success;
                               });

                           if (include_key_share) {
                               handshake->get_extensions().add(tls_extension_type_t::key_share, dir, handshake, [&](tls_extension* extension) -> return_t {
                                   tls_extension_client_key_share* keyshare = (tls_extension_client_key_share*)extension;
                                   keyshare->clear();
                                   keyshare->add(group);
                                   return errorcode_t::success;
                               });

                               auto pkey = session->get_tls_protection().get_key().find(KID_TLS_CLIENTHELLO_KEYSHARE_PRIVATE);
                               _logger->write([&](basic_stream& bs) -> void { dump_key(pkey, &bs); });
                               _test_case.assert(pkey, __FUNCTION__, "{client} key share (client generated)");
                           }

                           // Keep pre_shared_key as the final ClientHello extension, as required by RFC 8446.
                           if (include_psk) {
                               handshake->get_extensions().add(tls_extension_type_t::pre_shared_key, dir, handshake, nullptr);
                           }

                           return errorcode_t::success;
                       })
                  .write(dir, bin);
    }
    __finally2 {}
    return ret;
}

static bool mutate_client_hello2_key_share(binary_t& message, uint8 mutation) {
    auto read_u16 = [&](size_t offset) -> uint16 { return static_cast<uint16>((static_cast<uint16>(message[offset]) << 8) | message[offset + 1]); };
    auto write_u16 = [&](size_t offset, uint16 value) -> void {
        message[offset] = static_cast<byte_t>((value >> 8) & 0xff);
        message[offset + 1] = static_cast<byte_t>(value & 0xff);
    };

    if ((message.size() < 9) || (0x16 != message[0]) || (0x01 != message[5])) {
        return false;
    }
    size_t record_end = 5 + read_u16(3);
    size_t handshake_end = 9 + ((static_cast<uint32>(message[6]) << 16) | (static_cast<uint32>(message[7]) << 8) | message[8]);
    if ((record_end > message.size()) || (handshake_end > record_end)) {
        return false;
    }

    size_t pos = 9 + 2 + 32;
    if (pos >= handshake_end) {
        return false;
    }
    size_t session_id_len = message[pos++];
    pos += session_id_len;
    if (pos + 2 > handshake_end) {
        return false;
    }
    size_t cipher_suites_len = read_u16(pos);
    pos += 2 + cipher_suites_len;
    if (pos >= handshake_end) {
        return false;
    }
    size_t compression_len = message[pos++];
    pos += compression_len;
    if (pos + 2 > handshake_end) {
        return false;
    }
    size_t extensions_length_offset = pos;
    size_t extensions_length = read_u16(pos);
    size_t extensions_begin = pos + 2;
    size_t extensions_end = extensions_begin + extensions_length;
    if (extensions_end > handshake_end) {
        return false;
    }

    pos = extensions_begin;
    while (pos + 4 <= extensions_end) {
        uint16 extension_type = read_u16(pos);
        size_t extension_length_offset = pos + 2;
        size_t extension_length = read_u16(extension_length_offset);
        size_t body = pos + 4;
        size_t extension_end = body + extension_length;
        if (extension_end > extensions_end) {
            return false;
        }
        if (0x0033 == extension_type) {
            if (extension_length < 2) {
                return false;
            }
            size_t vector_length_offset = body;
            size_t vector_length = read_u16(vector_length_offset);
            size_t entries_begin = body + 2;
            if (vector_length != extension_length - 2) {
                return false;
            }
            if (0 == mutation) {
                if (vector_length < 4) {
                    return false;
                }
                write_u16(entries_begin, t_underlying(tls_group_t::secp256r1));
                return true;
            }
            if (1 == mutation) {
                if (vector_length < 4) {
                    return false;
                }
                binary_t entry(message.begin() + entries_begin, message.begin() + entries_begin + vector_length);
                message.insert(message.begin() + extension_end, entry.begin(), entry.end());
                write_u16(vector_length_offset, static_cast<uint16>(vector_length + entry.size()));
                write_u16(extension_length_offset, static_cast<uint16>(extension_length + entry.size()));
                write_u16(extensions_length_offset, static_cast<uint16>(extensions_length + entry.size()));
                uint16 record_length = read_u16(3);
                write_u16(3, static_cast<uint16>(record_length + entry.size()));
                uint32 handshake_length = (static_cast<uint32>(message[6]) << 16) | (static_cast<uint32>(message[7]) << 8) | message[8];
                handshake_length += static_cast<uint32>(entry.size());
                message[6] = static_cast<byte_t>((handshake_length >> 16) & 0xff);
                message[7] = static_cast<byte_t>((handshake_length >> 8) & 0xff);
                message[8] = static_cast<byte_t>(handshake_length & 0xff);
                return true;
            }
            if (2 == mutation) {
                size_t removed = vector_length;
                message.erase(message.begin() + entries_begin, message.begin() + extension_end);
                write_u16(vector_length_offset, 0);
                write_u16(extension_length_offset, 2);
                write_u16(extensions_length_offset, static_cast<uint16>(extensions_length - removed));
                uint16 record_length = read_u16(3);
                write_u16(3, static_cast<uint16>(record_length - removed));
                uint32 handshake_length = (static_cast<uint32>(message[6]) << 16) | (static_cast<uint32>(message[7]) << 8) | message[8];
                handshake_length -= static_cast<uint32>(removed);
                message[6] = static_cast<byte_t>((handshake_length >> 16) & 0xff);
                message[7] = static_cast<byte_t>((handshake_length >> 8) & 0xff);
                message[8] = static_cast<byte_t>(handshake_length & 0xff);
                return true;
            }
            return false;
        }
        pos = extension_end;
    }
    return false;
}

static return_t do_test_construct_server_hello(tls_session* session, tls_session* client_session, tls_direction_t dir, binary_t& bin) {
    return_t ret = errorcode_t::success;

    __try2 {
        uint16 server_cs = 0;
        tls_version_t server_version = tls_version_t{};

        auto& protection = session->get_tls_protection();
        protection.negotiate(session, server_cs, server_version);

        if (0x0000 == server_cs) {
            ret = errorcode_t::unknown;
            _test_case.test(ret, __FUNCTION__, "no cipher suite");
            __leave2;
        }

        {
            tls_advisor* tlsadvisor = tls_advisor::get_instance();
            auto csname = tlsadvisor->nameof_tls_cipher_suite(server_cs);
            _test_case.assert(csname.size(), __FUNCTION__, "%s", csname.c_str());
        }

        tls_record_handshake record(session);
        ret = record
                  .add(tls_handshake_type_t::server_hello, session,
                       [&](tls_handshake* hs) -> return_t {
                           auto handshake = (tls_handshake_server_hello*)hs;

                           {
                               openssl_prng prng;

                               // server_key_exchange, client_key_exchange
                               binary_t random;  // gmt_unix_time(4 bytes) + random(28 bytes)
                               time_t gmt_unix_time = time(nullptr);
                               binary_append(random, gmt_unix_time, hton64);
                               random.resize(sizeof(uint32));
                               binary_t temp;
                               prng.random(temp, 28);
                               binary_append(random, temp);
                               handshake->set_random(random);

                               binary_t session_id;
                               prng.random(session_id, 32);
                               handshake->set_session_id(session_id);

                               handshake->set_cipher_suite(server_cs);
                           }

                           handshake->get_extensions()
                               .add(tls_extension_type_t::supported_versions, dir, handshake,
                                    [&](tls_extension* extension) -> return_t {
                                        (*(tls_extension_server_supported_versions*)extension).set(server_version);
                                        return errorcode_t::success;
                                    })
                               .add(tls_extension_type_t::key_share, dir, handshake, [](tls_extension* extension) -> return_t {
                                   tls_extension_server_key_share* keyshare = (tls_extension_server_key_share*)extension;
                                   keyshare->clear();
                                   keyshare->add_keyshare();
                                   return errorcode_t::success;
                               });

                           return errorcode_t::success;
                       })
                  .write(dir, bin);
    }
    __finally2 {}
    return ret;
}

static return_t do_test_send_record(tls_session* session, tls_direction_t dir, const binary_t& bin) {
    return_t ret = errorcode_t::success;
    __try2 {
        if (nullptr == session) {
            ret = errorcode_t::invalid_parameter;
            __leave2;
        }

        tls_records records;
        ret = records.read(session, dir, bin);
    }
    __finally2 {}
    return ret;
}

static bool do_test_mutate_server_hello_key_share_group(binary_t& bin, tls_group_t group) {
    // TLSPlaintext record + ServerHello handshake framing.
    auto read_u16 = [&](size_t pos) -> uint16 { return (uint16)(((uint16)bin[pos] << 8) | bin[pos + 1]); };
    auto read_u24 = [&](size_t pos) -> uint32 { return ((uint32)bin[pos] << 16) | ((uint32)bin[pos + 1] << 8) | (uint32)bin[pos + 2]; };

    if (bin.size() < 9 || bin[0] != 0x16 || bin[5] != 0x02) {
        return false;
    }

    size_t record_end = 5 + read_u16(3);
    size_t handshake_end = 9 + read_u24(6);
    if (record_end > bin.size() || handshake_end > record_end) {
        return false;
    }

    size_t pos = 9;
    // ServerHello: legacy_version, random, legacy_session_id_echo,
    // cipher_suite, legacy_compression_method, extensions.
    if (pos + 2 + 32 + 1 > handshake_end) {
        return false;
    }
    pos += 2 + 32;
    uint8 session_id_len = bin[pos++];
    if (pos + session_id_len + 2 + 1 + 2 > handshake_end) {
        return false;
    }
    pos += session_id_len + 2 + 1;

    uint16 extensions_len = read_u16(pos);
    pos += 2;
    size_t extensions_end = pos + extensions_len;
    if (extensions_end > handshake_end) {
        return false;
    }

    while (pos + 4 <= extensions_end) {
        uint16 extension_type = read_u16(pos);
        uint16 extension_len = read_u16(pos + 2);
        pos += 4;
        if (pos + extension_len > extensions_end) {
            return false;
        }

        if (0x0033 == extension_type) {  // key_share (ServerHello or HelloRetryRequest)
            if (extension_len < 2) {
                return false;
            }
            bin[pos] = (byte_t)((uint16)group >> 8);
            bin[pos + 1] = (byte_t)((uint16)group & 0xff);
            return true;
        }
        pos += extension_len;
    }
    return false;
}

// GPT Generated testcase
static void test_server_hello_key_share_validation(const char* name, const char* omit_supported_group, bool mutate_group) {
    // Scenario under test: the named test-case variant.
    // Action: client hello.
    // Expected: mutate ServerHello key_share group.
    _test_case.begin(name);

    tls_session session_client;
    tls_session session_server;
    binary_t client_hello;
    binary_t server_hello;
    return_t ret = errorcode_t::success;

    ret = do_test_construct_client_hello(&session_client, from_client, "secp256r1", client_hello, omit_supported_group);
    _test_case.test(ret, __FUNCTION__, "client hello");
    ret = do_test_send_record(&session_server, from_client, client_hello);
    _test_case.test(ret, __FUNCTION__, "client hello");

    session_server.get_keyvalue().set(session_conf_enforce_key_share_group, t_underlying(tls_group_t::secp256r1));

    ret = do_test_construct_server_hello(&session_server, &session_client, from_server, server_hello);
    _test_case.test(ret, __FUNCTION__, "server hello");

    if (mutate_group) {
        _test_case.assert(do_test_mutate_server_hello_key_share_group(server_hello, tls_group_t::x25519), __FUNCTION__, "mutate ServerHello key_share group");
    }

    ret = do_test_send_record(&session_client, from_server, server_hello);
    _test_case.assert(errorcode_t::handshake_failure == ret, __FUNCTION__, "reject invalid ServerHello key_share group");

    size_t fatal_alert_count = 0;
    std::set<tls_alertdesc_t> fatal_alerts;
    session_client.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
        if (tls_alertlevel_t::fatal == level) {
            ++fatal_alert_count;
            fatal_alerts.insert(desc);
        }
    });
    _test_case.assert(1 == fatal_alert_count && fatal_alerts == std::set<tls_alertdesc_t>{tls_alertdesc_t::illegal_parameter}, __FUNCTION__,
                      "exactly one fatal illegal_parameter alert");
    _test_case.assert(0 == session_client.get_session_status(), __FUNCTION__, "terminate handshake after invalid ServerHello key_share");
}

// GPT Generated testcase
static void test_hello_retry_request_group_validation(const char* name, const char* omit_supported_group, tls_group_t selected_group) {
    // Scenario under test: the named test-case variant.
    // Action: client hello.
    // Expected: mutate HelloRetryRequest selected_group.
    _test_case.begin(name);

    tls_session session_client;
    tls_session session_server;
    binary_t client_hello;
    binary_t hello_retry_request;
    return_t ret = errorcode_t::success;

    ret = do_test_construct_client_hello(&session_client, from_client, "secp256r1", client_hello, omit_supported_group);
    _test_case.test(ret, __FUNCTION__, "client hello");
    ret = do_test_send_record(&session_server, from_client, client_hello);
    _test_case.test(ret, __FUNCTION__, "client hello");

    session_server.get_keyvalue().set(session_conf_enforce_key_share_group, t_underlying(tls_group_t::x25519));

    ret = do_test_construct_server_hello(&session_server, &session_client, from_server, hello_retry_request);
    _test_case.test(ret, __FUNCTION__, "HelloRetryRequest");

    _test_case.assert(do_test_mutate_server_hello_key_share_group(hello_retry_request, selected_group), __FUNCTION__, "mutate HelloRetryRequest selected_group");

    ret = do_test_send_record(&session_client, from_server, hello_retry_request);
    _test_case.assert(errorcode_t::handshake_failure == ret, __FUNCTION__, "reject invalid HelloRetryRequest selected_group");

    size_t fatal_alert_count = 0;
    std::set<tls_alertdesc_t> fatal_alerts;
    session_client.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
        if (tls_alertlevel_t::fatal == level) {
            ++fatal_alert_count;
            fatal_alerts.insert(desc);
        }
    });
    _test_case.assert(1 == fatal_alert_count && fatal_alerts == std::set<tls_alertdesc_t>{tls_alertdesc_t::illegal_parameter}, __FUNCTION__,
                      "exactly one fatal illegal_parameter alert");
    _test_case.assert(0 == session_client.get_session_status(), __FUNCTION__, "terminate handshake after invalid HRR selected_group");
}

// A server must not accept ClientHello2 without the key_share requested by HRR.
static void test_clienthello2_requires_hrr_key_share() {
    // Scenario under test: ClientHello2 must include the key_share requested by HelloRetryRequest.
    // Action: construct the initial ClientHello.
    // Expected: retain the requested group on the server.
    _test_case.begin("ClientHello2 must include the key_share requested by HelloRetryRequest");

    tls_session session_client;
    tls_session session_server;
    binary_t client_hello;
    binary_t hello_retry_request;
    binary_t malformed_client_hello2;

    return_t ret = do_test_construct_client_hello(&session_client, from_client, "secp256r1", client_hello);
    _test_case.test(ret, __FUNCTION__, "construct the initial ClientHello");
    if (errorcode_t::success != ret) {
        return;
    }
    ret = do_test_send_record(&session_server, from_client, client_hello);
    _test_case.test(ret, __FUNCTION__, "process the initial ClientHello");
    if (errorcode_t::success != ret) {
        return;
    }

    session_server.get_keyvalue().set(session_conf_enforce_key_share_group, t_underlying(tls_group_t::x25519));
    ret = do_test_construct_server_hello(&session_server, &session_client, from_server, hello_retry_request);
    _test_case.test(ret, __FUNCTION__, "construct HelloRetryRequest requesting x25519");
    if (errorcode_t::success != ret) {
        return;
    }
    ret = do_test_send_record(&session_client, from_server, hello_retry_request);
    _test_case.test(ret, __FUNCTION__, "process HelloRetryRequest and retain selected_group");
    if (errorcode_t::success != ret) {
        return;
    }

    _test_case.assert(t_underlying(tls_group_t::x25519) == session_server.get_session_info(from_server).get_keyvalue().get(session_key_share_group), __FUNCTION__,
                      "retain the requested group on the server");
    ret = do_test_construct_client_hello(&session_client, from_client, "x25519", malformed_client_hello2, nullptr, false);
    _test_case.test(ret, __FUNCTION__, "serialize ClientHello2 without the requested key_share extension");
    if (errorcode_t::success != ret) {
        return;
    }

    ret = do_test_send_record(&session_server, from_client, malformed_client_hello2);
    _test_case.assert(errorcode_t::handshake_failure == ret, __FUNCTION__, "reject ClientHello2 that omits the HRR-requested key_share");

    size_t illegal_parameter_count = 0;
    session_server.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
        if ((tls_alertlevel_t::fatal == level) && (tls_alertdesc_t::illegal_parameter == desc)) {
            ++illegal_parameter_count;
        }
    });
    _test_case.assert(1 == illegal_parameter_count, __FUNCTION__, "report exactly one fatal illegal_parameter for a missing retry key_share");
}

// ClientHello2 must contain exactly one non-empty key share for the HRR-selected group.
static void test_clienthello2_rejects_invalid_hrr_key_share_entries() {
    // Scenario under test: ClientHello2 key_share must contain exactly the HRR-selected group.
    // Action: construct the initial ClientHello.
    // Expected: %s: mutate ClientHello2 key_share.
    _test_case.begin("ClientHello2 key_share must contain exactly the HRR-selected group");

    auto run_case = [](uint8 mutation, const char* label) -> void {
        tls_session session_client;
        tls_session session_server;
        binary_t client_hello;
        binary_t hello_retry_request;
        binary_t malformed_client_hello2;

        return_t ret = do_test_construct_client_hello(&session_client, from_client, "secp256r1", client_hello);
        _test_case.test(ret, __FUNCTION__, "construct the initial ClientHello");
        if (errorcode_t::success != ret) {
            return;
        }
        ret = do_test_send_record(&session_server, from_client, client_hello);
        _test_case.test(ret, __FUNCTION__, "process the initial ClientHello");
        if (errorcode_t::success != ret) {
            return;
        }

        session_server.get_keyvalue().set(session_conf_enforce_key_share_group, t_underlying(tls_group_t::x25519));
        ret = do_test_construct_server_hello(&session_server, &session_client, from_server, hello_retry_request);
        _test_case.test(ret, __FUNCTION__, "construct HelloRetryRequest requesting x25519");
        if (errorcode_t::success != ret) {
            return;
        }
        ret = do_test_send_record(&session_client, from_server, hello_retry_request);
        _test_case.test(ret, __FUNCTION__, "process HelloRetryRequest");
        if (errorcode_t::success != ret) {
            return;
        }

        ret = do_test_construct_client_hello(&session_client, from_client, "x25519", malformed_client_hello2);
        _test_case.test(ret, __FUNCTION__, "construct valid ClientHello2");
        if (errorcode_t::success != ret) {
            return;
        }
        _test_case.assert(mutate_client_hello2_key_share(malformed_client_hello2, mutation), __FUNCTION__, "%s: mutate ClientHello2 key_share", label);

        ret = do_test_send_record(&session_server, from_client, malformed_client_hello2);
        _test_case.assert(errorcode_t::handshake_failure == ret, __FUNCTION__, "%s: reject invalid ClientHello2 key_share", label);

        size_t fatal_alert_count = 0;
        std::set<tls_alertdesc_t> fatal_alerts;
        session_server.get_alert(from_client, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
            if (tls_alertlevel_t::fatal == level) {
                ++fatal_alert_count;
                fatal_alerts.insert(desc);
                _logger->writeln("%s: fatal alert desc=%u", label, t_underlying(desc));
            }
        });
        _test_case.assert(1 == fatal_alert_count && fatal_alerts == std::set<tls_alertdesc_t>{tls_alertdesc_t::illegal_parameter}, __FUNCTION__,
                          "%s: expected exactly one fatal illegal_parameter (count=%zu, distinct=%zu)", label, fatal_alert_count, fatal_alerts.size());
    };

    run_case(0, "wrong retry group");
    run_case(1, "multiple key-share entries");
    run_case(2, "empty key-share vector");
}

// GPT Generated testcase
static void test_server_hello_after_hrr_group_validation() {
    // Scenario under test: ServerHello key_share does not match retry ClientHello.
    // Action: initial client hello.
    // Expected: mutate final ServerHello key_share group.
    _test_case.begin("ServerHello key_share does not match retry ClientHello");

    tls_session session_client;
    tls_session session_server;
    binary_t client_hello;
    binary_t hello_retry_request;
    binary_t retry_client_hello;
    binary_t server_hello;
    return_t ret = errorcode_t::success;

    ret = do_test_construct_client_hello(&session_client, from_client, "secp256r1", client_hello);
    _test_case.test(ret, __FUNCTION__, "initial client hello");
    ret = do_test_send_record(&session_server, from_client, client_hello);
    _test_case.test(ret, __FUNCTION__, "initial client hello");

    session_server.get_keyvalue().set(session_conf_enforce_key_share_group, t_underlying(tls_group_t::x25519));
    ret = do_test_construct_server_hello(&session_server, &session_client, from_server, hello_retry_request);
    _test_case.test(ret, __FUNCTION__, "HelloRetryRequest");
    ret = do_test_send_record(&session_client, from_server, hello_retry_request);
    _test_case.test(ret, __FUNCTION__, "HelloRetryRequest");

    ret = do_test_construct_client_hello(&session_client, from_client, "x25519", retry_client_hello);
    _test_case.test(ret, __FUNCTION__, "retry client hello");
    ret = do_test_send_record(&session_server, from_client, retry_client_hello);
    _test_case.test(ret, __FUNCTION__, "retry client hello");

    ret = do_test_construct_server_hello(&session_server, &session_client, from_server, server_hello);
    _test_case.test(ret, __FUNCTION__, "final ServerHello");
    _test_case.assert(do_test_mutate_server_hello_key_share_group(server_hello, tls_group_t::secp256r1), __FUNCTION__, "mutate final ServerHello key_share group");

    ret = do_test_send_record(&session_client, from_server, server_hello);
    _test_case.assert(errorcode_t::handshake_failure == ret, __FUNCTION__, "reject ServerHello group not in retry key_share");

    size_t fatal_alert_count = 0;
    std::set<tls_alertdesc_t> fatal_alerts;
    session_client.get_alert(from_server, [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
        if (tls_alertlevel_t::fatal == level) {
            ++fatal_alert_count;
            fatal_alerts.insert(desc);
        }
    });
    _test_case.assert(1 == fatal_alert_count && fatal_alerts == std::set<tls_alertdesc_t>{tls_alertdesc_t::illegal_parameter}, __FUNCTION__,
                      "exactly one fatal illegal_parameter alert");
    _test_case.assert(0 == session_client.get_session_status(), __FUNCTION__, "terminate handshake after mismatched post-HRR ServerHello");
}

void test_helloretryrequest(const char* cligroup, const char* retrygroup, tls_group_t svrgroup, tls_group_t reinforcegroup, tls_flow_t flow_expect,
                            const std::set<tls_alertdesc_t>& alerts) {
    // Scenario under test: HelloRetryRequest.
    // Action: %s %s.
    // Expected: 1-RTT.
    _test_case.begin("HelloRetryRequest");

    return_t ret = errorcode_t::success;
    auto tlsadvisor = tls_advisor::get_instance();
    tls_session session_client;
    tls_session session_server;
    uint32 session_status = 0;
    tls_flow_t flow;
    std::string flow_status;
    basic_stream step;

    {
        flow = session_server.get_tls_protection().get_flow();
        flow_status = tlsadvisor->nameof_tls_flow(flow);
        _test_case.assert(tls_flow_t::one_rtt == flow, __FUNCTION__, "1-RTT");
    }

    {
        // client hello
        binary_t bin;
        step.clear();
        step << flow_status << " client hello";

        tls_direction_t dir = from_client;
        std::string dirstr;
        direction_string(dir, 0, dirstr);

        ret = do_test_construct_client_hello(&session_client, dir, cligroup, bin);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), step.c_str());
        ret = do_test_send_record(&session_server, dir, bin);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), step.c_str());
    }

    {
        // test
        session_status = session_server.get_session_status();
        _test_case.assert(session_status_client_hello == session_status, __FUNCTION__, "%s session status 0x%08x", step.c_str(), session_status);
    }

    session_server.get_keyvalue().set(session_conf_enforce_key_share_group, t_underlying(svrgroup));

    {
        // server hello
        // MUST be HelloRetryRequest
        binary_t bin;
        step.clear();
        step << flow_status << " server hello";

        tls_direction_t dir = from_server;
        std::string dirstr;
        direction_string(dir, 0, dirstr);

        ret = do_test_construct_server_hello(&session_server, &session_client, from_server, bin);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), step.c_str());
        ret = do_test_send_record(&session_client, from_server, bin);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), step.c_str());

        // The client must retain the exact group requested by HRR for ClientHello2.
        auto selected_group = session_client.get_session_info(from_server).get_keyvalue().get(session_key_share_group);
        _test_case.assert(t_underlying(svrgroup) == selected_group, __FUNCTION__, "retain HRR selected_group");
    }

    {
        flow = session_server.get_tls_protection().get_flow();
        flow_status = tlsadvisor->nameof_tls_flow(flow);
    }

    {
        // test
        session_status = session_server.get_session_status();
        _test_case.assert((session_status_server_hello & session_status), __FUNCTION__, "%s session status 0x%08x", step.c_str(), session_status);
        _test_case.assert(tls_flow_t::hello_retry_request == flow, __FUNCTION__, "HelloRetryRequest");
    }

    {
        // client hello
        // retrygroup
        binary_t bin;
        step.clear();
        step << flow_status << " client hello";

        tls_direction_t dir = from_client;
        std::string dirstr;
        direction_string(dir, 0, dirstr);

        ret = do_test_construct_client_hello(&session_client, dir, retrygroup, bin);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), step.c_str());
        ret = do_test_send_record(&session_server, dir, bin);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), step.c_str());

        size_t retry_key_share_count = 0;
        bool retry_key_share_matches_hrr = false;
        session_server.get_tls_protection().get_protection_context().for_each_keyshare_groups([&](tls_group_t group, bool*) -> void {
            ++retry_key_share_count;
            if (group == svrgroup) {
                retry_key_share_matches_hrr = true;
            }
        });
        _test_case.assert(1 == retry_key_share_count && retry_key_share_matches_hrr, __FUNCTION__, "ClientHello2 contains exactly the HRR-selected key_share group");
    }

    session_server.get_keyvalue().set(session_conf_enforce_key_share_group, t_underlying(reinforcegroup));

    {
        // test
        session_status = session_server.get_session_status();
        _test_case.assert((session_status_hello_retry_request & session_status), __FUNCTION__, "%s session status 0x%08x", step.c_str(), session_status);
    }

    {
        // server hello
        binary_t bin;
        step.clear();
        step << flow_status << " server hello";
        tls_direction_t dir = from_server;
        std::string dirstr;
        direction_string(dir, 0, dirstr);

        ret = do_test_construct_server_hello(&session_server, &session_client, dir, bin);
        _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), step.c_str());

        ret = do_test_send_record(&session_client, dir, bin);

        if (alerts.empty()) {
            _test_case.test(ret, __FUNCTION__, "%s %s", dirstr.c_str(), step.c_str());

            auto negotiated_group = session_client.get_session_info(from_server).get_keyvalue().get(session_key_share_group);
            _test_case.assert(t_underlying(svrgroup) == negotiated_group, __FUNCTION__, "final ServerHello uses the HRR-selected group");
            _test_case.assert(0 != (session_client.get_session_status() & session_status_server_hello), __FUNCTION__, "client accepts final ServerHello after HRR");

            // test
            session_status = session_server.get_session_status();
            _test_case.assert((session_status_server_hello & session_status), __FUNCTION__, "%s session status 0x%08x", step.c_str(), session_status);
        } else {
            _test_case.ntest(ret, __FUNCTION__, "%s %s", dirstr.c_str(), step.c_str());
        }

        size_t fatal_alert_count = 0;
        std::set<tls_alertdesc_t> fatal_alerts;
        // unexpected message
        auto lambda = [&](tls_alertlevel_t level, tls_alertdesc_t desc) -> void {
            if (tls_alertlevel_t::fatal == level) {
                ++fatal_alert_count;
                fatal_alerts.insert(desc);
            }
            _logger->writeln("level %i desc %i", level, desc);
        };
        session_client.get_alert(dir, lambda);
        _test_case.assert(fatal_alerts == alerts, __FUNCTION__, "alert");
        _test_case.assert(fatal_alert_count == alerts.size(), __FUNCTION__, "exact fatal alert count");
        if (false == alerts.empty()) {
            _test_case.assert(0 == session_client.get_session_status(), __FUNCTION__, "terminate handshake after second HRR");
        }
    }

    {
        flow = session_server.get_tls_protection().get_flow();
        flow_status = tlsadvisor->nameof_tls_flow(flow);
        _test_case.assert(flow_expect == flow, __FUNCTION__, "%s", flow_status.c_str());
    }
}

/*
 * Scenario: TLS 1.3 PSK offer is declined after HelloRetryRequest.
 *
 *   Client                                             Server
 *     | -- ClientHello1 -------------------------------> |
 *     |    PSK identity + secp256r1 key_share            |
 *     |                                                  |
 *     | <-- HelloRetryRequest -------------------------- |
 *     |     selected_group = x25519                      |
 *     |                                                  |
 *     | -- ClientHello2 -------------------------------> |
 *     |    same PSK identity + fresh x25519 key_share    |
 *     |                                                  |
 *     | <-- ServerHello -------------------------------- |
 *     |     no pre_shared_key / selected_identity        |
 *
 * Preconditions:
 *   - The client has one valid TLS 1.3 resumption ticket.
 *   - The server has no matching ticket, so it cannot select the offered PSK.
 *   - ClientHello1 offers secp256r1 while the server requests x25519.
 *
 * Expected:
 *   - ClientHello2 repeats the PSK identity and supplies the requested x25519 share.
 *   - The server leaves selected_identity unset (0xffff sentinel).
 *   - Both peers preserve the HRR transcript and transition to the full handshake.
 *   - Both peers discard resumption_early and derive equal zero-PSK early and
 *     (EC)DHE handshake secrets.
 *
 * Purpose:
 *   Cover RFC 8446 sections 4.1.4, 4.2.8, 4.2.11 and 7.1 together. This is a
 *   PSK-rejection/key-schedule test, not an anti-replay test (RFC 8446 section 8).
 */
static void test_hrr_psk_decline_uses_full_handshake_schedule() {
    // Scenario under test: TLS 1.3 HRR ClientHello2 PSK decline uses the full-handshake key schedule.
    // Action: prepare the initial PSK binder transcript hash.
    // Expected: capture the ClientHello1 PSK identity snapshot before HRR.
    _test_case.begin("TLS 1.3 HRR ClientHello2 PSK decline uses the full-handshake key schedule");

    tls_session client;
    tls_session server;
    client.set_type(session_type_t::tls);
    server.set_type(session_type_t::tls);

    auto configure_tls13 = [](tls_session& session) {
        auto& protection = session.get_tls_protection();
        protection.set_tls_version(tls_13);
        protection.set_cipher_suite(0x1301);
        session.get_keyvalue().set(session_tls_version, tls_13);
    };
    configure_tls13(client);
    configure_tls13(server);
    // This synthetic client starts a resumption attempt rather than a fresh
    // full handshake. Without zero_rtt, tls_extensions::write() correctly
    // omits pre_shared_key from a one_rtt ClientHello.
    client.get_tls_protection().set_flow(tls_flow_t::zero_rtt);

    openssl_digest digest;
    binary_t empty;
    binary_t empty_hash;
    return_t ret = digest.digest("sha256", empty, empty_hash);
    _test_case.test(ret, __FUNCTION__, "prepare the initial PSK binder transcript hash");
    if (errorcode_t::success != ret) {
        return;
    }
    client.get_tls_protection().get_secrets().assign(tls_secret_t::empty_hash, empty_hash);

    uint64 now_ms = static_cast<uint64>(std::chrono::duration_cast<std::chrono::milliseconds>(std::chrono::system_clock::now().time_since_epoch()).count());
    tls_resumption_ticket ticket;
    ticket.identity = {0xd1, 0x18};
    ticket.server_name = {'t', 'e', 's', 't', '.', 's', 'e', 'r', 'v', 'e', 'r', '.', 'c', 'o', 'm'};
    ticket.nonce = {0x00, 0x18};
    ticket.psk = binary_t(32, 0x48);
    ticket.lifetime = 3600;
    ticket.age_add = 0x12345678;
    ticket.timestamp = now_ms - 10;
    ticket.version = tls_13;
    ticket.cipher_suite = 0x1301;
    client.store_resumption_ticket(ticket);

    binary_t client_hello1;
    ret = do_test_construct_client_hello(&client, from_client, "secp256r1", client_hello1, nullptr, true, true);
    _test_case.test(ret, __FUNCTION__, "construct ClientHello1 with a PSK offer and secp256r1 key_share");
    if (errorcode_t::success != ret) {
        return;
    }
    // The ClientHello1 identity list is the reference against which ClientHello2
    // is checked. Verify that the writer captured it before the HRR exchange.
    const binary_t expected_psk_identity_snapshot = {0x00, 0x02, 0xd1, 0x18};
    const binary_t& client_hello1_psk_snapshot = client.get_tls_protection().get_secrets().get(tls_secret_t::client_hello_psk_identities);
    _test_case.assert(expected_psk_identity_snapshot == client_hello1_psk_snapshot, __FUNCTION__, "capture the ClientHello1 PSK identity snapshot before HRR");
    ret = do_test_send_record(&server, from_client, client_hello1);
    _test_case.test(ret, __FUNCTION__, "process ClientHello1 while the server has no matching PSK identity");
    if (errorcode_t::success != ret) {
        return;
    }

    server.get_keyvalue().set(session_conf_enforce_key_share_group, t_underlying(tls_group_t::x25519));
    binary_t hello_retry_request;
    ret = do_test_construct_server_hello(&server, &client, from_server, hello_retry_request);
    _test_case.test(ret, __FUNCTION__, "construct HelloRetryRequest requesting x25519");
    if (errorcode_t::success != ret) {
        return;
    }
    ret = do_test_send_record(&client, from_server, hello_retry_request);
    _test_case.test(ret, __FUNCTION__, "process HelloRetryRequest and retain the HRR transcript");
    if (errorcode_t::success != ret) {
        return;
    }
    const binary_t& post_hrr_psk_snapshot = client.get_tls_protection().get_secrets().get(tls_secret_t::client_hello_psk_identities);
    _test_case.assert(expected_psk_identity_snapshot == post_hrr_psk_snapshot, __FUNCTION__, "preserve the ClientHello1 PSK identity snapshot while processing HRR");
    _test_case.assert(tls_flow_t::hello_retry_request == client.get_tls_protection().get_flow(), __FUNCTION__, "enter the HRR flow before constructing ClientHello2");

    binary_t client_hello2;
    ret = do_test_construct_client_hello(&client, from_client, "x25519", client_hello2, nullptr, true, true);
    _test_case.test(ret, __FUNCTION__, "construct ClientHello2 with the requested key_share and repeated PSK offer");
    if (errorcode_t::success != ret) {
        return;
    }
    ret = do_test_send_record(&server, from_client, client_hello2);
    _test_case.test(ret, __FUNCTION__, "process ClientHello2 and decline the unknown PSK identity");
    if (errorcode_t::success != ret) {
        return;
    }
    const binary_t offered_identity = {0xd1, 0x18};
    auto identity_pos = std::search(client_hello2.begin(), client_hello2.end(), offered_identity.begin(), offered_identity.end());
    _test_case.assert(client_hello2.end() != identity_pos, __FUNCTION__, "confirm ClientHello2 carries the original PSK identity on the wire");
    _test_case.assert(0xffff == server.get_keyvalue().get(session_server_psk_selected_identity), __FUNCTION__, "keep the unknown PSK identity unselected");
    _test_case.assert(tls_flow_t::hello_retry_request == server.get_tls_protection().get_flow(), __FUNCTION__,
                      "retain HRR flow after ClientHello2 so the transcript prefix is preserved");

    binary_t server_hello;
    ret = do_test_construct_server_hello(&server, &client, from_server, server_hello);
    _test_case.test(ret, __FUNCTION__, "construct the final non-PSK ServerHello");
    if (errorcode_t::success != ret) {
        return;
    }
    ret = do_test_send_record(&client, from_server, server_hello);
    _test_case.test(ret, __FUNCTION__, "process the final ServerHello without selected_identity");
    if (errorcode_t::success != ret) {
        return;
    }

    auto& client_protection = client.get_tls_protection();
    auto& server_protection = server.get_tls_protection();
    auto& client_secrets = client_protection.get_secrets();
    auto& server_secrets = server_protection.get_secrets();
    _test_case.assert(tls_flow_t::one_rtt == client_protection.get_flow(), __FUNCTION__, "complete the client transition to the full-handshake flow");
    _test_case.assert(tls_flow_t::one_rtt == server_protection.get_flow(), __FUNCTION__, "complete the server transition to the full-handshake flow");
    _test_case.assert(client_secrets.get(tls_secret_t::resumption_early).empty(), __FUNCTION__, "discard the offered PSK before deriving the client handshake secrets");
    _test_case.assert(server_secrets.get(tls_secret_t::resumption_early).empty(), __FUNCTION__,
                      "discard any provisional PSK state before deriving the server handshake secrets");
    _test_case.assert(
        !client_secrets.get(tls_secret_t::early_secret).empty() && client_secrets.get(tls_secret_t::early_secret) == server_secrets.get(tls_secret_t::early_secret),
        __FUNCTION__, "derive matching zero-PSK early secrets after HRR");
    _test_case.assert(!client_secrets.get(tls_secret_t::handshake).empty() && client_secrets.get(tls_secret_t::handshake) == server_secrets.get(tls_secret_t::handshake),
                      __FUNCTION__, "derive matching handshake secrets from the HRR transcript and requested x25519 key_share");
}

void testcase_gpt_helloretryrequest() {
    // RFC 8446 4.2.8. ServerHello key_share must be present in both
    // the client's supported_groups and key_share offers.
    test_server_hello_key_share_validation("ServerHello key_share not offered", nullptr, true);
    test_server_hello_key_share_validation("ServerHello key_share not supported", "secp256r1", false);

    // HRR selected_group must be supported, and must not already be in key_share.
    test_hello_retry_request_group_validation("HRR selected_group not supported", "x25519", tls_group_t::x25519);
    test_hello_retry_request_group_validation("HRR selected_group already offered", nullptr, tls_group_t::secp256r1);
    test_clienthello2_requires_hrr_key_share();
    test_clienthello2_rejects_invalid_hrr_key_share_entries();
    test_server_hello_after_hrr_group_validation();
    test_hrr_psk_decline_uses_full_handshake_schedule();

    // RFC 4.2.8.  Key Share

    // C->S CH secp256r1
    // enforce server key share group 0x001d "x25519"
    // S->C SH HRR x25519 success
    test_helloretryrequest("secp256r1", "x25519", tls_group_t::x25519, tls_group_t::x25519, tls_flow_t::one_rtt, {});
    // C->S CH x25519
    // enforce server key share group 0x0018 "secp384r1"
    // S->C SH HRR secp384r1
    // C->S alert (reject 2nd HRR) unexpected_message
    test_helloretryrequest("secp256r1", "x25519", tls_group_t::x25519, tls_group_t::secp384r1, tls_flow_t::hello_retry_request, {tls_alertdesc_t::unexpected_message});
}
