/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_gpt_common.hpp
 * @author GPT
 * @desc   Shared helper declarations for testcase_gpt groups.
 */

#ifndef __HOTPLACE_TEST_TESTCASE_TLS_TESTCASEGPTCOMMON__
#define __HOTPLACE_TEST_TESTCASE_TLS_TESTCASEGPTCOMMON__

#include <set>

#include "sample.hpp"

inline size_t test_collect_fatal_alerts(tls_session& session, tls_direction_t dir, std::set<tls_alertdesc_t>& alerts) {
    size_t count = 0;
    alerts.clear();
    session.get_alert(dir, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
        if (tls_alertlevel_t::fatal == level) {
            ++count;
            alerts.insert(desc);
        }
    });
    return count;
}

struct test_tls_client_hello_view {
    size_t record_length;
    size_t record_end;
    size_t handshake_length;
    size_t handshake_end;
    size_t extensions_length_offset;
    size_t extensions_length;
    size_t extensions_begin;
    size_t extensions_end;
};

bool test_parse_client_hello_view(const binary_t& message, test_tls_client_hello_view& view);
bool test_find_client_hello_extension(const binary_t& message, uint16 extension_type, size_t& body_pos, size_t& body_size);
void test_append_u16(binary_t& bin, uint16 value);
void test_append_u32(binary_t& bin, uint32 value);
void test_write_u32(binary_t& bin, size_t pos, uint32 value);

struct test_tls_extension_view {
    size_t extensions_length_offset;
    size_t extensions_length;
    size_t extension_length_offset;
    size_t extension_length;
    size_t body_offset;
    size_t end_offset;
};

bool test_find_tls_extension(const binary_t& message, size_t extensions_length_offset, size_t message_end, uint16 extension_type, test_tls_extension_view& view);

inline size_t test_count_fatal_alert(tls_session& session, tls_direction_t dir, tls_alertdesc_t expected) {
    size_t count = 0;
    session.get_alert(dir, [&](tls_alertlevel_t level, tls_alertdesc_t desc) {
        if ((tls_alertlevel_t::fatal == level) && (expected == desc)) {
            ++count;
        }
    });
    return count;
}

inline size_t test_count_fatal_alerts(tls_session& session, tls_direction_t dir) {
    size_t count = 0;
    session.get_alert(dir, [&](tls_alertlevel_t level, tls_alertdesc_t) {
        if (tls_alertlevel_t::fatal == level) {
            ++count;
        }
    });
    return count;
}

class testable_tls_handshake_certificate_verify : public tls_handshake_certificate_verify {
   public:
    explicit testable_tls_handshake_certificate_verify(tls_session* session);
    return_t sign_for_test(const EVP_PKEY* pkey, tls_direction_t dir, tls_sigscheme_t& scheme, binary_t& signature);
    return_t write_for_test(tls_direction_t dir, binary_t& body);
    return_t verify_for_test(const EVP_PKEY* pkey, tls_direction_t dir, tls_sigscheme_t scheme, const binary_t& signature);
};

class test_tls13_failing_client_hello : public tls_handshake_client_hello {
   public:
    explicit test_tls13_failing_client_hello(tls_session* session);
    bool preprocess_called() const;

   protected:
    virtual return_t do_preprocess(tls_direction_t dir, tls_io_operation_t opdir);

   private:
    bool _preprocess_called;
};

class test_tls13_server_hello_phase_probe : public tls_handshake_server_hello {
   public:
    explicit test_tls13_server_hello_phase_probe(tls_session* session);
    return_t validate_phase(tls_direction_t dir);
};

class test_tls13_server_hello_postprocess_probe : public tls_handshake_server_hello {
   public:
    explicit test_tls13_server_hello_postprocess_probe(tls_session* session);
    return_t postprocess_read();
    return_t postprocess_write();
};

class test_tls13_server_hello_writer_probe : public tls_handshake_server_hello {
   public:
    explicit test_tls13_server_hello_writer_probe(tls_session* session);
    bool postprocessed() const;
    bool serialized_body_valid() const;

   protected:
    virtual return_t do_postprocess(tls_direction_t dir, tls_io_operation_t operation, const byte_t* stream, size_t size);

   private:
    bool _postprocessed;
    binary_t _serialized;
};

class test_tls13_inner_plaintext_writer : public tls_record_application_data {
   public:
    using tls_record_application_data::tls_record_application_data;

    return_t write_inner_plaintext(tls_direction_t dir, const binary_t& plaintext, binary_t& record);
};

class test_tls_record_size_probe : public tls_record_application_data {
   public:
    using tls_record_application_data::tls_record_application_data;

    return_t read_record_header(tls_direction_t dir, const byte_t* stream, size_t size, size_t& pos);
    return_t write_record_fragment(tls_direction_t dir, binary_t& record, const binary_t& fragment);
    return_t write_inner_plaintext(tls_direction_t dir, const binary_t& plaintext, binary_t& record);
    return_t validate_plaintext_size(tls_direction_t dir, size_t size);
};

return_t test_client_supportedversion_clienthello(tls_session* session, tls_version_t minspec, tls_version_t maxspec, binary_t& bin);
return_t test_client_supportedversion_serverhello(tls_session* session, tls_version_t minspec, tls_version_t maxspec, tls_version_t& server_version);
uint16 test_read_u16(const binary_t& bin, size_t pos);
uint32 test_read_u24(const binary_t& bin, size_t pos);
void test_write_u16(binary_t& bin, size_t pos, uint16 value);
void test_write_u24(binary_t& bin, size_t pos, uint32 value);
bool test_rewrite_client_hello_supported_versions(binary_t& bin, uint8 vector_len, const binary_t& versions);
bool test_remove_client_hello_supported_versions(binary_t& bin);
void test_client_supported_versions_vector(const char* name, uint8 vector_len, const binary_t& versions, bool expect_success);
void test_serverhello_unoffered_supported_version();
return_t test_build_tls12_serverhello(tls_session& client, tls_session& server, tls_version_t client_min, tls_version_t client_max, binary_t& wire,
                                      bool tls12_only_supported_versions = false);
bool test_set_tls_serverhello_random_suffix(binary_t& wire, const byte_t suffix[8]);
void test_configure_tls13_inner_plaintext_session(tls_session& session, bool server_finished = false, bool client_finished = true);
return_t test_read_tls13_inner_plaintext(const binary_t& plaintext, tls_direction_t dir, tls_session& reader, tls_records& records);
return_t test_read_tls13_application_data_with_finished_status(tls_direction_t dir, bool server_finished, bool client_finished, tls_session& reader,
                                                               tls_records& records);
void test_configure_tls_record_size_session(tls_session& session, tls_version_t version, bool protected_record);
return_t test_read_tls_record_header_size(tls_version_t version, bool protected_record, uint16 length, tls_session& session);
return_t test_read_tls_record_fragment_size(tls_version_t version, bool protected_record, uint16 length, tls_session& session, tls_records& records);
return_t test_write_tls_record_fragment_size(tls_version_t version, bool protected_record, size_t length);
return_t test_write_tls_record_header_path(tls_version_t version, size_t length);
void test_configure_dtls13_ccm8_session(tls_session& session);

#endif
