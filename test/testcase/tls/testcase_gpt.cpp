/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_gpt.cpp
 * @author GPT
 * @desc   Test group dispatcher.
 */

void testcase_gpt_helloretryrequest();
void testcase_gpt_negotiation();
void testcase_gpt_certificate();
void testcase_gpt_record();
void testcase_gpt_record_sequence();
void testcase_gpt_loopback_tcp();
void testcase_gpt_renegotiation();
void testcase_gpt_early_data();
void testcase_gpt_early_data_ccs();
void testcase_gpt_early_data_buffer();
void testcase_gpt_session_ticket();
void testcase_gpt_psk();
void testcase_gpt_psk_binder();
void testcase_gpt_psk_hrr_binder();
void testcase_gpt_psk_hrr_suite();
void testcase_gpt_psk_offer();
void testcase_gpt_psk_ticket_age();
void testcase_gpt_finished();
void testcase_gpt_secure_prosumer();

void testcase_gpt() {
    testcase_gpt_helloretryrequest();
    testcase_gpt_negotiation();
    testcase_gpt_certificate();
    testcase_gpt_record();
    testcase_gpt_record_sequence();
    testcase_gpt_loopback_tcp();
    testcase_gpt_renegotiation();
    testcase_gpt_early_data();
    testcase_gpt_early_data_ccs();
    testcase_gpt_early_data_buffer();
    testcase_gpt_session_ticket();
    testcase_gpt_psk();
    testcase_gpt_psk_binder();
    testcase_gpt_psk_hrr_binder();
    testcase_gpt_psk_hrr_suite();
    testcase_gpt_psk_offer();
    testcase_gpt_psk_ticket_age();
    testcase_gpt_finished();
    testcase_gpt_secure_prosumer();
}
