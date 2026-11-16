/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file   testcase_gpt.cpp
 * @author GPT
 * @desc   Test group dispatcher.
 */

void testcase_gpt_negotiation();
void testcase_gpt_certificate();
void testcase_gpt_record();
void testcase_gpt_early_data();
void testcase_gpt_session_ticket();
void testcase_gpt_psk();
void testcase_gpt_psk_offer();
void testcase_gpt_finished();

void testcase_gpt() {
    testcase_gpt_negotiation();
    testcase_gpt_certificate();
    testcase_gpt_record();
    testcase_gpt_early_data();
    testcase_gpt_session_ticket();
    testcase_gpt_psk();
    testcase_gpt_psk_offer();
    testcase_gpt_finished();
}
