/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc https://github.com/syncsynchalt/illustrated-tls13
 * @remarks
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include "sample.hpp"

/**
 * see also
 *   test_captured_tls13
 *   test_captured_tls12
 *   test_captured_dtls12
 */
void test_use_pre_master_secret() {
    _test_case.begin("https://github.com/syncsynchalt/illustrated-tls13/captures/");

    /**
     * https://github.com/syncsynchalt/illustrated-tls13/captures/
     *   capture.pcap (wireshark capture file)
     *     TLS record(s) to hexadecimal stream
     *   keylog.txt (SSLKEYLOGFILE)
     *     https://www.ietf.org/archive/id/draft-thomson-tls-keylogfile-00.html
     *     https://tlswg.org/sslkeylogfile/draft-ietf-tls-keylogfile.html
     *
     * SSLKEYLOGFILE label              TLS traffic secret
     * SERVER_HANDSHAKE_TRAFFIC_SECRET  server_handshake_traffic_secret
     * CLIENT_HANDSHAKE_TRAFFIC_SECRET  client_handshake_traffic_secret
     * SERVER_TRAFFIC_SECRET_0          server_application_traffic_secret_0
     * CLIENT_TRAFFIC_SECRET_0          client_application_traffic_secret_0
     * EARLY_TRAFFIC_SECRET             client_early_traffic_secret
     * EXPORTER_SECRET                  exporter_master_secret
     */

    tls_session session;
    auto& protection = session.get_tls_protection();
    protection.use_pre_master_secret(true);
    // SERVER_HANDSHAKE_TRAFFIC_SECRET (server_handshake_traffic_secret)
    protection.set_item(server_handshake_traffic_secret,
                        base16_decode_rfc("23323da031634b241dd37d61032b62a4f450584d1f7f47983ba2f7cc0cdcc39a68f481f2b019f9403a3051908a5d1622"));
    // CLIENT_HANDSHAKE_TRAFFIC_SECRET (client_handshake_traffic_secret)
    protection.set_item(client_handshake_traffic_secret,
                        base16_decode_rfc("db89d2d6df0e84fed74a2288f8fd4d0959f790ff23946cdf4c26d85e51bebd42ae184501972f8d30c4a3e4a3693d0ef0"));
    // EXPORTER_SECRET
    protection.set_item(tls_secret_exp_master,
                        base16_decode_rfc("5da16dd8325dd8279e4535363384d9ad0dbe370538fc3ad74e53d533b77ac35ee072d56c90871344e6857ccb2efc9e14"));
    // SERVER_TRAFFIC_SECRET_0 (server_application_traffic_secret_0)
    protection.set_item(server_application_traffic_secret_0,
                        base16_decode_rfc("86c967fd7747a36a0685b4ed8d0e6b4c02b4ddaf3cd294aa44e9f6b0183bf911e89a189ba5dfd71fccffb5cc164901f8"));
    // CLIENT_TRAFFIC_SECRET_0 (client_application_traffic_secret_0)
    protection.set_item(client_application_traffic_secret_0,
                        std::move(base16_decode_rfc("9e47af27cb60d818a9ea7d233cb5ed4cc525fcd74614fb24b0ee59acb8e5aa7ff8d88b89792114208fec291a6fa96bad")));
    {
        const char* record =
            "16030100f8010000f40303000102030405060708090a0b0c0d0e0f101112131415161718191a1b1c1d1e1f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfc"
            "fdfeff000813021303130100ff010000a30000001800160000136578616d706c652e756c666865696d2e6e6574000b000403000102000a00160014001d0017001e0019001801000101"
            "010201030104002300000016000000170000000d001e001c040305030603080708080809080a080b080408050806040105010601002b0003020304002d00020101003300260024001d"
            "0020358072d6365880d1aeea329adf9121383851ed21a28e3b75e965d0d2cd166254";
        binary_t bin_record = std::move(base16_decode_rfc(record));
        dump_record("client hello", &session, from_client, bin_record);
    }
    {
        const char* record =
            "160303007a020000760303707172737475767778797a7b7c7d7e7f808182838485868788898a8b8c8d8e8f20e0e1e2e3e4e5e6e7e8e9eaebecedeeeff0f1f2f3f4f5f6f7f8f9fafbfc"
            "fdfeff130200002e002b0002030400330024001d00209fd7ad6dcff4298dd3f96d5b1b2af910a0535b1488d7f8fabb349a982880b61514030300010117030300176be02f9da7c2dc9d"
            "def56f2468b90adfa25101ab0344ae1703030343baf00a9be50f3f2307e726edcbdacbe4b18616449d46c6207af6e9953ee5d2411ba65d31feaf4f78764f2d693987186cc01329c187"
            "a5e4608e8d27b318e98dd94769f7739ce6768392caca8dcc597d77ec0d1272233785f6e69d6f43effa8e7905edfdc4037eee5933e990a7972f206913a31e8d04931366d3d8bcd6a4a4"
            "d647dd4bd80b0ff863ce3554833d744cf0e0b9c07cae726dd23f9953df1f1ce3aceb3b7230871e92310cfb2b098486f43538f8e82d8404e5c6c25f66a62ebe3c5f26232640e20a7691"
            "75ef83483cd81e6cb16e78dfad4c1b714b04b45f6ac8d1065ad18c13451c9055c47da300f93536ea56f531986d6492775393c4ccb095467092a0ec0b43ed7a0687cb470ce350917b0a"
            "c30c6e5c24725a78c45f9f5f29b6626867f6f79ce054273547b36df030bd24af10d632dba54fc4e890bd0586928c0206ca2e28e44e227a2d5063195935df38da8936092eef01e84cad"
            "2e49d62e470a6c7745f625ec39e4fc23329c79d1172876807c36d736ba42bb69b004ff55f93850dc33c1f98abb92858324c76ff1eb085db3c1fc50f74ec04442e622973ea707434187"
            "94c388140bb492d6294a0540e5a59cfae60ba0f14899fca71333315ea083a68e1d7c1e4cdc2f56bcd6119681a4adbc1bbf42afd806c3cbd42a076f545dee4e118d0b396754be2b042a"
            "685dd4727e89c0386a94d3cd6ecb9820e9d49afeed66c47e6fc243eabebbcb0b02453877f5ac5dbfbdf8db1052a3c994b224cd9aaaf56b026bb9efa2e01302b36401ab6494e7018d6e"
            "5b573bd38bcef023b1fc92946bbca0209ca5fa926b4970b1009103645cb1fcfe552311ff730558984370038fd2cce2a91fc74d6f3e3ea9f843eed356f6f82d35d03bc24b81b58ceb1a"
            "43ec9437e6f1e50eb6f555e321fd67c8332eb1b832aa8d795a27d479c6e27d5a61034683891903f66421d094e1b00a9a138d861e6f78a20ad3e1580054d2e305253c713a02fe1e28de"
            "ee7336246f6ae34331806b46b47b833c39b9d31cd300c2a6ed831399776d07f570eaf0059a2c68a5f3ae16b617404af7b7231a4d942758fc020b3f23ee8c15e36044cfd67cd640993b"
            "16207597fbf385ea7a4d99e8d456ff83d41f7b8b4f069b028a2a63a919a70e3a10e3084158faa5bafa30186c6b2f238eb530c73e170303011973719fce07ec2f6d3bba0292a0d40b27"
            "70c06a271799a53314f6f77fc95c5fe7b9a4329fd9548c670ebeea2f2d5c351dd9356ef2dcd52eb137bd3a676522f8cd0fb7560789ad7b0e3caba2e37e6b4199c6793b3346ed46cf74"
            "0a9fa1fec414dc715c415c60e575703ce6a34b70b5191aa6a61a18faff216c687ad8d17e12a7e99915a611bfc1a2befc15e6e94d784642e682fd17382a348c301056b940c984720040"
            "8bec56c81ea3d7217ab8e85a88715395899c90587f72e8ddd74b26d8edc1c7c837d9f2ebbc260962219038b05654a63a0b12999b4a8306a3ddcc0e17c53ba8f9c80363f7841354d291"
            "b4ace0c0f330c0fcd5aa9deef969ae8ab2d98da88ebb6ea80a3a11f00ea296a3232367ff075e1c66dd9cbedc471317030300451061de27e51c2c9f342911806f282b710c10632ca500"
            "6755880dbf7006002d0e84fed9adf27a43b5192303e4df5c285d58e3c76224078440c0742374744aecf28cf3182fd0";
        binary_t bin_record = std::move(base16_decode_rfc(record));
        dump_record("server hello ... server finished", &session, from_server, bin_record);
    }
    {
        const char* record =
            "14030300010117030300459ff9b063175177322a46dd9896f3c3bb820ab51743ebc25fdadd53454b73deb54cc7248d411a18bccf657a960824e9a19364837c350a69a88d4bf635c85e"
            "b874aebc9dfde8";
        binary_t bin_record = std::move(base16_decode_rfc(record));
        dump_record("change_cipher_spec ... client finished", &session, from_client, bin_record);
    }
    {
        const char* record = "1703030015828139cb7b73aaabf5b82fbf9a2961bcde10038a32";
        binary_t bin_record = std::move(base16_decode_rfc(record));
        dump_record("application_data (ping)", &session, from_client, bin_record);
    }
    {
        const char* record =
            "17030300ea382d8c19a47f4e8d9b0c510bc348db2cc99b241cd0d18b31d0ca1ac12dc1e303c58d0c7e9e27294c6b0e3198f7d319eb14622ec48b6ac8f866d7494fa775c880ff43ad4b"
            "1af53a03ca197795778fff2ffe1d3b99b34de782a76abfa840e6366cd7349d9bcff641f5e0dff95e40d72e09effe18ee64672cb96005404488ad1896c44a5fd174998e9b0094d8e6d8"
            "4d2929b7883dc9a3c3c7313a87293f31b61d24d99097c8853bfbeb95d1d01f99ca05b0501859cf6340e8377075970152fa94f5f5be2906e72a15e40836a41f4cd3dbe7d513c16e8861"
            "1d3eae9338d9db1f91ca3d5842602a610b43a463";
        binary_t bin_record = std::move(base16_decode_rfc(record));
        dump_record("application_data (new_session_ticket)", &session, from_server, bin_record);
    }
    {
        const char* record =
            "17030300ea38adfb1d01fd95a60385e8bbf1fd8dcb46709897e7d674c2f7370ec11d8e33eb4f4fe7f54bf4dc0b92fae7421c33c6453cebc073159610a09740ab2d056f8d51cfa26200"
            "7d401236dafc2f7292ff0cc886a4ef389f2ced1226c6b4dcf69d994ff9148ef969bc77d9433ab1d3a932542182829f889ad95f04c752f94ace57146a5d84b042bfb3485a64e7e957b0"
            "8980cd08baf9698b8929986d1174d4aa6dd7a7e8c086052c3c76d81934bdf59b966e392031f3471adebddddbe84fcf1ff408846ae9b28ca4a9e728844a493d80455d6eaff205b40a1e"
            "f18574efc0b96ad383afbd8dfc86f8087c1f7dc8";
        binary_t bin_record = std::move(base16_decode_rfc(record));
        dump_record("application_data (new_session_ticket)", &session, from_server, bin_record);
    }
    {
        const char* record = "17030300150cda85f1447ae23fa66d56f4c5408482b1b1d4c998";
        binary_t bin_record = std::move(base16_decode_rfc(record));
        dump_record("application_data (pong)", &session, from_server, bin_record);
    }
}
