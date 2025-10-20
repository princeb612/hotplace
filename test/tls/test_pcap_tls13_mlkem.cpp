/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 * @remarks
 *
 * Revision History
 * Date         Name                Description
 *
 */

#include "sample.hpp"

void test_pcap_tls13_mlkem() {
    // MLKEM

    {
        _test_case.begin("TLS 1.3 tls13_TLS_AES_128_CCM_SHA256_MLKEM512.pcapng");

        tls_session session(session_type_tls);

        auto sslkeylog = sslkeylog_importer::get_instance();
        sslkeylog->attach(&session);

        (*sslkeylog) << "SERVER_HANDSHAKE_TRAFFIC_SECRET 0eadc6a1788916e5199dc24ca980d304489f92e180c50c558cb2c5dcdce66f96 "
                        "0e7da5c8b6bf000c0599618bdc34b1ed628d287619665274da3bdc51d649627f";
        (*sslkeylog) << "EXPORTER_SECRET 0eadc6a1788916e5199dc24ca980d304489f92e180c50c558cb2c5dcdce66f96 "
                        "d0d84072fee9b483ab96bea1c5224dd75548fdb7083d8a2aa83e528f8c543442";
        (*sslkeylog) << "SERVER_TRAFFIC_SECRET_0 0eadc6a1788916e5199dc24ca980d304489f92e180c50c558cb2c5dcdce66f96 "
                        "159d5dfca44a8a66b980b4280b565df0004daafda1f99398a96780227ba83840";
        (*sslkeylog) << "CLIENT_HANDSHAKE_TRAFFIC_SECRET 0eadc6a1788916e5199dc24ca980d304489f92e180c50c558cb2c5dcdce66f96 "
                        "5953c3bec14ebeafe042191d554a335debe58cfb1a12b349aba7d2c2386020db";
        (*sslkeylog) << "CLIENT_TRAFFIC_SECRET_0 0eadc6a1788916e5199dc24ca980d304489f92e180c50c558cb2c5dcdce66f96 "
                        "c437c7abf792d31b89940c5c452ef89b78aa4a08edd9252bbcc2bfd1501f94c4";

        play_pcap(&session, pcap_tls13_aes128gcm_sha256_mlkem512, sizeof_pcap_tls13_aes128gcm_sha256_mlkem512);
    }

    {
        _test_case.begin("TLS 1.3 tls13_TLS_AES_128_CCM_SHA256_MLKEM768.pcapng");

        tls_session session(session_type_tls);

        auto sslkeylog = sslkeylog_importer::get_instance();
        sslkeylog->attach(&session);

        (*sslkeylog) << "SERVER_HANDSHAKE_TRAFFIC_SECRET 72f4fd6702bd475a94e1e80a91c9a8a2d7ed160f3445d30ee9959d9621f4ba2c "
                        "df6301988ab035b487e5f7b94742567adb3d0c399d9ea5ef8ede85368f211026";
        (*sslkeylog) << "EXPORTER_SECRET 72f4fd6702bd475a94e1e80a91c9a8a2d7ed160f3445d30ee9959d9621f4ba2c "
                        "4f0c0a4e1412f2c9bf7ba1aba347ec2fbcd624836c11f038ca2327fee4619c3b";
        (*sslkeylog) << "SERVER_TRAFFIC_SECRET_0 72f4fd6702bd475a94e1e80a91c9a8a2d7ed160f3445d30ee9959d9621f4ba2c "
                        "d6f113f4783f908cabdfda5c9cc26c113ab29e1b36dc01ebd14b78c19bd06737";
        (*sslkeylog) << "CLIENT_HANDSHAKE_TRAFFIC_SECRET 72f4fd6702bd475a94e1e80a91c9a8a2d7ed160f3445d30ee9959d9621f4ba2c "
                        "842cb1512334ce3c11a16dc48bbcb9b6509ce695fb2a5c776701cc02edfa8852";
        (*sslkeylog) << "CLIENT_TRAFFIC_SECRET_0 72f4fd6702bd475a94e1e80a91c9a8a2d7ed160f3445d30ee9959d9621f4ba2c "
                        "b214c1fd92038ccd71fa0c62d70c8b189bfce3660db3e941febf1d2d7b790f73";

        play_pcap(&session, pcap_tls13_aes128gcm_sha256_mlkem768, sizeof_pcap_tls13_aes128gcm_sha256_mlkem768);
    }

    {
        _test_case.begin("TLS 1.3 tls13_TLS_AES_128_CCM_SHA256_MLKEM1024.pcapng");

        tls_session session(session_type_tls);

        auto sslkeylog = sslkeylog_importer::get_instance();
        sslkeylog->attach(&session);

        (*sslkeylog) << "SERVER_HANDSHAKE_TRAFFIC_SECRET 00ab11e590762daa4d17567ffb8e53b2fe1ca569bd9b841d64d31fe130caa82e "
                        "4648aa6e38d1def505b7319ca1a525c926971a8010aed0b99b37f8c7512acf08";
        (*sslkeylog) << "EXPORTER_SECRET 00ab11e590762daa4d17567ffb8e53b2fe1ca569bd9b841d64d31fe130caa82e "
                        "483759ce74b327e5dc8fed0bb82cb63d36629fc805e629337ece3bff1f1b6c15";
        (*sslkeylog) << "SERVER_TRAFFIC_SECRET_0 00ab11e590762daa4d17567ffb8e53b2fe1ca569bd9b841d64d31fe130caa82e "
                        "58487cdf120f18d746383673fc83ddf186c38bb5e8aa5fc01f9f2014128bfb19";
        (*sslkeylog) << "CLIENT_HANDSHAKE_TRAFFIC_SECRET 00ab11e590762daa4d17567ffb8e53b2fe1ca569bd9b841d64d31fe130caa82e "
                        "84486b9a42215bf477b4a07a49bb32fb5b82393e243a0a7b552f1b8d39763637";
        (*sslkeylog) << "CLIENT_TRAFFIC_SECRET_0 00ab11e590762daa4d17567ffb8e53b2fe1ca569bd9b841d64d31fe130caa82e "
                        "9375babb3abaf98a471413230e4c13e9868ef6d18d3d253da4f0ae9b49628288";

        play_pcap(&session, pcap_tls13_aes128gcm_sha256_mlkem1024, sizeof_pcap_tls13_aes128gcm_sha256_mlkem1024);
    }

    // hybrid MLKEM

    {
        _test_case.begin("TLS 1.3 tls13_TLS_AES_128_CCM_SHA256_SecP256r1MLKEM768.pcapng");

        tls_session session(session_type_tls);

        auto sslkeylog = sslkeylog_importer::get_instance();
        sslkeylog->attach(&session);

        (*sslkeylog) << "SERVER_HANDSHAKE_TRAFFIC_SECRET a771772cd5024b8bdbebed457ae2b648df0e7a27fb10c0a139f25d54be8e36f7 "
                        "b05a5a2344e39bcffa03327ca5147269898ba61748b6091cbb1320b345175b2f";
        (*sslkeylog) << "EXPORTER_SECRET a771772cd5024b8bdbebed457ae2b648df0e7a27fb10c0a139f25d54be8e36f7 "
                        "16962036f3561161e5d15eebedeb2121ead12c44bad47d060d38e03f6fcb93eb";
        (*sslkeylog) << "SERVER_TRAFFIC_SECRET_0 a771772cd5024b8bdbebed457ae2b648df0e7a27fb10c0a139f25d54be8e36f7 "
                        "026747680ade14119d0395a1bd17112798646fde50574c727eace699c17d07d0";
        (*sslkeylog) << "CLIENT_HANDSHAKE_TRAFFIC_SECRET a771772cd5024b8bdbebed457ae2b648df0e7a27fb10c0a139f25d54be8e36f7 "
                        "d6a2333a654ed6d53d5c13dfa49c6a7a582c0dafb4678acf85d25b9ba1d68058";
        (*sslkeylog) << "CLIENT_TRAFFIC_SECRET_0 a771772cd5024b8bdbebed457ae2b648df0e7a27fb10c0a139f25d54be8e36f7 "
                        "d0282b4797220d75a32d2bb36f649ad1cdc3e2489b83df059dd86d588a13cc4d";

        play_pcap(&session, pcap_tls13_aes128gcm_sha256_secp256r1mlkem768, sizeof_pcap_tls13_aes128gcm_sha256_secp256r1mlkem768);
    }

    {
        _test_case.begin("TLS 1.3 tls13_TLS_AES_128_CCM_SHA256_X25519MLKEM768.pcapng");

        tls_session session(session_type_tls);

        auto sslkeylog = sslkeylog_importer::get_instance();
        sslkeylog->attach(&session);

        (*sslkeylog) << "SERVER_HANDSHAKE_TRAFFIC_SECRET eeff3b12b284e64c59ee3eb71ead214c28e552964939fddacd5cbb7b61d5fbb2 "
                        "b87a2fefb446a062ac376d1c3e64e0b4967528dd4599233be6c31e63039a67bb";
        (*sslkeylog) << "EXPORTER_SECRET eeff3b12b284e64c59ee3eb71ead214c28e552964939fddacd5cbb7b61d5fbb2 "
                        "2080b729b75e526e724ba4fb76d806fe48a8c9f0141d152f6910f3d9dbf3e2f6";
        (*sslkeylog) << "SERVER_TRAFFIC_SECRET_0 eeff3b12b284e64c59ee3eb71ead214c28e552964939fddacd5cbb7b61d5fbb2 "
                        "678afd939623d2d91132bd895087e40006e3a61818cfa5005eb3cd0a7e6748be";
        (*sslkeylog) << "CLIENT_HANDSHAKE_TRAFFIC_SECRET eeff3b12b284e64c59ee3eb71ead214c28e552964939fddacd5cbb7b61d5fbb2 "
                        "450b1a22afc24e238d00186e367309876a7e67e3d0a9844577e5d815cdabdbb8";
        (*sslkeylog) << "CLIENT_TRAFFIC_SECRET_0 eeff3b12b284e64c59ee3eb71ead214c28e552964939fddacd5cbb7b61d5fbb2 "
                        "1156d6830a41d7fe958cde2cf74ccb348d91f59c9a649b18ab803b26c23a2f54";

        play_pcap(&session, pcap_tls13_aes128gcm_sha256_x25519mlkem768, sizeof_pcap_tls13_aes128gcm_sha256_x25519mlkem768);
    }

    {
        _test_case.begin("TLS 1.3 tls13_TLS_AES_128_CCM_SHA256_SecP384r1MLKEM1024.pcapng");

        tls_session session(session_type_tls);

        auto sslkeylog = sslkeylog_importer::get_instance();
        sslkeylog->attach(&session);

        (*sslkeylog) << "SERVER_HANDSHAKE_TRAFFIC_SECRET 48d6db376538948c9ee64daded5ffe77e0f7a8a50cc17cd8456b9b7120936eae "
                        "908766c605ec30bbd84b7bbdc6b1d96164d330924385bfd37989debb4660f49f";
        (*sslkeylog) << "EXPORTER_SECRET 48d6db376538948c9ee64daded5ffe77e0f7a8a50cc17cd8456b9b7120936eae "
                        "876a1a9c117da419ac36ded9fd7b3a2693efd6743e28506fb32139a1d3a80ae7";
        (*sslkeylog) << "SERVER_TRAFFIC_SECRET_0 48d6db376538948c9ee64daded5ffe77e0f7a8a50cc17cd8456b9b7120936eae "
                        "f948b2e1694d480baa64b01cfb9693a732841ddc1217bb3109c4a3e720ecd969";
        (*sslkeylog) << "CLIENT_HANDSHAKE_TRAFFIC_SECRET 48d6db376538948c9ee64daded5ffe77e0f7a8a50cc17cd8456b9b7120936eae "
                        "23b203467279759446393407e9548fe4b905bdd7f57317c5f79c5835158b2f2d";
        (*sslkeylog) << "CLIENT_TRAFFIC_SECRET_0 48d6db376538948c9ee64daded5ffe77e0f7a8a50cc17cd8456b9b7120936eae "
                        "517b30b77ff6e84b383357ccadd583b2136598cb742efc13ebf04af7b5b67554";

        play_pcap(&session, pcap_tls13_aes128gcm_sha256_secp384r1mlkem1024, sizeof_pcap_tls13_aes128gcm_sha256_secp384r1mlkem1024);
    }

    // TLS 1.3 key_share raw encoding
    _test_case.begin("TLS 1.3 keyshare MLKEM encoding");
#if OPENSSL_VERSION_NUMBER >= 0x30500000L
    struct testvector {
        const char *desc;
        const char *name;
        const char *keydata;
    } table[] = {
        {
            "tls13_TLS_AES_128_CCM_SHA256_MLKEM512.pcapng #4",
            "ML-KEM-512",
            "1f2b4292ebc62fcb597216161966494c75402a791368aa26c0c874dae536d273c7747cab386300dac6069a55485b156f71295453496c8a2bab26b1c810c961e22c8e9af8661ac45b0e"
            "f3be736c845dc2cf592338b9cc5574063714c9c6bf0b79d90a5ef7ec60cb8512442776f14b67e6e47f7a4c553b814f044861e6c593240156666bc5db92548260897150c5b9828a84a6"
            "0ba3b4b478bbb495c70321826b77b53468e235a9209b4e811101c56b0e0096cdc65034fa9414ea49f6595933a9433747203f422da34385bac6866c61a8425294015227378613c2108f"
            "345824fb859c71e2b69e89545ee09a14750446e9ccc8caa8451035d7a91578b521d9c74431e754cd0a95a20940a154bbbf1b77444703887c61062305c0e0b78425ad8515013a565041"
            "fc438f21436e9750ed0271fed78936c430faf653949ccb4006c70469b42957c688ba4db3e842f21b2b780a40e6a8cb300b4bcd6a2de0206d67d62332b5c107c1c8fb8841fc90ab4fa0"
            "0969089afd5b3b12146fb8537be8e0aae7026f7511c1923766dc41372a637ded6a35734b16a7888ea6c8588141645cd11434c47fe504914af454b68c9e816b0bf4f1560d64a022892b"
            "0966129a6b45f3330add347f52c748e3c0446d198b2fd48a63dcb944db382f9159a4188b91676ac385c8a314c0d5c2330836a18fa9a00626458c69a1630b9766b9bd54f7783f523af7"
            "e1964ee52280827394179dda236aad70743d0c81542562f2a3bd6ca750631983b02559b5dbc640eb999c156bbf090506822c617c385c3c3e27a914e40a3c6020a837a2a5cc16212a57"
            "7ad4bba70a7bc38ab0bff3a0143f61032dc736b00c45fab2c5baf6b765dc4d2ad731a9959947d07822db605ecb449fa900e4b196a09a1219dcc4cb61ce46b2c8c831b091b51079a331"
            "e2811a5281cb022a8319047cd5111d3851b2f320c1b40093d3d61e36120e15334047c550f3947a27b15604d2a270e5084fc6af7fe96ce66778085cae0a473086e53d4b84b861eb4f2f"
            "cb80260a7313815c32f01525a78d29d693aa7b2bea6cb070b99c184a51afa1c34ffb623f618b329ae4f5e57e74de479d13bddb2e8cbf5a5f19d9952d19fccb970b5c52d4b191",
        },
        {
            "tls13_TLS_AES_128_CCM_SHA256_MLKEM768.pcapng #4",
            "ML-KEM-768",
            "ed5b6ab49b1da4a46611d3607348b4804261bed53df9ab75717249b35905311c7e9ddab56f3191f0ca3960e3b6ab300196b990bf1a06edb14df287551a2637116b7632683ed491b360"
            "8a1cb8904938109447585cdfe9625ffb5bd87b16127693fe536630404b6ad2857c305970185d002d6cf8c7543976090a5a2b8472abb59b976aa80d6a2ca4b0a8b694b80ee3731184fb"
            "6208e9a47a1088004d54e4ac2ab0c6cb07a12ce3da4fa2cb690db67a35d135bc423cdb9c103418bcf4f510f75bc98cea5f812738d8e23bdcb96b7549231505a8294b8e25a28d3e972c"
            "7333a4e0d874ac3602d294806d2924ddc33fa2255849e2533bdbb77fa1b82fa255719bc597f5b75de2611731195af548d5474795c743ffe50d331c71e1a7b6d076a003b8302092756e"
            "2a977f08619a615fbd923dc6939d06799571a610bda33995d90b268a48d34a54671839c24acebcf8cfcc7926059ccd596b0080e37cd638b4e3656eabdc54293744144447d0033dfddc"
            "4d812b173a067ed4eb4e25d335e9f3c9b62040516846c2110808dabfeaf46261fa820a63b15abb08e97091b178078b5a702372c1aa12787b174b5e937880f51bc103042fa27505ecc8"
            "23ea029e805c139500f7c319ea2c454cca63e9712e48b27299457c3a54a1697bbc02f6b4f9a064a9f58bf5f009de52477d252a5162749717678e366bebcc32f7739a6949ccf7608bcd"
            "6c594cec056cc75046b70d70563e60856c199aa1c5b475d42765f85c73c425075a15053217a0a0b787ddd5ca093947d40a0a75fa1de727ac65364f7c077c3d94bc3fb13d7fe625c277"
            "22da522ea3e701d9c0075d5706962a31cd376ba2273916f8aabe76b34580365b92c3be600e2167602f544ab3750a76983afdd479909722ec50c5feb7938202878fd4cd669275176cb8"
            "a76c43efc8101478b32d86720d6a0803e14f623acc8252c0b2775bc8c54a58b44e50d89b4aa1bc7394cfc758b03dc4bb6bd13ef57b03e00c5d2fac7b960a04a4e7a252629db3d4c622"
            "d2c4ebc920a294cafaecb9422a3d2a5072a8f25c4c3b8ac7e91a32e531a981a65ee95ac4e318bd83aed4540481a3c5aee54c89cb7d7814c27740c1865a990ef77378b83d6804c0c8b5"
            "5216fa10906634de1b481b84b5dc71a505f7b14eb020849769a54609af1c3387658886c73b0f1a231e614ae5e422d6c761b5b6bb87c10a8d8a53d1f305ae6023fbf5653e0a13d31bc5"
            "d574be8758855829ccfec337a191428939ca7ff9021072047be895cf04771b4c1b31bcbaa2d986c0a8440864a13a4185dfda7cca57267271440d246b0d56497754a112038c32f23f0c"
            "b715e5f65d59871af5d3567ee8382216b43f6262385b93de5245a3bc59b0b20f5a17b0fcca01d0dc568cc11cc0882512a60434a75fa259a286330778da3594e5279bd6566cb8a481f2"
            "b98fcb61c95699bb9aa672507e048b4c6a599d01631cc4d19e48328a9678ce108b56a27859fc6c586b926746351686288b0e02ad3cabab117219370657c2f0a92e923b9e39bdcec02a"
            "6ab8bb8693ac1772225d07b81d10a3fe4a88efa3040757cf2c954551bb2887db88b5e927d17c25d4304e308b9ce2f63887d9956206a1bf36bd1140217738c6b4983aab420baea99020"
            "0ac8053577b5002116f500d145829bea",
        },
        {
            "tls13_TLS_AES_128_CCM_SHA256_MLKEM1024.pcapng #4",
            "ML-KEM-1024",
            "c1736a5a5593764aba2384726be9465d532bff6a0f5cf75a1eb669879c257d640c922247f5b2aedc66ad21e8724610b771b6649c35beabbcaec38a4a2e48adee77567a48657525a87b"
            "fb982cb71f9825918bb42c3b2c23bbfb4bf4b27d9c36bd601739ad60175305ad4a80333726a5a1d84fed75a690f33cf829bd890b0a9b383fc030988748be61266380ea19aed0b76061"
            "421de4cd8b3b693c77a82f4213899179a514abf5eb1028eb3d8ea8811de7a7c0fa76b5a73cbc868e3fe848d6c97aadd3805ff38eda4b1760896690c6026fdb7f5846718089420d6478"
            "3a4c44fc18ca51010442144965758d1989b04540aaa0b217d93469c0c1cc373abf6dd24a193a2a73c6b5cd20069ab6cdd2ccc85543944f18a6693a3430568a51cb54762462d017759e"
            "2ba5ead246e31cb48ab216c1a711bfa93970f73bd9e723658bbc21f12e8a9b3fd6a97165177d738a38d0847c4b00c7a17635900c889abb54fc1a887a2b4ec2f50605b07ccacc838d8a"
            "5390ec288a83539d12494c676424ba83a6ebc4838bc271333bb30808e11545c365b54ee4cbd5e8915aa641c1554aef5a431975abf18c5b64683ff7469b0eda2ab95c2146ac03657975"
            "08c7b40309838e3726271bb866aa9f0a565851b36dcba307bc02c8f7ab70a1d3ce4ec4c54d29a672167fcfd7b5fe625cbbe69303c298db75317a262fff327ff36a3151aba4db071193"
            "e88614d45914a8c5283165440271defb1b7bec85a1754ba724bc2ea29bb6e89ac664bce453a012a3cdb6d9529e0a51bae63703a87550888ee2211d9370162d29174e66507a6b0efabc"
            "034c36a66f4270a6442e9913107db660a9f27697e39b3d5b63499794703618de80b582f18ac544c10894899bd790a3496b6e59312cd044ec6a5bc4e3c076b4b5bb2817e3d34cfa736f"
            "0fd2bc919ac1898271105012be41b8c8b54be4c062e4604659e645ec363424e9c696f92a2f61389ef11550098b8a790d5fb5a03f80bdca4aa19e4baa7a8522ca5a1b1fc8322fc86544"
            "28c46db1be448384777ca10422a695e28da2435012c39cebf0ccbda3578d5190d5600b6f097868d1a25424072bd22f61db71fe41716048407dd1ab4390c2e546bf14a7085bb4cb0f39"
            "898ccac1a56112ff0720823467211625a9a714fc7bb773a06419f722061858a0c63d57383255e463dbea656de62906e78f825972c7952ddb437e9c8c8c26dcb67c1bb533c685965814"
            "ac21575743c5b5e8c1aadc532f2120c0368709111029b88ab9962286f55d36730320d4ca89e228d434408dac804e9a23e9c20f937bb5f4a09b6c5bc80882785a93a95f940f5e029fab"
            "d01b99081e1c3055aefa004d695249da673765ca750305f0d85ae75851918c6062cb345d2066043c896bd24d0f041b941c7098647f1fa16526d8c1f1f629bcfb1c28e8996d2892da88"
            "4273034544ecb3973ab1f7a7baa8609f95f7cada0cac449989b0ea197dc171e2d3638fe13efdd19024f188861613f8ba5b4fc34809c020089abc0959409dc0cc31d05b1cd3ce3c47c5"
            "7628077a341b90a9873d9a8b522949f291847b890c499c8656512ded1a494359083cfccdb45987aa640bd291899b1810fd00639df5af9f3713229c205711b93f0028f074705d2567ff"
            "2438c2f6683fa37ca150722040b8b0829274f9067f878087066bc98b62a0201cee92ca57a64f6679093981cd88457bfb293b6142c68a009c95f87c35c66f9965a3e1d7ccb78aa71eb0"
            "1971f6462d4327d446b38246adc77884bc9119e7a480ec0b1de4106fcc80358fe094b8bcc3ca5a4c8da164d30881c4c8af3ea2a4d9007e9310235401b11a2aa825b15d25d01e4db562"
            "ae0376022a80bad99dc690ae662478184b595d278f6f618c5d855bf578b16fc0cc8b86cf13f95ce16a6ce16a0f5e5881422a3387d3cfd883ca3a6546c26298e0aaceb216c6069a4bb3"
            "a6517085966d33980f75169e16ccc9185897c5a463a26c71ca37006428194b4a3fda98c3e9a24b338e5948a195d5735927c8f8254ef91476d834a3c23c62774915a52cac5b2ace13e5"
            "15557894a7d34d157cb3f427c6b367653dd633b967545678bf627674bbb920aab065a25752f9289ccbba5dd7422af163c2a4c851011a07dac2335229c56de65b840b327b2a91510491"
            "2ba33c45820b97016c12b2bc3e0e0c6b86af9226ecaf6dbe56a464ddc80f5776f5b6dc",
        },
    };

    return_t ret = errorcode_t::success;
    crypto_keychain keychain;
    for (size_t i = 0; i < RTL_NUMBER_OF(table); i++) {
        auto item = table + i;
        auto name = item->name;
        binary_t bin_pub = base16_decode(item->keydata);
        binary_t encode_pub;

        EVP_PKEY *pkey = nullptr;
        ret = keychain.pkey_decode_raw(nullptr, name, &pkey, bin_pub, key_encoding_pub_raw);
        _test_case.test(ret, __FUNCTION__, "decode %s", name);

        ret = keychain.pkey_encode_raw(nullptr, pkey, encode_pub, key_encoding_pub_raw);
        _test_case.test(ret, __FUNCTION__, "encode %s", name);
        _test_case.assert(bin_pub == encode_pub, __FUNCTION__, "confirm %s", name);

        _logger->writeln([&](basic_stream &dbs) -> void { dump_key(pkey, &dbs); });

        EVP_PKEY_free(pkey);
    }
#else
    _test_case.test(not_supported, __FUNCTION__, "openssl 3.5 required");
#endif
}
