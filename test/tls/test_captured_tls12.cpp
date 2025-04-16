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

// test/tls/tls12/tls12etm.pcapng
// Encrypt-then-MAC EtM
pcap_testvector capture_tls12etm[] = {
    // C->S, client_hello
    {
        from_client, "client_hello",
        "16 03 01 00 c0 01 00 00 bc 03 03 96 89 88 b1 0e"  // 0000
        "d8 d7 2b e8 7f ae a5 64 a0 d8 15 a4 62 f1 41 ca"  // 0010
        "80 19 ad c5 33 ae c9 89 15 2b ff 00 00 36 c0 2c"  // 0020
        "c0 30 00 9f cc a9 cc a8 cc aa c0 2b c0 2f 00 9e"  // 0030
        "c0 24 c0 28 00 6b c0 23 c0 27 00 67 c0 0a c0 14"  // 0040
        "00 39 c0 09 c0 13 00 33 00 9d 00 9c 00 3d 00 3c"  // 0050
        "00 35 00 2f 01 00 00 5d ff 01 00 01 00 00 0b 00"  // 0060
        "04 03 00 01 02 00 0a 00 0c 00 0a 00 1d 00 17 00"  // 0070
        "1e 00 19 00 18 00 23 00 00 00 16 00 00 00 17 00"  // 0080
        "00 00 0d 00 30 00 2e 04 03 05 03 06 03 08 07 08"  // 0090
        "08 08 1a 08 1b 08 1c 08 09 08 0a 08 0b 08 04 08"  // 00a0
        "05 08 06 04 01 05 01 06 01 03 03 03 01 03 02 04"  // 00b0
        "02 05 02 06 02"                                   // 00c0
    },
    // S->C, server_hello, certificate, server_key_exchange, server_hello_done
    {
        from_server, "server_hello, certificate, server_key_exchange, server_hello_done",
        "16 03 03 00 45 02 00 00 41 03 03 65 8b 66 a2 af"  // 0000
        "4e 1b 13 dd 8b 50 51 78 90 21 13 a5 bf b0 21 ee"  // 0010
        "8b 24 30 cf ab 97 20 b1 37 6d 63 00 c0 27 00 00"  // 0020
        "19 ff 01 00 01 00 00 0b 00 04 03 00 01 02 00 23"  // 0030
        "00 00 00 16 00 00 00 17 00 00 16 03 03 03 6a 0b"  // 0040
        "00 03 66 00 03 63 00 03 60 30 82 03 5c 30 82 02"  // 0050
        "44 a0 03 02 01 02 02 14 63 a6 71 10 79 d6 a6 48"  // 0060
        "59 da 67 a9 04 e8 e3 5f e2 03 a3 26 30 0d 06 09"  // 0070
        "2a 86 48 86 f7 0d 01 01 0b 05 00 30 59 31 0b 30"  // 0080
        "09 06 03 55 04 06 13 02 4b 52 31 0b 30 09 06 03"  // 0090
        "55 04 08 0c 02 47 47 31 0b 30 09 06 03 55 04 07"  // 00a0
        "0c 02 59 49 31 0d 30 0b 06 03 55 04 0a 0c 04 54"  // 00b0
        "65 73 74 31 0d 30 0b 06 03 55 04 0b 0c 04 54 65"  // 00c0
        "73 74 31 12 30 10 06 03 55 04 03 0c 09 54 65 73"  // 00d0
        "74 20 52 6f 6f 74 30 1e 17 0d 32 34 30 38 32 39"  // 00e0
        "30 36 32 37 31 37 5a 17 0d 32 35 30 38 32 39 30"  // 00f0
        "36 32 37 31 37 5a 30 54 31 0b 30 09 06 03 55 04"  // 0100
        "06 13 02 4b 52 31 0b 30 09 06 03 55 04 08 0c 02"  // 0110
        "47 47 31 0b 30 09 06 03 55 04 07 0c 02 59 49 31"  // 0120
        "0d 30 0b 06 03 55 04 0a 0c 04 54 65 73 74 31 0d"  // 0130
        "30 0b 06 03 55 04 0b 0c 04 54 65 73 74 31 0d 30"  // 0140
        "0b 06 03 55 04 03 0c 04 54 65 73 74 30 82 01 22"  // 0150
        "30 0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00 03"  // 0160
        "82 01 0f 00 30 82 01 0a 02 82 01 01 00 ad 9a 29"  // 0170
        "67 5f f3 a4 79 b4 c6 e6 32 73 d8 d7 ed 88 94 15"  // 0180
        "83 e4 31 00 04 6c b5 8c ac 87 ab 74 44 13 76 ca"  // 0190
        "0b 74 29 40 9e 97 2a 01 d7 8b 46 26 6e 19 35 4d"  // 01a0
        "c0 d3 b5 ea 0e 93 3a 06 e8 e5 85 b5 27 05 63 db"  // 01b0
        "28 b8 92 da 5a 14 39 0f da 68 6d 6f 0a fb 52 dc"  // 01c0
        "08 0f 54 d3 e4 a2 28 9d a0 71 50 82 e0 db ca d1"  // 01d0
        "94 dd 42 98 3a 09 33 a8 d9 ef fb d2 35 43 b1 22"  // 01e0
        "a2 be 41 6d ba 91 dc 0b 31 4e 88 f9 4d 9c 61 2d"  // 01f0
        "ec b2 13 0a c2 91 8e a2 d6 e9 40 b9 32 b9 80 8f"  // 0200
        "b3 18 a3 33 13 23 d5 d0 7e d9 d0 7f 93 e0 2d 4d"  // 0210
        "90 c5 58 24 56 d5 c9 10 13 4a b2 99 23 7d 34 b9"  // 0220
        "8e 97 19 69 6f ce c6 3f d6 17 a7 d2 43 e0 36 cb"  // 0230
        "51 7b 2f 18 8b c2 33 f8 57 cf d1 61 0b 7c ed 37"  // 0240
        "35 e3 13 7a 24 2e 77 08 c2 e3 d9 e6 17 d3 a5 c6"  // 0250
        "34 5a da 86 a7 f8 02 36 1d 66 63 cf e9 c0 3d 82"  // 0260
        "fb 39 a2 8d 92 01 4a 83 cf e2 76 3d 87 02 03 01"  // 0270
        "00 01 a3 21 30 1f 30 1d 06 03 55 1d 11 04 16 30"  // 0280
        "14 82 12 74 65 73 74 2e 70 72 69 6e 63 65 62 36"  // 0290
        "31 32 2e 70 65 30 0d 06 09 2a 86 48 86 f7 0d 01"  // 02a0
        "01 0b 05 00 03 82 01 01 00 00 a5 f5 54 18 ab ad"  // 02b0
        "36 38 c8 fc 0b 66 60 dd 9f 75 9d 86 5b 79 2f ee"  // 02c0
        "57 f1 79 1c 15 a1 34 23 d0 1c a9 58 51 a4 d0 08"  // 02d0
        "f5 d8 f7 49 e9 c5 b5 65 91 51 2d 6d e4 3b 0e 77"  // 02e0
        "02 1f 45 8e 34 e5 bb eb f6 9d df 4a 40 60 21 b3"  // 02f0
        "8e 16 33 3f f4 b6 90 d3 3c 34 ce e6 d9 47 07 a7"  // 0300
        "57 14 0c f9 78 0b 36 72 a9 88 07 07 93 b4 d7 fe"  // 0310
        "29 5e e8 41 37 20 a5 03 c7 97 cb 82 ca db 14 e5"  // 0320
        "8b 96 1f a9 e9 20 3d 6b 25 ae f4 89 4c 60 8d e9"  // 0330
        "14 33 47 4b 88 54 a2 47 19 81 c8 7b 0e 32 52 2b"  // 0340
        "91 88 ad 0f 6d 73 30 8c 00 af d5 fc 46 46 af 3a"  // 0350
        "c2 17 89 ec c8 83 ae da e6 69 63 e0 9c 84 22 c5"  // 0360
        "7a de e8 23 6b 53 9d 6f 94 d2 7f 5c be 1d 0c de"  // 0370
        "0e 07 0d 52 a5 43 8c e8 05 ef c0 ff f0 73 fa dc"  // 0380
        "5a 51 4c 24 09 65 45 7d ab 52 8b 7e 5d f0 fb de"  // 0390
        "a7 3d 43 c5 af 76 e3 6e f9 a1 dc 78 a2 bd 54 41"  // 03a0
        "04 99 e5 56 32 ba 02 fd 72 16 03 03 01 2c 0c 00"  // 03b0
        "01 28 03 00 1d 20 8e 93 3b 4c a7 02 61 06 89 0b"  // 03c0
        "e2 d0 3e 0e 05 64 a7 37 9e b8 b9 0b 5b 3d 68 2c"  // 03d0
        "55 f4 a5 ef 46 67 08 04 01 00 50 ec 45 47 75 24"  // 03e0
        "3b 9c af e9 2f 3a af 50 bb aa 85 f0 67 5c b6 cd"  // 03f0
        "12 e6 7d 01 1a 3f a5 f4 0a 38 a2 4b 7d 90 b1 3f"  // 0400
        "7e 41 3b c6 d2 e0 c6 97 39 6f 22 aa 2b ee 09 d6"  // 0410
        "83 b9 ab 77 c0 a4 63 e8 cb f2 0a 67 1d 72 71 b8"  // 0420
        "7a a9 36 b4 90 ad 6d 22 25 01 ee 52 3b ce b9 56"  // 0430
        "8b f6 46 38 cf d9 dc d5 30 8e 3c aa e8 05 d7 05"  // 0440
        "c4 bb 25 33 43 8f a7 5c 72 a6 c1 c1 f9 3d 89 a8"  // 0450
        "9c b2 15 86 82 11 0e 1f 9c 00 12 6f cd 64 01 57"  // 0460
        "08 fa 5a 85 f6 5a be 58 e4 18 20 79 d8 13 6a cf"  // 0470
        "9a 3a 81 b7 ba 08 e4 4c ed e6 53 f9 f9 a5 7d 25"  // 0480
        "27 b7 84 a2 73 86 83 fe 28 d5 50 c4 ad c6 c2 10"  // 0490
        "24 f7 89 ec b1 18 a7 75 84 ef d5 52 08 dc 6d 74"  // 04a0
        "0e 99 a7 2e 0b cf af 85 3b c7 15 a3 52 29 26 19"  // 04b0
        "d0 cf fc 29 f2 1d d8 59 b1 5d 4a 54 2b 9e 1e dd"  // 04c0
        "52 fe d8 74 a2 78 ca f5 1b c8 3a c1 06 16 ad 35"  // 04d0
        "4a 84 be 16 2b c6 10 a8 b2 f7 16 03 03 00 04 0e"  // 04e0
        "00 00 00"                                         // 04f0
    },
#if 0
    // C->S, client_key_exchange, change_cipher_spec, finished
    {
        from_client, "client_key_exchange, change_cipher_spec, finished",
        "16 03 03 00 25 10 00 00 21 20 86 be ac 52 20 97"  // 0000
        "62 d5 c1 50 61 5c 9b c5 ba b2 11 89 6c 70 a2 e8"  // 0010
        "21 27 b8 80 f4 a1 b1 03 3a 28 14 03 03 00 01 01"  // 0020
        "16 03 03 00 50 b2 08 4a 5b 1d d6 15 cd 05 6d 1f"  // 0030
        "28 8f b8 e5 7b 7e eb d2 6f bb 00 18 32 c0 6c de"  // 0040
        "4b 8f a4 77 10 43 71 e5 ba 2a 09 1b 70 3b bc 80"  // 0050
        "69 bc 97 bc 2d d0 d2 36 fa 30 89 55 3b 17 e9 6e"  // 0060
        "c6 a4 64 10 c0 00 2d ab 9e 5c e6 df b4 a8 53 9c"  // 0070
        "90 63 48 d9 ab"                                   // 0080
    },
    // S->C new_session_ticket, change_cipher_spec, finished
    {
        from_server, "new_session_ticket, change_cipher_spec, finished",
        "16 03 03 00 ba 04 00 00 b6 00 00 1c 20 00 b0 96"  // 0000
        "67 2d fe 2d c6 99 a8 e9 d1 0f 5a 23 4b 99 af 2a"  // 0010
        "f6 45 88 e7 d5 34 6c 9c 09 62 46 73 32 9a dc a9"  // 0020
        "e8 0b 1c f0 77 b2 e7 cf e8 a1 2c c9 39 34 31 9a"  // 0030
        "af b1 95 e3 b8 4d 78 96 d1 7d 12 4d c6 d7 72 34"  // 0040
        "1d 3c e5 56 07 f1 92 a2 4a ed 9e cb 0a b3 e6 ea"  // 0050
        "a5 4b fb 14 5e 2f 93 e6 0e 1b 04 9c c1 54 64 4b"  // 0060
        "c3 b5 d0 50 0a 59 19 9e 42 5a 7f e7 ac 80 f7 c7"  // 0070
        "2f 06 74 50 3d 5b 2d 34 a5 4f e6 2a 14 74 42 91"  // 0080
        "a0 4c 51 00 7a e1 41 e2 b5 c2 a0 8b 25 a6 8e 64"  // 0090
        "fd 4a 82 21 22 ff 76 eb 72 ce ed 26 80 d7 13 27"  // 00a0
        "48 cd d1 da 89 d8 fc d8 fe 47 0b 4c 5c 93 b0 14"  // 00b0
        "03 03 00 01 01 16 03 03 00 50 aa 69 b7 80 25 eb"  // 00c0
        "0b 3d f4 0c 35 dc 01 a8 95 fc d2 53 66 af 6b b1"  // 00d0
        "83 46 a7 27 5f 5c 48 2d 62 39 80 c2 b3 84 20 c1"  // 00e0
        "ea ba bb b2 08 2a 41 c9 e1 e1 29 a5 ce c9 a8 66"  // 00f0
        "eb f1 f8 ef e4 e5 62 86 be e2 8a b6 c6 93 42 92"  // 0100
        "4f 2b 76 91 e7 9e 40 f4 33 31"                    // 0110
    },
    // C->S application data
    {
        from_client, "application data",
        "17 03 03 00 40 94 b3 62 f1 1e 8d 44 5d 51 bb 33"  // 0000
        "6b bd 23 65 75 f8 7e b6 4f 32 e9 fe 23 16 a3 7f"  // 0010
        "05 5f 6f 54 66 49 a0 05 59 df e3 9d 94 d8 82 9f"  // 0020
        "85 e7 76 49 14 73 48 d7 e3 9e 02 e3 f6 20 f8 d7"  // 0030
        "b2 95 09 c0 6a"                                   // 0040
    },
    // C->S alert
    {
        from_client, "alert",
        "15 03 03 00 40 61 43 21 ca 8f 02 65 10 a4 d4 b4"  // 0000
        "4a 0c 85 41 9f cc c6 f6 95 4c 21 3e e2 13 12 6b"  // 0010
        "29 47 3e 3f d6 17 9f cd f2 81 0c 1b 6c ef 28 5c"  // 0020
        "d2 e7 1a 97 2f d0 96 ac 0e 98 f7 d3 ae ee 48 1b"  // 0030
        "c5 c1 7d b1 88"                                   // 0040
    },
    // S->C alert
    {
        from_server, "alert",
        "15 03 03 00 40 57 61 d6 68 76 c5 bd b4 bc 5d 3d"  // 0000
        "c6 67 3b db 44 96 67 0d 24 2e 67 6d 23 24 f5 75"  // 0010
        "4c 67 be e5 57 11 54 29 00 85 c6 0d 43 83 a6 67"  // 0020
        "fe b8 b2 58 a2 26 1b 9b ec dc eb 52 6e 49 c0 a1"  // 0030
        "1f 93 e5 d6 ea"                                   // 0040
    },
#endif
};

// test/tls/tls12/tls12mte.pcapng
pcap_testvector capture_tls12mte[] = {
    // C->S, client_hello
    {
        from_client, "client_hello",
        "16 03 03 00 cc 01 00 00 c8 03 03 88 06 aa f3 ba"  // 0000
        "b7 cf a0 06 49 7e f5 06 20 dd ae 53 20 bf 15 41"  // 0010
        "d2 d2 a9 7a fb 85 14 5a a1 d2 75 20 b4 81 ac d6"  // 0020
        "e0 a2 2e 0f a5 d6 0d b9 fd 2d 02 3c 32 fb 20 89"  // 0030
        "4a 64 af 87 4e 7a 68 4f df 4f 6f 5a 00 10 c0 23"  // 0040
        "c0 24 c0 27 c0 28 c0 2b c0 2c c0 2f c0 30 01 00"  // 0050
        "00 6f 00 0b 00 02 01 00 00 0a 00 0c 00 0a 00 1d"  // 0060
        "00 17 00 1e 00 19 00 18 00 0d 00 1e 00 1c 04 03"  // 0070
        "05 03 06 03 08 07 08 08 04 01 05 01 06 01 08 09"  // 0080
        "08 0a 08 0b 08 04 08 05 08 06 00 2b 00 03 02 03"  // 0090
        "03 00 2d 00 02 01 01 00 33 00 26 00 24 00 1d 00"  // 00a0
        "20 ab a4 8c ab ab 5b e5 92 54 cc 25 c8 b3 67 ae"  // 00b0
        "0d 35 8b 69 1f 3b 98 d0 4b 5c 67 3b 55 f0 d2 91"  // 00c0
        "57"                                               // 00d0
    },
    // S->C, server_hello, certificate, server_key_exchange, server_hello_done
    {
        from_server, "server_hello, certificate, server_key_exchange, server_hello_done",
        "16 03 03 00 54 02 00 00 50 03 03 e7 36 be 0b f5"  // 0000
        "e6 d9 ff ec 34 8b 1d 22 2e 5e 5f 0d d2 d4 a4 6c"  // 0010
        "99 ae 52 1d e3 54 08 88 72 ca ab 20 37 9e f9 6b"  // 0020
        "1c 03 10 52 81 88 10 c9 2b 67 f0 b7 f9 e0 5f 7b"  // 0030
        "d4 e2 e8 aa ed ff 4d 55 d8 7d a7 77 c0 27 00 00"  // 0040
        "08 00 0b 00 04 03 00 01 02 16 03 03 03 6a 0b 00"  // 0050
        "03 66 00 03 63 00 03 60 30 82 03 5c 30 82 02 44"  // 0060
        "a0 03 02 01 02 02 14 63 a6 71 10 79 d6 a6 48 59"  // 0070
        "da 67 a9 04 e8 e3 5f e2 03 a3 26 30 0d 06 09 2a"  // 0080
        "86 48 86 f7 0d 01 01 0b 05 00 30 59 31 0b 30 09"  // 0090
        "06 03 55 04 06 13 02 4b 52 31 0b 30 09 06 03 55"  // 00a0
        "04 08 0c 02 47 47 31 0b 30 09 06 03 55 04 07 0c"  // 00b0
        "02 59 49 31 0d 30 0b 06 03 55 04 0a 0c 04 54 65"  // 00c0
        "73 74 31 0d 30 0b 06 03 55 04 0b 0c 04 54 65 73"  // 00d0
        "74 31 12 30 10 06 03 55 04 03 0c 09 54 65 73 74"  // 00e0
        "20 52 6f 6f 74 30 1e 17 0d 32 34 30 38 32 39 30"  // 00f0
        "36 32 37 31 37 5a 17 0d 32 35 30 38 32 39 30 36"  // 0100
        "32 37 31 37 5a 30 54 31 0b 30 09 06 03 55 04 06"  // 0110
        "13 02 4b 52 31 0b 30 09 06 03 55 04 08 0c 02 47"  // 0120
        "47 31 0b 30 09 06 03 55 04 07 0c 02 59 49 31 0d"  // 0130
        "30 0b 06 03 55 04 0a 0c 04 54 65 73 74 31 0d 30"  // 0140
        "0b 06 03 55 04 0b 0c 04 54 65 73 74 31 0d 30 0b"  // 0150
        "06 03 55 04 03 0c 04 54 65 73 74 30 82 01 22 30"  // 0160
        "0d 06 09 2a 86 48 86 f7 0d 01 01 01 05 00 03 82"  // 0170
        "01 0f 00 30 82 01 0a 02 82 01 01 00 ad 9a 29 67"  // 0180
        "5f f3 a4 79 b4 c6 e6 32 73 d8 d7 ed 88 94 15 83"  // 0190
        "e4 31 00 04 6c b5 8c ac 87 ab 74 44 13 76 ca 0b"  // 01a0
        "74 29 40 9e 97 2a 01 d7 8b 46 26 6e 19 35 4d c0"  // 01b0
        "d3 b5 ea 0e 93 3a 06 e8 e5 85 b5 27 05 63 db 28"  // 01c0
        "b8 92 da 5a 14 39 0f da 68 6d 6f 0a fb 52 dc 08"  // 01d0
        "0f 54 d3 e4 a2 28 9d a0 71 50 82 e0 db ca d1 94"  // 01e0
        "dd 42 98 3a 09 33 a8 d9 ef fb d2 35 43 b1 22 a2"  // 01f0
        "be 41 6d ba 91 dc 0b 31 4e 88 f9 4d 9c 61 2d ec"  // 0200
        "b2 13 0a c2 91 8e a2 d6 e9 40 b9 32 b9 80 8f b3"  // 0210
        "18 a3 33 13 23 d5 d0 7e d9 d0 7f 93 e0 2d 4d 90"  // 0220
        "c5 58 24 56 d5 c9 10 13 4a b2 99 23 7d 34 b9 8e"  // 0230
        "97 19 69 6f ce c6 3f d6 17 a7 d2 43 e0 36 cb 51"  // 0240
        "7b 2f 18 8b c2 33 f8 57 cf d1 61 0b 7c ed 37 35"  // 0250
        "e3 13 7a 24 2e 77 08 c2 e3 d9 e6 17 d3 a5 c6 34"  // 0260
        "5a da 86 a7 f8 02 36 1d 66 63 cf e9 c0 3d 82 fb"  // 0270
        "39 a2 8d 92 01 4a 83 cf e2 76 3d 87 02 03 01 00"  // 0280
        "01 a3 21 30 1f 30 1d 06 03 55 1d 11 04 16 30 14"  // 0290
        "82 12 74 65 73 74 2e 70 72 69 6e 63 65 62 36 31"  // 02a0
        "32 2e 70 65 30 0d 06 09 2a 86 48 86 f7 0d 01 01"  // 02b0
        "0b 05 00 03 82 01 01 00 00 a5 f5 54 18 ab ad 36"  // 02c0
        "38 c8 fc 0b 66 60 dd 9f 75 9d 86 5b 79 2f ee 57"  // 02d0
        "f1 79 1c 15 a1 34 23 d0 1c a9 58 51 a4 d0 08 f5"  // 02e0
        "d8 f7 49 e9 c5 b5 65 91 51 2d 6d e4 3b 0e 77 02"  // 02f0
        "1f 45 8e 34 e5 bb eb f6 9d df 4a 40 60 21 b3 8e"  // 0300
        "16 33 3f f4 b6 90 d3 3c 34 ce e6 d9 47 07 a7 57"  // 0310
        "14 0c f9 78 0b 36 72 a9 88 07 07 93 b4 d7 fe 29"  // 0320
        "5e e8 41 37 20 a5 03 c7 97 cb 82 ca db 14 e5 8b"  // 0330
        "96 1f a9 e9 20 3d 6b 25 ae f4 89 4c 60 8d e9 14"  // 0340
        "33 47 4b 88 54 a2 47 19 81 c8 7b 0e 32 52 2b 91"  // 0350
        "88 ad 0f 6d 73 30 8c 00 af d5 fc 46 46 af 3a c2"  // 0360
        "17 89 ec c8 83 ae da e6 69 63 e0 9c 84 22 c5 7a"  // 0370
        "de e8 23 6b 53 9d 6f 94 d2 7f 5c be 1d 0c de 0e"  // 0380
        "07 0d 52 a5 43 8c e8 05 ef c0 ff f0 73 fa dc 5a"  // 0390
        "51 4c 24 09 65 45 7d ab 52 8b 7e 5d f0 fb de a7"  // 03a0
        "3d 43 c5 af 76 e3 6e f9 a1 dc 78 a2 bd 54 41 04"  // 03b0
        "99 e5 56 32 ba 02 fd 72 16 03 03 01 2c 0c 00 01"  // 03c0
        "28 03 00 1d 20 f4 29 00 ff 3d 69 88 1d a1 44 60"  // 03d0
        "74 0f ac 51 a0 4c b5 ef 3f fd eb ff 76 63 6e 9c"  // 03e0
        "5d fe 3d 31 2b 04 01 01 00 4d 94 81 0f dd 66 c6"  // 03f0
        "7a fd 9b b4 22 eb 76 b7 db 28 4b ad 39 00 d5 f7"  // 0400
        "e5 7a 41 db d9 30 72 b4 c5 b9 09 ed 75 c1 ed 72"  // 0410
        "e2 15 6f 3f d0 4b 81 46 fb 7a ae 8c c3 c3 10 16"  // 0420
        "f2 71 69 ce 4e d2 84 49 2c 40 37 0e b9 60 60 36"  // 0430
        "ce 66 2c 05 f1 a3 59 e5 6d 4d 06 bd 72 7d eb c2"  // 0440
        "72 2e 1b 55 85 51 1f 03 55 68 6d 6d a8 ea 96 be"  // 0450
        "a6 20 eb 08 24 e5 a8 86 18 0a 06 58 37 da 81 e0"  // 0460
        "ea 9e 05 6c 2c cf 76 4b 29 fe 52 f4 6a a6 fa b8"  // 0470
        "d9 81 db eb 08 db c4 80 c2 1d 04 b1 fb 7c 5c b2"  // 0480
        "73 bf 06 c8 61 7d 18 bb f8 2b 02 68 9b 52 e2 fa"  // 0490
        "ca 74 3d 07 dd eb 0c 59 24 61 c2 21 5e 09 12 4e"  // 04a0
        "db 7e 2e d4 d7 bc d6 2b 21 b7 d7 ce b1 65 f8 0e"  // 04b0
        "2f ec 8c 36 c4 5a 03 3a 13 57 6d 2b 15 df 65 29"  // 04c0
        "75 41 e0 1d a0 82 ba ee 12 45 8a e8 57 75 6d 85"  // 04d0
        "3e c2 d3 dc 5a 69 f7 d5 34 12 51 67 98 2d a0 f1"  // 04e0
        "81 41 12 1c f6 41 f1 a0 09 16 03 03 00 04 0e 00"  // 04f0
        "00 00"                                            // 0500
    },
    // C->S, client_key_exchange, change_cipher_spec, finished
    {
        from_client, "client_key_exchange, change_cipher_spec, finished",
        "16 03 03 00 25 10 00 00 21 20 c7 34 68 18 ac 64"  // 0000
        "38 c9 5a 9a 50 38 1d 70 0e 21 ca a9 0c 91 22 ea"  // 0010
        "8e 15 e6 bf cc aa dd 7e 80 23 14 03 03 00 01 01"  // 0020
        "16 03 03 00 50 03 b6 79 08 6a b0 11 61 c3 db 15"  // 0030
        "1d 62 b7 75 50 f1 e8 2e e2 82 85 1b 22 73 b6 05"  // 0040
        "df e8 c4 40 f8 86 b1 4d ce 29 32 f6 74 35 2f f5"  // 0050
        "3a f5 8c 60 0b bb 8e af 45 57 bd 31 66 3b 55 33"  // 0060
        "d1 59 57 3b 50 94 dc c4 9d 51 98 15 6b 9e 49 72"  // 0070
        "76 59 eb 23 f7"                                   // 0080
    },
    // S->C change_cipher_spec, finished
    {
        from_server, "change_cipher_spec, finished",
        "14 03 03 00 01 01 16 03 03 00 50 cb 3a 05 2d 43"  // 0000
        "3e e8 bb 9f 8a 50 d8 3d 97 b9 0f 44 e1 06 b3 e4"  // 0010
        "26 87 a7 37 14 d9 b4 e7 80 69 60 b0 c7 17 ce cb"  // 0020
        "aa 8e e9 3d a0 08 e3 8e 59 b7 52 67 96 c6 9f f2"  // 0030
        "f5 c7 c0 18 32 d2 27 9d cc 44 e1 b1 56 a8 1a 17"  // 0040
        "ae 8b 55 7e c2 b7 1b 3f 03 e2 ca"                 // 0050

    },
    // C->S application data
    {
        from_client, "application data",
        "17 03 03 00 40 a7 99 3a d1 45 c1 8e 6f 25 14 16"  // 0000
        "71 a3 56 d6 81 df 39 1e 62 10 68 9a 8e 7e bd 5a"  // 0010
        "4c 67 fa fa f4 9d 1e 9f 91 4d 11 d2 01 ff ac b6"  // 0020
        "08 97 91 45 ac 88 78 af be 99 af 03 a8 81 d2 2c"  // 0030
        "a4 fb ac 35 c8"                                   // 0040
    },
    // C->S alert
    {
        from_client, "alert",
        "15 03 03 00 40 48 61 45 6b a1 a0 c2 7a 29 d5 2e"  // 0000
        "13 26 53 9b 13 cc a1 5d ee ca ea af bb a6 15 7c"  // 0010
        "f7 0f d2 c0 38 c5 a1 be 8a 39 63 be af da b1 1a"  // 0020
        "61 20 62 7c d4 29 3b 0b 14 45 96 7e 5d 4f 21 24"  // 0030
        "2f 19 2e 34 23"                                   // 0040
    },
    // S->C alert
    {
        from_server, "alert",
        "15 03 03 00 40 06 ef 55 b7 23 a5 c9 61 8c 0e 76"  // 0000
        "89 3f 14 4f e3 e6 29 0c 39 99 f2 be a2 32 a8 f4"  // 0010
        "d0 fc 79 38 ef 2f e6 2d d8 9f c2 82 19 a5 04 95"  // 0020
        "31 04 b5 28 7f 4e 36 7c 74 40 4a eb fa fe c6 98"  // 0030
        "60 0c f4 a4 d6"                                   // 0040
    },
};

void test_captured_tls12() {
    return_t ret = errorcode_t::success;

    _test_case.begin("TLS 1.2 pre master secret encrypt_then_mac");
    {
        tls_session session_sclient(session_tls);
        auto& protection = session_sclient.get_tls_protection();

        // crypto_keychain keychain;
        // auto key = session_sclient.get_tls_protection().get_keyexchange();
        // keychain.load_file(&key, key_certfile, "server.crt", KID_TLS_SERVER_CERTIFICATE_PUBLIC);
        // keychain.load_file(&key, key_pemfile, "server.key", KID_TLS_SERVER_CERTIFICATE_PRIVATE);

        constexpr char constexpr_master_secret[] = "3a3847a4d20f9766ff81040b9db89f85f56b1b9526afc626c0138e5b89d62c74680af78ba4d827ee38989518845bc985";
        protection.use_pre_master_secret(true);
        protection.set_item(tls_secret_master, base16_decode(constexpr_master_secret));

        play_pcap(&session_sclient, capture_tls12etm, RTL_NUMBER_OF(capture_tls12etm));
    }

    _test_case.begin("TLS 1.2 pre master secret w/o encrypt_then_mac");
    {
        tls_session session_netclient(session_tls);
        auto& protection = session_netclient.get_tls_protection();

        constexpr char constexpr_master_secret[] = "1598a9701b35936119d3b114b9b4df696d3d0fbcd92ee122612b59cdf0752f392e3ff27b38b9b585aa60e09408833a36";
        protection.use_pre_master_secret(true);
        protection.set_item(tls_secret_master, base16_decode(constexpr_master_secret));

        play_pcap(&session_netclient, capture_tls12mte, RTL_NUMBER_OF(capture_tls12mte));
    }
}
