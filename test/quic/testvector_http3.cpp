/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 *
 * Revision History
 * Date         Name                Description
 */

#include "sample.hpp"

// http3.pcapng
const testvector_http3_t pcap_http3[] = {
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 1200]
        //     1... .... = Header Form: Long Header (1)
        //     .1.. .... = Fixed Bit: True
        //     ..00 .... = Packet Type: Initial (0)
        //     [.... 00.. = Reserved: 0]
        //     [.... ..11 = Packet Number Length: 4 bytes (3)]
        //     Version: 1 (0x00000001)
        //     Destination Connection ID Length: 8
        //     Destination Connection ID: bd21df6a65e76e9e
        //     Source Connection ID Length: 0
        //     Token Length: 0
        //     Length: 1182
        //     [Packet Number: 0]
        //     Payload […]: ...
        //     CRYPTO
        //         Frame Type: CRYPTO (0x0000000000000006)
        //         Offset: 0
        //         Length: 280
        //         Crypto Data
        //         TLSv1.3 Record Layer: Handshake Protocol: Client Hello
        //             Handshake Protocol: Client Hello
        //     PADDING Length: 878
        //         Frame Type: PADDING (0x0000000000000000)
        //         [Padding Length: 878]
        from_client,
        prot_quic,
        "WIRESHARK#1 QUIC CRYPTO[CH], PADDING",
        "c4 00 00 00 01 08 bd 21 df 6a 65 e7 6e 9e 00 00"
        "44 9e bc 72 3e 7a c5 67 fb 41 d7 d1 8c 63 93 2d"
        "ed 1e ec ff 46 95 3d cf 65 f2 37 28 94 d3 23 29"
        "43 92 9f 09 5f 93 c4 06 fd 48 82 6f be 21 16 e1"
        "a9 d7 0d 57 b4 28 6e f6 b1 42 03 9e da 25 94 53"
        "cc a0 ee 9d 0e 88 82 ad 4f f6 3e 0d bb b0 75 b7"
        "06 57 43 ce da de 5f 92 c0 aa 45 10 72 7e 9d 98"
        "b2 34 29 4c 6c 3a 41 4b ba 34 75 7b ba ee db 2d"
        "12 f5 a1 9f ea e1 98 e9 94 00 f0 17 b0 7b 78 84"
        "bd 87 21 9e e2 50 a9 9f 8a 9e 7e c4 5c ad 0c f0"
        "07 f3 d4 7c 9a 03 40 f7 b8 18 86 29 b4 27 8e c4"
        "4a 25 70 48 13 b5 f7 b2 7e 25 f4 48 37 03 80 de"
        "3f 36 18 24 08 df e1 e0 71 d6 3d 84 1a f6 ca 1a"
        "00 69 26 02 2b 40 55 7e 2d 0c 1c 5a 1e 48 38 ca"
        "0b a1 84 93 f0 01 9d fc cd c0 9e 3a 3b ac b9 50"
        "4c 8b db 47 d5 a3 92 91 b9 2b 4d a8 20 33 43 d9"
        "e2 34 2c 07 80 bd 8a a5 de 49 75 5d 22 45 a7 d6"
        "98 b6 8a 97 1a df 4b 3f bb 11 82 8d 77 57 4f 2f"
        "f2 ed 11 72 20 98 c1 82 ff 70 b5 b3 39 41 c9 b6"
        "84 3f 60 e0 84 c2 af 12 eb 3d 74 00 4e 52 fd 91"
        "e9 79 00 f1 a4 38 cd 75 ae 0b 8d 81 8d 15 36 eb"
        "7f b9 25 d2 8a 91 d8 f2 d3 9b 7e f0 2f 11 4c d7"
        "4b dc ea d9 1c 6d d3 92 a9 fc 4f aa 40 d2 35 26"
        "13 49 ed a9 b8 af 99 d0 25 00 35 2e 59 80 76 df"
        "9f 9f 06 c6 d2 2a 6f 8c 0c 3c 15 af 6c 59 68 b3"
        "12 91 1a 6f 7b e0 7b f1 66 f6 53 f9 ce ed b6 53"
        "6d 65 83 7b 21 6b 08 76 71 92 de ce 5b 10 cb a7"
        "a2 ed e9 dc 16 2f 15 b7 81 76 38 2e 97 6c 66 3f"
        "27 67 82 1e 12 39 a7 36 0f 21 79 76 4a fc 98 83"
        "5d ae 4a 5d 8e 3b 58 34 3c 8a 82 91 50 5e ff ea"
        "d7 30 16 e3 13 96 ca 4e 71 ab d3 a6 20 fb e2 88"
        "f1 8b 23 14 9c e7 0f bf 5e 71 2c 90 3f 68 5d ba"
        "ea 12 6b c8 4f 8b cf 85 dc ba f8 a6 45 37 87 fd"
        "04 b9 a3 75 20 6d ff d6 27 2b 19 b7 95 95 29 8d"
        "7d bc e8 7e 1a f4 c5 39 f3 d8 9a 91 e4 90 ff f1"
        "da af 49 46 a9 75 70 a4 fb 57 77 b5 29 ff 3f fe"
        "3c 8f 25 fb 29 85 a9 49 9d f6 f5 d1 13 99 97 a1"
        "0c 03 bc 27 06 ee 12 41 61 0b 54 a5 50 c5 8c 60"
        "30 b9 ab 66 2e 4f 02 82 25 87 27 1a 98 57 5a c6"
        "b0 e1 c4 c6 e0 86 66 3a 95 63 7d ad 64 bc 3f 33"
        "c0 44 00 bd 35 04 08 5b b4 0f c0 91 f7 50 b2 73"
        "b8 27 7e 1a 92 92 8a a3 45 1c 00 c3 82 57 06 d5"
        "dc 34 ea f1 e0 06 16 a7 03 c8 d3 ba fa c6 23 5a"
        "aa a0 f7 6e 92 0a 0d ff b8 e7 ce 97 53 58 f2 34"
        "4c eb 95 b0 c1 95 14 74 32 e0 4d a4 e0 fb 57 be"
        "c0 ff 00 ad f9 7a 6b 03 f1 98 e2 07 57 d9 f6 e4"
        "ea da 10 1a 08 4a e0 e2 a6 78 2f 57 ba 4d fc 3e"
        "41 99 f7 72 3d 97 a8 b8 4b fa 2e 62 be be 76 80"
        "ea cf a4 24 83 0c 33 27 43 78 82 8a 8b f9 5a 26"
        "8c c2 d7 57 7f 3c cc c7 3b f2 17 6a 77 86 79 b8"
        "0f 31 57 cd eb d4 e6 c4 26 7a e9 85 47 47 5f 3d"
        "7c 8b e1 ee 0d 77 56 2f 3f 4f 32 41 91 ee 6d 19"
        "cc 1b d6 39 a8 c8 ab 2e 11 cd 31 78 87 f1 60 73"
        "30 b5 80 b6 88 d9 11 85 ec 00 86 2e 60 e1 19 03"
        "fe f9 5f 3f 39 85 ac 22 d5 b6 78 73 35 8a e7 8a"
        "55 fd fe a0 1e 83 9b b4 cc 1d 62 b9 11 75 d4 01"
        "77 7d 3e e9 9a 71 e8 d1 18 8d 11 61 ad 48 3f 94"
        "95 8e 59 5e 39 a9 a2 ec 9e 13 3c 74 17 f3 8d 9a"
        "98 e4 33 02 13 97 1f e4 66 0d 55 7f 94 18 2e a2"
        "0e f2 70 4d 49 49 95 d6 98 58 f4 47 17 ce 3f b6"
        "47 61 60 a1 b0 44 82 2c 03 c7 cf b6 d9 40 a9 cf"
        "11 e9 a9 6a 79 52 53 b9 57 53 40 a0 50 92 a9 62"
        "95 bc d5 ae 9c 54 43 35 7a bd ff 0a b5 3b 29 e1"
        "01 c5 54 1f c2 b2 d5 87 8a e8 36 96 31 14 d3 e6"
        "41 7a f6 3a db 6b 66 89 d3 48 8e 81 db 00 e6 a0"
        "16 1a c3 c2 f8 13 29 62 ac 09 3f 32 e4 13 35 7e"
        "4d 10 c6 7b 32 13 58 16 26 a2 b7 30 f0 3e 70 e1"
        "85 09 37 0f d4 20 20 d5 95 b6 2b 7c 68 5e 34 a5"
        "87 4d 34 1c 77 08 58 6d f0 03 57 73 9e 01 f9 f0"
        "c3 50 47 c2 72 2e 37 44 b6 67 b5 fc 5c 1b 32 4d"
        "52 b8 b9 20 a4 58 23 c8 13 bd c9 d3 0f b2 30 6d"
        "93 c7 e0 18 b8 a6 bb 6b a0 3e fb 47 ac 14 73 ef"
        "a8 70 c5 fc a7 f2 0e d3 e7 e3 fb aa 4c 07 eb 58"
        "37 c0 17 a6 82 ee c6 6d 35 ec 0b 2b b5 67 50 31"
        "43 ca 26 d9 d3 31 f8 22 d7 8b bb a9 5a da 4a f2",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 1200]
        //     1... .... = Header Form: Long Header (1)
        //     .1.. .... = Fixed Bit: True
        //     ..00 .... = Packet Type: Initial (0)
        //     [.... 00.. = Reserved: 0]
        //     [.... ..00 = Packet Number Length: 1 bytes (0)]
        //     Version: 1 (0x00000001)
        //     Destination Connection ID Length: 0
        //     Source Connection ID Length: 8
        //     Source Connection ID: fd21df6a65e76e9e
        //     Token Length: 0
        //     Length: 1182
        //     [Packet Number: 1]
        //     Payload […]: ...
        //     ACK
        //         Frame Type: ACK (0x0000000000000002)
        //         Largest Acknowledged: 0
        //         ACK Delay: 0
        //         ACK Range Count: 0
        //         First ACK Range: 0
        //     CRYPTO
        //         Frame Type: CRYPTO (0x0000000000000006)
        //         Offset: 0
        //         Length: 90
        //         Crypto Data
        //         TLSv1.3 Record Layer: Handshake Protocol: Server Hello
        //             Handshake Protocol: Server Hello
        //     PADDING Length: 1066
        //         Frame Type: PADDING (0x0000000000000000)
        //         [Padding Length: 1066]
        from_server,
        prot_quic,
        "WIRESHARK#3 QUIC ACK, CRYPTO[SH], PADDING",
        "ca 00 00 00 01 00 08 fd 21 df 6a 65 e7 6e 9e 00"
        "44 9e 4d fc 5a cb 03 85 3b f2 1d cd 09 30 b6 49"
        "39 25 7f 26 2c 36 87 fe 2d e0 5c ad 19 f9 85 1e"
        "b5 c8 6b 12 fd f0 ca 3e c2 d9 8e 8c 3b 82 ec bd"
        "02 46 cd 7a 8b 37 cc 55 07 54 51 0a c6 7d 8a b2"
        "e6 2b 22 33 4c ee ec 3a 10 5a fc 9d dd 47 85 26"
        "5a fd 06 dd e0 ca 74 10 1e fc 77 d7 a8 8f 53 f8"
        "7b 38 00 eb 59 18 28 a0 6d e9 c1 21 39 69 cf e9"
        "fa e6 82 d9 6d 0b 12 e9 75 ef 3b b2 a5 6c 92 38"
        "fc 28 f3 7b 38 3c e0 2c d7 e4 f0 5a 0f 2c cc d0"
        "9c 78 08 50 27 16 89 0b a4 82 7c c5 e3 3f 8b 81"
        "3b 6d 6f c6 6b 72 f9 45 9b 22 62 34 8b b9 ab ff"
        "49 58 8b 3e bc 5b 0c 24 d2 8a 8f 8a f8 b3 af 3f"
        "bf 86 9f 1d a8 a5 25 ac a6 f6 9e 34 40 33 9d 44"
        "12 f0 d9 dd dd ad 4c 8b 40 fe ba d0 0e 5e e5 bc"
        "61 65 a3 65 6c cb ea 3c 46 88 88 9e 67 bb 4a 1e"
        "4c ce fa 64 80 79 9a c1 dc a4 09 bd a7 07 d2 76"
        "ad 41 22 6f 3e 0a 85 df 0f be 9f 95 da 8c e0 ac"
        "70 02 25 6a 91 60 1b fb ef 9a 80 48 db f9 fe b7"
        "3b 8a 1b 99 12 4b 6b 1e 98 35 4a 48 cc 42 45 0a"
        "d9 fe 94 41 d3 aa 64 24 96 72 a5 70 b9 71 b0 fc"
        "b9 e8 39 bd 68 17 eb 39 a4 e2 e9 39 9a d7 15 67"
        "ad c2 4f 57 a6 e1 c3 4f 0b 57 60 9f fd ce 8e f2"
        "7d 2d a2 d4 78 ba 77 d3 62 06 cb 58 cc 7d 4b 05"
        "a7 a4 dd 63 5d aa 8c e2 48 be d1 20 51 9d 42 63"
        "29 ab 16 f3 8f b8 73 34 4e 93 bf 51 41 f2 90 32"
        "25 4c 0a 43 39 21 5b 23 6e cc 7d ef 09 ca 82 36"
        "be b6 b7 b9 e8 c9 f3 02 1c 00 bb cb 1c be af 19"
        "69 33 a7 0f bf 9c 37 b1 45 a4 47 3b aa f7 59 01"
        "a1 67 67 e2 9d ae ba 2a 59 dc 81 b6 0d e3 f4 2e"
        "64 c0 85 14 37 14 87 00 db 99 d4 0a 71 9e 1f 1c"
        "27 9b 01 df 69 42 79 24 0e 0a f8 87 cc 43 10 64"
        "99 1e db b4 6e b9 13 5c ea c9 55 1d f0 60 68 dc"
        "c7 9d c9 11 17 4f f7 25 05 04 3f c4 b4 d9 6f 83"
        "c8 6b a9 54 8a 1d ef bb 4c 4a 94 b8 cd 8d ff 6c"
        "16 d7 dd e2 58 77 1f 76 a6 c7 d0 a9 dd bf ae f9"
        "81 6a 9f 47 f0 fb 9d be 91 59 4e f7 1a 07 d7 50"
        "d2 14 34 14 33 ff c5 e6 32 2d bd a4 d2 da cf 4e"
        "ca 6d 4f 1f f8 55 b1 21 6d 2d 9a 2a 3a 7c 07 3d"
        "34 2e 29 f8 19 4e 48 a4 9d ed 6a d4 75 8d ab b4"
        "1e 4a 62 fe f4 79 78 b4 a7 c0 83 42 c1 f8 b8 9f"
        "91 5a 60 ff 3a bd 05 61 5f 30 34 00 55 7c c2 c7"
        "44 7a 03 2c cc 5a 39 7f 15 63 43 0b 65 9c 73 25"
        "70 fe 94 cf e5 c0 bf 04 f1 7c ce 97 9a 6d 58 35"
        "a0 f2 c3 7e 0b 86 be f7 e2 9b 80 66 51 74 0a 1e"
        "5a 4d 34 17 f9 ba 61 26 16 ef 26 2e 72 f4 39 e5"
        "3e 35 12 82 f4 39 08 3c 3e 30 f4 08 96 6d 2b d0"
        "1c 0c 11 28 f4 ea 34 d4 69 b1 42 2c 78 0e 99 21"
        "6c b8 0b 09 19 62 4b 2c d1 22 99 43 e5 46 f7 e5"
        "8f 23 b9 0c 1d bf 27 18 84 a4 d1 6e 7e 9e c2 e6"
        "2c 56 b0 b9 59 10 f6 7a c7 a6 24 55 2b 04 8c 60"
        "47 f2 f5 a2 04 08 37 4a 42 6d d6 a6 91 8c 34 e4"
        "6a 1e 5f 58 db 3b 70 3f ee fd 27 ef 16 b8 6e 78"
        "ba be 0e 15 53 38 99 f8 79 f8 e1 c7 71 2b 31 97"
        "4a ab cf 22 d4 c5 2f 7c 70 2e 21 2d cf 8d 82 4e"
        "60 e5 d1 15 dd f3 a7 e2 ab cf bb eb ba 9a 97 70"
        "33 d1 27 09 a9 c9 fd 7e 58 b8 04 df 7d 77 18 e0"
        "61 ee c2 23 fb a7 b2 8f 69 08 fb cb a3 6b 03 cf"
        "70 19 41 c8 5e 24 fa a3 37 36 8b ca 3a bb f2 5e"
        "bb 2a 1a dc 07 3e f3 cc 6a 91 59 58 ef d2 c4 eb"
        "a2 b1 67 8f 5f 46 63 7f 8c 96 cf e6 2b 89 cc 91"
        "e0 b7 11 98 54 2a 5b 18 7b 43 3d 67 18 51 b6 e5"
        "1d 01 bb d1 85 85 0e 59 95 58 bf 61 2a 9c 78 4f"
        "7f 94 b7 06 83 ba b3 9b 48 2f ce 6b 37 44 e4 88"
        "40 2a 37 30 87 9c bb 98 46 96 70 12 2a f8 e3 1f"
        "4d ed 55 b6 fe c2 21 e0 f5 7c b0 70 b1 ba aa 45"
        "a9 8d b8 a4 c7 27 8e df f0 0d dd 3a 80 8d 5c e4"
        "fc 61 fa 14 03 63 b6 0b f0 03 a3 4e 95 a1 a7 b0"
        "ce fd 98 6d 90 c3 e7 40 b3 b6 3b 4a fe fd ab 0d"
        "fd 71 47 b6 cc 9c 46 9f 16 59 ad 37 a1 a3 d1 10"
        "f1 d7 8a 03 3f 34 c2 2b db 71 fa 83 13 c3 10 64"
        "d1 80 be d5 0b 87 7e f7 75 14 39 27 ad 04 5e de"
        "4d 73 42 5f 58 bb 31 93 c5 ee 61 1c e9 52 68 cb"
        "e6 01 b3 de 7c 2f cb 8a 08 9d b0 94 8b dc 45 f4"
        "cc f1 7c 11 3e f7 af e2 49 10 1e ca 26 cc 68 de",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 1200]
        //     1... .... = Header Form: Long Header (1)
        //     .1.. .... = Fixed Bit: True
        //     ..00 .... = Packet Type: Initial (0)
        //     [.... 00.. = Reserved: 0]
        //     [.... ..11 = Packet Number Length: 4 bytes (3)]
        //     Version: 1 (0x00000001)
        //     Destination Connection ID Length: 8
        //     Destination Connection ID: fd21df6a65e76e9e
        //     Source Connection ID Length: 0
        //     Token Length: 0
        //     Length: 1182
        //     [Packet Number: 1]
        //     Payload […]: ...
        //     ACK
        //         Frame Type: ACK (0x0000000000000002)
        //         Largest Acknowledged: 1
        //         ACK Delay: 0
        //         ACK Range Count: 0
        //         First ACK Range: 0
        //     PADDING Length: 1157
        //         Frame Type: PADDING (0x0000000000000000)
        //         [Padding Length: 1157]
        from_client,
        prot_quic,
        "WIRESHARK#4 QUIC ACK, PADDING",
        "cb 00 00 00 01 08 fd 21 df 6a 65 e7 6e 9e 00 00"
        "44 9e 16 24 a8 37 8f 2e a7 dc 3b f7 cf c9 8b af"
        "db d7 51 a1 ec 3a 56 9f 84 14 39 1c d9 4d c8 24"
        "f8 3e d0 28 0a 92 73 3f bf 81 6f 61 37 83 5c 26"
        "51 b0 9a 19 fd a7 65 13 1d ce a3 37 ef 54 db 70"
        "76 a7 08 d8 ec e1 19 bd 1e a6 08 6f 00 c4 f4 4e"
        "a6 0e 24 89 e3 a3 c4 f2 43 d4 d3 5d 37 f6 81 db"
        "15 6d e4 7b 6b 95 03 95 69 ff 12 1e dd ae 28 fc"
        "1c b7 02 6a 3b d4 c5 a9 4e 03 64 ba c2 cb 2d 4c"
        "de 56 f2 8f 0a 65 40 f5 9d 9d 1b cf 2b 89 cd a9"
        "b8 a1 7a 47 91 99 91 64 23 a0 d2 fe 1d 9c 06 03"
        "8c a0 42 f5 da 7b d5 5c ed 4e cb 53 e0 bc 70 b1"
        "36 4a 4b a1 0b 52 ad 31 7f 1a 2c d2 38 bc 08 43"
        "62 1e ba 93 2a 97 ab 37 d3 64 ca e1 05 fa 2f 35"
        "96 cf 0e ae e3 8b 51 5f 7d 1f ed 07 1b dd 09 d7"
        "58 63 28 a2 53 24 80 52 76 f9 29 00 7c 34 3f 4f"
        "ed 56 74 ad 1b bd 15 9e fb d5 88 0b 08 f5 90 af"
        "35 99 45 02 fb 60 ce 36 bc a6 41 04 c4 68 ec 08"
        "16 d1 80 fc 45 ce 87 9f f3 19 af 59 03 89 68 5f"
        "cb 7b 7d 40 a3 57 8f 52 47 8b f9 d4 65 c1 2e c1"
        "36 8b 54 51 1b 18 62 41 4d b9 4d 41 74 55 d1 a4"
        "f9 61 a3 f2 87 db bd 03 8a 07 21 d1 ef fd 40 e9"
        "e2 5d d8 e4 18 d1 51 22 b1 6b 49 6b d5 75 78 a5"
        "94 17 4e 1e 7d 22 4b 6c 48 20 1d ae 05 f9 23 be"
        "38 74 95 c6 57 5d 68 c4 e0 a5 55 c9 fe 04 ba 34"
        "67 ac 22 db 85 c0 af 5e 43 7f 93 15 c7 46 e2 0f"
        "8e 12 a0 c9 9c dd ee 18 e5 01 48 9c 21 e9 ef 17"
        "6a 70 1c b8 ca 5c ad 46 51 8f 02 da 22 2e 53 be"
        "4d a8 6c e9 3a 72 1d ea 06 a1 bb 4f 72 71 2a c8"
        "ca 7c b2 45 a9 0e 3e 96 03 5a b6 76 93 e1 d8 ce"
        "1a eb 71 d4 c3 7e 82 96 a1 c9 3c 59 c8 e0 3b f8"
        "59 9e 25 92 bc 30 d2 ad 0a 75 a1 30 a5 cd e9 8c"
        "87 8b 2f d4 c0 ad 13 52 b3 bd 5c a8 a3 b8 ea d6"
        "a5 99 2b 66 c8 67 0f e0 f2 f5 0b 5d ca 1a f5 32"
        "1c 3b 8d aa d9 93 93 dc c2 26 e3 21 9a f6 d6 c1"
        "11 62 af de 84 ce be 86 91 a3 3a a8 ac 88 b1 3c"
        "f5 6f 64 e3 71 8d c0 74 ba 56 f8 2c 51 aa 49 aa"
        "f7 a5 83 9e 45 64 63 bf 1a 93 25 89 45 5b 1a 96"
        "78 5b b8 e3 3e f2 5a f9 42 f3 74 a9 47 c4 ce 65"
        "ab 6a 0e 14 53 25 e1 06 a0 b2 06 50 c9 22 dc 50"
        "cd e1 2a 73 a1 79 28 8d 2a 97 14 ad 3c e2 ba 92"
        "9c 66 72 47 c8 b1 b4 2e 5c 43 f6 b2 d7 63 6a 9a"
        "49 6b 80 b9 39 3e 9c 05 54 c7 91 af 44 97 6f cc"
        "84 dd 9e 14 90 5d fa b9 27 1f 19 cd 5c 8c 7d 3e"
        "90 75 2c fb 6b 31 76 7e 58 0f 90 fb 26 53 9e 54"
        "19 6c ce 28 53 bd b9 b7 36 27 44 96 d6 4c e1 dc"
        "55 e2 b6 85 2e d9 cd af 09 34 aa 32 7c 3d 41 0e"
        "b3 09 58 a1 31 dd be 0b 73 fb e6 42 47 bc 32 10"
        "8a 4b 9c bf ee b8 31 66 cc 8f 3e 4a 53 e8 29 9e"
        "64 50 b0 ab 49 ae e7 58 5e b9 a2 ef c5 02 75 e5"
        "e7 cc f1 b0 b2 73 78 39 55 d3 5d d8 fd b5 33 ca"
        "b4 bc dd 24 07 4a 7f 34 c9 8f 93 83 9e 62 e0 b9"
        "c1 77 20 af b0 da 13 2b 7e 11 b6 b3 8e 26 32 0b"
        "d0 b7 0e 1e da a6 8a 53 4f dc 62 0a c8 9b a3 1f"
        "56 dd 88 75 f4 a2 b2 dc b9 a7 e9 b8 ef 10 f2 ef"
        "b5 7c 7c 6a a3 f2 b2 1f 58 c0 d7 90 d9 7b c7 42"
        "59 87 4b 4c 9a 03 60 12 b7 63 db 22 24 9b 6f 54"
        "9f a8 2c 93 e1 71 94 a0 89 df 02 90 b3 07 56 a9"
        "2e d0 1d c5 c5 50 fd 4d 6b b2 a3 a9 3d db 50 06"
        "91 8d cb 35 dc 55 e8 95 0a f1 4a f2 a9 f6 53 95"
        "7e 7b 8a bb 5c 6c 57 75 49 5c a8 85 c8 49 16 e3"
        "7c b2 8a 0c 44 6c ea 6e c2 89 09 b4 04 7f 7e 4b"
        "48 c3 aa 1c 42 1b 90 92 3b bf 1f 22 0f a6 b9 71"
        "93 5b 1c 4a 03 1e d3 00 a6 10 90 93 9e b8 54 1b"
        "0f 6d 3a 9e 6c 22 57 b7 6e 83 0c 3b 5d 05 de 56"
        "96 57 80 78 0d eb cb 37 a2 8a 3c 0f ab 70 07 b7"
        "0d 09 a1 04 bb 4f d6 60 28 ba 63 ad e2 ee e5 8e"
        "b9 3b 1a 2a 35 21 0b 57 62 c0 26 30 73 02 9a 5c"
        "05 0c 61 71 13 f3 eb 38 79 f7 02 7f 66 ee 91 5a"
        "b6 6f 02 2b 0f e5 0e 38 12 32 a3 9b d2 3d bb bf"
        "55 66 5d 44 44 4f 7b 50 b2 70 16 f1 a4 db cf 5c"
        "c2 ab 6b c6 b6 81 a1 68 fa 53 52 ba 31 73 19 19"
        "b3 c0 2e 1b fd fa 75 fa 37 98 ef 9a a1 5e 3a f7"
        "19 5d 03 24 00 7c 78 f3 89 0d 79 c9 ce 84 e2 f3"
        "bc 99 f0 ac 4c 91 3e 04 33 54 fd c2 97 dc ee 80",
    },
    {
        // TLSv1.3 Record Layer: Handshake Protocol: Client Hello
        //     Content Type: Handshake (22)
        //     Version: TLS 1.0 (0x0301)
        //     Length: 512
        //     Handshake Protocol: Client Hello
        //         Handshake Type: Client Hello (1)
        //         Length: 508
        //         Version: TLS 1.2 (0x0303)
        //         Random: 95bed2d24d72386f90f77864e5fdfa4ba00357955d70957456e3743e00fe6b8c
        //         Session ID Length: 32
        //         Session ID: 47a70c71a5e58dd33112e0eb8ff4497807690138585d881b62e0c73130ec140f
        //         Cipher Suites Length: 60
        //         Cipher Suites (30 suites)
        //         Compression Methods Length: 1
        //         Compression Methods (1 method)
        //         Extensions Length: 375
        //         Extension: renegotiation_info (len=1)
        //         Extension: server_name (len=19) name=www.google.com
        //         Extension: ec_point_formats (len=4)
        //         Extension: supported_groups (len=22)
        //         Extension: application_layer_protocol_negotiation (len=14)
        //         Extension: encrypt_then_mac (len=0)
        //         Extension: extended_master_secret (len=0)
        //         Extension: post_handshake_auth (len=0)
        //         Extension: signature_algorithms (len=48)
        //         Extension: supported_versions (len=5) TLS 1.3, TLS 1.2
        //         Extension: psk_key_exchange_modes (len=2)
        //         Extension: key_share (len=38) x25519
        //         Extension: compress_certificate (len=3)
        //         Extension: padding (len=163)
        from_client,
        prot_tls13,
        "WIRESHARK#7 TLS 1.3 CH",
        "16 03 01 02 00 01 00 01 fc 03 03 95 be d2 d2 4d"
        "72 38 6f 90 f7 78 64 e5 fd fa 4b a0 03 57 95 5d"
        "70 95 74 56 e3 74 3e 00 fe 6b 8c 20 47 a7 0c 71"
        "a5 e5 8d d3 31 12 e0 eb 8f f4 49 78 07 69 01 38"
        "58 5d 88 1b 62 e0 c7 31 30 ec 14 0f 00 3c 13 02"
        "13 03 13 01 c0 2c c0 30 00 9f cc a9 cc a8 cc aa"
        "c0 2b c0 2f 00 9e c0 24 c0 28 00 6b c0 23 c0 27"
        "00 67 c0 0a c0 14 00 39 c0 09 c0 13 00 33 00 9d"
        "00 9c 00 3d 00 3c 00 35 00 2f 01 00 01 77 ff 01"
        "00 01 00 00 00 00 13 00 11 00 00 0e 77 77 77 2e"
        "67 6f 6f 67 6c 65 2e 63 6f 6d 00 0b 00 04 03 00"
        "01 02 00 0a 00 16 00 14 00 1d 00 17 00 1e 00 19"
        "00 18 01 00 01 01 01 02 01 03 01 04 00 10 00 0e"
        "00 0c 02 68 32 08 68 74 74 70 2f 31 2e 31 00 16"
        "00 00 00 17 00 00 00 31 00 00 00 0d 00 30 00 2e"
        "04 03 05 03 06 03 08 07 08 08 08 1a 08 1b 08 1c"
        "08 09 08 0a 08 0b 08 04 08 05 08 06 04 01 05 01"
        "06 01 03 03 03 01 03 02 04 02 05 02 06 02 00 2b"
        "00 05 04 03 04 03 03 00 2d 00 02 01 01 00 33 00"
        "26 00 24 00 1d 00 20 f4 22 c8 11 95 3c f5 69 b5"
        "f0 d0 a7 66 be 2a d9 fb 0a ca be af 71 81 d3 91"
        "0d 52 f0 4c a6 65 78 00 1b 00 03 02 00 01 00 15"
        "00 a3 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        "00 00 00 00 00 00 00 00 00 00 00 00 00 00 00 00"
        "00 00 00 00 00",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 1200]
        //     1... .... = Header Form: Long Header (1)
        //     .1.. .... = Fixed Bit: True
        //     ..10 .... = Packet Type: Handshake (2)
        //     [.... 00.. = Reserved: 0]
        //     [.... ..00 = Packet Number Length: 1 bytes (0)]
        //     Version: 1 (0x00000001)
        //     Destination Connection ID Length: 0
        //     Source Connection ID Length: 8
        //     Source Connection ID: fd21df6a65e76e9e
        //     Length: 1183
        //     [Packet Number: 2]
        //     Payload […]: ...
        //     CRYPTO
        //         Frame Type: CRYPTO (0x0000000000000006)
        //         Offset: 0
        //         Length: 1162
        //         Crypto Data
        //         TLSv1.3 Record Layer: Handshake Protocol: Multiple Handshake Messages
        //             Handshake Protocol: Encrypted Extensions
        //                 Handshake Type: Encrypted Extensions (8)
        //                 Length: 161
        //                 Extensions Length: 159
        //                 Extension: server_name (len=0)
        //                 Extension: application_layer_protocol_negotiation (len=5)
        //                 Extension: quic_transport_parameters (len=142)
        //             Handshake Protocol: Certificate (fragment)
        //             Reassembled Handshake Message in frame: 14
        from_server,
        prot_quic,
        "WIRESHARK#8 QUIC CRYPTO[EE, CERT(fragment)]",
        "ec 00 00 00 01 00 08 fd 21 df 6a 65 e7 6e 9e 44"
        "9f da d0 8a 68 fd 69 54 a5 63 f8 ad 34 58 b5 e5"
        "62 2f 9b e4 00 d2 c8 a8 08 4c fe 0a 98 5c cf 2e"
        "65 8e 4b f5 c7 26 f8 ad 21 7e ae 80 bc fc 58 5c"
        "97 1d 01 58 78 29 08 ed 8a 2a 1c 48 6a 62 50 a7"
        "f8 31 c2 3c fc e5 ce 16 ee 95 61 03 96 76 2d af"
        "dc 81 39 70 55 40 fe 9e 90 dd d8 96 af 6c d4 5d"
        "76 ed 6f 77 33 cc a4 c6 4d 3c 43 8a 8d 1b b8 f2"
        "a8 a3 8e 10 d2 f2 7d 81 fd c4 9e a6 5b 49 e7 fd"
        "2b bc 72 cd a8 3a 3b 9b 18 2c f4 63 75 89 e7 bb"
        "92 7d 66 c0 1c fc 2a 77 25 3f ee e2 f7 4a ad 38"
        "d8 fb c1 aa 5b 98 4e ef e5 85 43 94 da c8 f1 68"
        "f8 3c 10 d9 67 94 43 59 ed 7f b5 0b 54 71 a3 a8"
        "39 36 3b 48 50 0d ef cd 51 9c c0 a3 0a 45 6a be"
        "8f 1e 9c 06 40 c4 b0 15 e0 d6 06 61 3e c1 6c e3"
        "c8 15 ce e4 2c da 92 3d 51 11 ba 95 df 38 82 b5"
        "02 7e 2a 41 38 b5 e3 32 6c 01 4f 16 45 1f 1e 2b"
        "e3 92 2b 77 99 19 e7 17 b8 de 4b 15 21 be 77 21"
        "a0 38 a3 e9 53 49 15 e9 41 66 07 10 8b 1c d4 f3"
        "c7 9c d0 a6 1f 9c 31 c9 01 26 1c e4 64 04 54 34"
        "7e 29 8a 11 2a 0f fc 94 44 96 86 b7 bd 71 a1 0e"
        "93 cb f7 8e 89 cf 9c 07 86 34 66 0b f8 f4 81 59"
        "ae b1 b6 0a 97 57 54 c0 b0 d5 c9 13 d9 36 18 6e"
        "41 41 c8 bb c5 36 d3 77 93 16 91 c8 65 28 35 8c"
        "65 bd 11 52 6e 6f cc 91 0e 3a 45 47 75 58 fb 79"
        "77 5f ee c7 6e 70 d5 47 da 9d cd 19 95 3e 52 11"
        "a4 51 d1 b5 bd c7 05 7f 66 35 9d 29 4b 91 52 8a"
        "e7 3f c6 d7 bb a4 15 21 16 af 57 21 d0 fb ab db"
        "b8 bf 20 31 e9 20 f1 dc 6d 7d ec 0b da 51 0a 5f"
        "62 ed b3 87 aa 64 18 e5 79 80 95 f0 c2 66 50 02"
        "7d b5 fe 21 c3 e7 8e b1 92 c8 6f 68 f9 29 41 af"
        "99 2c 25 02 e0 71 97 52 c4 66 9f 79 09 64 12 1c"
        "0f a7 78 b9 76 0a f0 45 85 39 f9 cf 0b ad a1 e2"
        "44 1c 4b df 31 b8 67 ad 36 53 f0 a2 e1 d7 fc c5"
        "f3 88 43 3a 03 87 d5 5d ae 18 8d dd ce 8d 85 56"
        "0b 12 c3 f9 af ff f8 10 93 ac 4f 8e 14 81 a3 54"
        "6a 05 fd 0c d4 b0 7c 99 6e 90 06 ef 1e 6b 15 c9"
        "d9 96 b7 0a 50 7e 7c a4 b1 fa 16 e8 3a 60 72 e6"
        "c3 5d b4 46 cf 5b 00 8e ab b8 bc a1 58 44 3c 55"
        "95 63 4f 94 14 32 38 93 34 82 6c 99 20 a5 a1 db"
        "d1 7d 56 2b 88 d0 dd e8 fb 1f ac a1 43 43 3c f3"
        "3d 95 ab f8 1b 47 85 87 28 e3 7a 17 3d c2 9b 18"
        "66 a6 c5 e4 0d c6 ce f7 e9 13 79 10 56 82 00 71"
        "a9 c6 76 6d f3 e6 d9 df fe 62 8e 30 7d 44 b3 2a"
        "43 ce cb 19 cc 03 86 7a 31 4c 06 e3 fa 9b 16 3c"
        "46 49 62 a2 4f c1 25 ba 88 ba dd 6c 9e 91 07 e0"
        "57 20 d6 79 69 17 b6 55 a0 85 ea d9 1a 15 64 de"
        "e4 0c d2 ad 21 78 5c 6d e3 19 ca dc ea e1 82 76"
        "e9 d8 f7 6b a4 dc 3f 86 ef 44 fc 8f 2c f9 cb 38"
        "e3 36 1b bd 3d 8e 6f 3a 9a 22 3a 6a 66 2e 8d ce"
        "7c 08 5e 7a 07 f0 34 38 8e 08 6f be c7 ba 1b 79"
        "78 71 1e 83 51 5a 0a 74 32 35 12 23 94 c0 ad 12"
        "89 fc 7a fe bd ef 32 ac 98 bc e0 8d c5 88 82 c1"
        "86 fa 15 fc ba f5 38 8e 8d 21 e9 7e ba d9 e3 11"
        "59 33 e0 55 07 fc 58 f3 11 02 e2 9e 3c 01 da a4"
        "ef 2f 97 0b 0c e6 30 75 55 55 e0 76 ba ff d1 65"
        "09 ce 3d 5e 4c 1f 03 d7 dd 5c f3 f0 f9 a3 d9 46"
        "26 e6 93 01 91 b8 e8 9e 89 19 30 eb a2 99 b8 44"
        "ba 12 8c a7 57 60 9e 7b 3b 1e cb 39 5a 10 e1 85"
        "0e 68 72 d4 56 7d 61 2a ce a5 c1 b0 04 90 d3 74"
        "89 a0 16 72 74 46 ac 64 0e cd 41 50 b5 a0 2a 9c"
        "d7 a5 88 71 1b 4e 69 e2 5f db 55 d8 30 33 c2 fe"
        "0b 69 f9 d7 3f 80 04 1e d2 96 90 d4 f3 4f 84 65"
        "cd 04 34 bf 5b 6a 25 07 57 0f 75 ea 09 ee de 8a"
        "9e 5f 3c ba d6 41 22 78 2f 72 11 9f 40 b6 5e f6"
        "b6 48 25 d7 19 61 59 02 b2 7d 10 3a 2c dc 67 1c"
        "91 22 02 e0 0c 87 c1 4a 10 d0 8b 47 1c 60 92 df"
        "c7 08 c3 d0 18 ad 01 59 68 9a ba 00 e2 35 c5 03"
        "2c 07 26 38 3e 49 74 c1 e3 66 9c 20 3a 33 8f 33"
        "13 19 65 56 3d dd ea 0d 14 f7 9d d2 a5 17 0e d5"
        "36 5e 2f 25 ad e0 fd 8d 58 a9 16 35 33 d9 ce f4"
        "8d 45 2b e0 57 30 08 ae 51 b1 d0 0d 19 da e8 3a"
        "72 9b ca f8 b9 a4 1a bb e5 f6 6c 07 a2 7d 6f 07"
        "70 8f 36 78 27 37 3b 58 9e 92 a0 38 d8 00 df c6"
        "b2 8c d5 ec e4 c6 1f fd 62 f2 e5 8d 74 15 21 0f",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 1200]
        //     1... .... = Header Form: Long Header (1)
        //     .1.. .... = Fixed Bit: True
        //     ..10 .... = Packet Type: Handshake (2)
        //     [.... 00.. = Reserved: 0]
        //     [.... ..00 = Packet Number Length: 1 bytes (0)]
        //     Version: 1 (0x00000001)
        //     Destination Connection ID Length: 0
        //     Source Connection ID Length: 8
        //     Source Connection ID: fd21df6a65e76e9e
        //     Length: 1183
        //     [Packet Number: 3]
        //     Payload […]: ...
        //     CRYPTO
        //         Frame Type: CRYPTO (0x0000000000000006)
        //         Offset: 1162
        //         Length: 1161
        //         Crypto Data
        //         TLSv1.3 Record Layer: Handshake Protocol: Certificate (fragment)
        //             Handshake Protocol: Certificate (fragment)
        //             Reassembled Handshake Message in frame: 14
        from_server,
        prot_quic,
        "WIRESHARK#9 QUIC CRYPTO[CERT(fragment)]",
        "e0 00 00 00 01 00 08 fd 21 df 6a 65 e7 6e 9e 44"
        "9f 0d ae 55 61 ed 12 ff 4b b6 4d 95 91 a2 61 08"
        "00 36 fa b4 6a 5a cf 3e 25 84 a9 8a f3 75 31 e8"
        "ec cd bc 3a 22 ef 04 59 1b 6d 6e 60 c9 7b 6a d8"
        "62 47 76 60 87 31 19 9c 2c 30 2a 7e ad 26 19 85"
        "12 bb bf d6 7f 1e 3d 7e a4 95 b5 6d b4 ec 8d 18"
        "a2 19 a6 c4 eb 5f 45 54 09 3d 22 20 e4 88 0c 41"
        "f3 c8 dd 86 be 50 87 72 c3 4e 39 db 61 7f 17 e5"
        "8f f2 f8 41 da 5f 16 46 ac c5 72 6b dc 04 35 7c"
        "69 37 ad 31 b5 fc 5c d3 f0 03 cd c4 87 a8 54 ed"
        "8d 05 7c 3a c3 34 45 e7 be b4 45 55 61 ca dd 3b"
        "c4 2b bc fa a4 7e 97 09 2f 83 5b c0 c6 9c 8a 15"
        "d2 c3 67 a9 18 a7 9b 20 e0 8e c6 c5 a4 55 3c 2a"
        "0f 49 a0 d2 94 27 6c d8 d6 c5 22 e3 12 5b a9 5a"
        "a1 67 91 15 af ed 0b 91 64 d9 be 95 5c 28 9b 08"
        "a4 89 b7 b3 9e 14 e3 26 ff c1 f9 af 47 3f b3 78"
        "5d 8a a3 d4 2c 11 a3 d2 8e 21 68 a3 bb 47 65 e2"
        "be 4c 2e 7c 00 55 a6 21 65 0e 6d a8 ee 60 d7 3a"
        "f3 43 ce ea fb 63 28 8d 2e cd 41 8b a9 89 65 c9"
        "91 e4 8a 6b 8b 05 41 8a 8a 75 21 05 9f b8 91 63"
        "e6 bc ac 38 49 c0 e7 fc bd 8f 1d 7e aa a5 e4 8e"
        "4b 40 8c a0 80 42 22 a8 38 bd d5 35 10 90 9d 44"
        "fb b9 24 70 e4 13 3f bc 62 98 5d 10 8f 36 77 31"
        "4d 3f bb b6 ee 1a e8 6f 48 ff 75 08 a8 e2 5f 18"
        "42 1d fa 9d 79 9d de 12 4e a2 ea cd 47 4f 01 92"
        "30 60 a1 e8 86 4d f8 b4 85 35 e3 97 1c 96 30 bc"
        "31 53 f5 c5 66 71 39 7b bc 44 06 9b 64 d6 2f 0b"
        "e1 c4 30 f5 c4 e8 f5 9a 76 0c 92 c3 67 af 14 13"
        "5b 5a 05 ba bd 22 54 2d e0 02 e6 d6 21 90 9a 4a"
        "17 dd ca 15 97 43 d0 8e 69 c8 8a ea 80 fa 74 1f"
        "ad e3 d0 c9 83 88 5c ed 12 07 81 0a fa 27 e6 a7"
        "52 2a 4f 67 ff 30 96 a9 92 71 b1 9d fb 1c f1 e7"
        "81 03 b0 0c 5a 50 42 b9 ae 9f 75 ab 66 d7 6f ed"
        "5d 51 e6 3d a6 12 8c 0f 95 a9 0d 88 87 58 c0 fb"
        "15 09 7a f8 bf 65 9e 66 7e 82 ec 12 67 f1 4d 1f"
        "57 07 73 57 3d 78 8f 65 17 ca a8 76 12 f7 6f ad"
        "f3 d1 7e 08 bb a0 46 29 3c 91 de e3 53 00 eb 96"
        "ac cd 6f 10 1f ca 15 4f b8 f4 eb ff df de 5a 29"
        "5e ba 0d 60 bb 4a 50 a2 67 e2 eb 4c 65 ac 80 20"
        "ad 13 8a d8 df 62 42 84 3e 96 5f fe 9c 7a 00 1c"
        "89 b6 b0 cf ec e6 1b 13 09 10 c1 04 b5 29 fa 9f"
        "ab fb a0 1e 0f c7 4d 75 ec e3 38 e4 e0 bf d6 04"
        "86 61 88 e1 e4 5d 9b 8a a8 a9 6e 92 ca 2b 68 09"
        "ba 92 78 12 78 c0 e6 0c e1 4a a6 df 98 dc 95 0d"
        "68 52 b2 e9 fc 38 64 3d 08 3a a1 dc 14 17 f1 7d"
        "a5 89 36 ad 67 28 c5 e1 c5 fc ba 79 c4 45 21 37"
        "dd c0 71 70 07 11 f5 bc b2 8a 71 68 83 bd a7 63"
        "07 8d 10 3f 53 18 7c db 72 65 2e 44 f9 ae 40 7a"
        "2e 28 11 67 55 c4 11 c0 56 ef 60 00 6e 62 7c f8"
        "dd 69 74 f8 7f c8 d7 ef 3c fe 39 e6 8a d7 a1 96"
        "f5 62 2a bd 3c ca 51 20 c3 34 fe de 07 b3 e0 ab"
        "69 26 2a 38 86 19 d7 0c 75 e6 f4 95 d6 75 15 f6"
        "43 2a 84 bb 23 46 8d 12 41 d3 df 6d 54 6f 40 16"
        "65 aa 01 28 cd a4 39 33 b9 cb 39 3c f6 5d 61 ed"
        "07 dc fe 1f 13 57 44 58 8c 46 1c 59 85 44 cc 73"
        "d8 e9 74 29 67 88 bd 6b fe 4e 0d 4d 84 f0 e3 fb"
        "a1 af 5a a4 fb ac 15 24 96 15 1a 84 6e e6 f0 79"
        "0c 2b f1 7a 69 1f 75 07 64 1c 34 8e 6d 7b 08 30"
        "e5 9c c9 16 ab 3d f7 3f 6b bb 5c e3 7a b3 1d 5d"
        "9b 21 b2 7f 6b 6b 64 9c 00 0c 90 b9 f5 5f e8 06"
        "c9 63 60 74 f1 99 27 af 53 c8 37 1f 5f 4d b8 99"
        "3b 21 83 ca 9a ad 03 6e 71 54 c0 62 af 54 d1 c8"
        "9b a4 39 e3 78 df 08 61 ab ba 27 17 e5 d6 05 03"
        "a3 2e 0b 74 4f 8c dd fd 02 1b 3f ca cf be 61 66"
        "91 dc e3 ca e7 5a 9a 8a b3 00 6b 43 07 e2 39 ca"
        "d7 7f d7 88 fc 45 af f9 97 59 3e 34 c9 7f de 2f"
        "cf 11 da aa df e1 f3 b4 53 21 18 65 2a fa 6c 2a"
        "29 84 28 0d c3 ed 7f c3 ff bd 2b a9 a7 34 0a 0d"
        "ee 96 b3 fa 26 40 73 2e 71 f0 5e 5d a5 ea 9c 6b"
        "70 bf df 60 e3 5e e8 7e 45 f4 73 cc e4 36 6b 43"
        "8a 88 97 4b 72 ea 59 9d 50 c3 bd c6 ce c6 a4 d5"
        "3c 8e 35 07 a0 ba 22 c8 6d c7 b6 52 b1 57 5c 94"
        "0a 55 8f bc 02 1c 7e 1d 9e 85 81 54 1f 22 d8 99"
        "1d d2 61 b6 55 76 25 dd e6 8f c6 e1 98 41 90 b3"
        "e2 3a 12 17 37 ac 23 d5 fc 18 8d 21 01 ac 16 da",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 41]
        //     1... .... = Header Form: Long Header (1)
        //     .1.. .... = Fixed Bit: True
        //     ..10 .... = Packet Type: Handshake (2)
        //     [.... 00.. = Reserved: 0]
        //     [.... ..11 = Packet Number Length: 4 bytes (3)]
        //     Version: 1 (0x00000001)
        //     Destination Connection ID Length: 8
        //     Destination Connection ID: fd21df6a65e76e9e
        //     Source Connection ID Length: 0
        //     Length: 25
        //     [Packet Number: 0]
        //     Payload: a5bce07e6181113a1a6a557d5053c4d006c4573571
        //     ACK
        //         Frame Type: ACK (0x0000000000000002)
        //         Largest Acknowledged: 2
        //         ACK Delay: 0
        //         ACK Range Count: 0
        //         First ACK Range: 0
        from_client,
        prot_quic,
        "WIRESHARK#10 QUIC ACK",
        "e8 00 00 00 01 08 fd 21 df 6a 65 e7 6e 9e 00 19"
        "1f 67 b2 f4 a5 bc e0 7e 61 81 11 3a 1a 6a 55 7d"
        "50 53 c4 d0 06 c4 57 35 71",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 41]
        //     1... .... = Header Form: Long Header (1)
        //     .1.. .... = Fixed Bit: True
        //     ..10 .... = Packet Type: Handshake (2)
        //     [.... 00.. = Reserved: 0]
        //     [.... ..11 = Packet Number Length: 4 bytes (3)]
        //     Version: 1 (0x00000001)
        //     Destination Connection ID Length: 8
        //     Destination Connection ID: fd21df6a65e76e9e
        //     Source Connection ID Length: 0
        //     Length: 25
        //     [Packet Number: 1]
        //     Payload: 933dc2377ba4f3f1090bad64f4676f98fcc3482d58
        //     ACK
        //         Frame Type: ACK (0x0000000000000002)
        //         Largest Acknowledged: 3
        //         ACK Delay: 0
        //         ACK Range Count: 0
        //         First ACK Range: 1
        from_client,
        prot_quic,
        "WIRESHARK#11 QUIC ACK",
        "ee 00 00 00 01 08 fd 21 df 6a 65 e7 6e 9e 00 19"
        "26 93 37 a7 93 3d c2 37 7b a4 f3 f1 09 0b ad 64"
        "f4 67 6f 98 fc c3 48 2d 58",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 1200]
        //     1... .... = Header Form: Long Header (1)
        //     .1.. .... = Fixed Bit: True
        //     ..10 .... = Packet Type: Handshake (2)
        //     [.... 00.. = Reserved: 0]
        //     [.... ..00 = Packet Number Length: 1 bytes (0)]
        //     Version: 1 (0x00000001)
        //     Destination Connection ID Length: 0
        //     Source Connection ID Length: 8
        //     Source Connection ID: fd21df6a65e76e9e
        //     Length: 1183
        //     [Packet Number: 4]
        //     Payload […]: ...
        //     CRYPTO
        //         Frame Type: CRYPTO (0x0000000000000006)
        //         Offset: 2323
        //         Length: 1161
        //         Crypto Data
        //         TLSv1.3 Record Layer: Handshake Protocol: Certificate (fragment)
        //             Handshake Protocol: Certificate (fragment)
        //             Reassembled Handshake Message in frame: 14
        from_server,
        prot_quic,
        "WIRESHARK#12 QUIC CRYPTO[CERT(fragment)]",
        "e5 00 00 00 01 00 08 fd 21 df 6a 65 e7 6e 9e 44"
        "9f 31 04 22 72 ad db fb ad 4c 97 2b 5e 9a a8 40"
        "38 14 8f 23 dd da 2a 9e 17 d8 5c 7b 1f 5b db 99"
        "5e ae b1 f8 0f 1e 48 17 b1 26 ef 84 4c 62 5e 3b"
        "5f 1c 20 1a f4 69 71 1d dd 27 49 79 3f cf 5c e5"
        "dc 36 13 df b7 de 55 2c d5 e4 66 94 b2 61 c0 1c"
        "41 fd 9b 3c 41 33 83 ae 3d ff 67 fe 70 f4 92 9a"
        "ac 1b 70 90 d4 e3 8b 23 04 6c 2e 32 89 9f c8 93"
        "7a 38 1d 8e e2 bb 3c f9 c7 72 a3 fd 96 27 52 53"
        "3a 2f ba 5e e0 ca 53 cb 5c 24 f6 c4 96 07 29 f2"
        "99 8a 66 e0 55 ad 2c b8 11 0b 82 b6 85 12 ee 8b"
        "4a 41 85 9d a3 4d 63 c5 cb 04 0d c5 29 33 03 4d"
        "7e 6d 05 d7 12 63 34 17 87 94 b5 36 59 bd 74 dd"
        "e3 ac 52 2b f0 22 a0 76 d3 c2 3b 05 35 a0 fb fc"
        "e8 27 02 5e 5b a4 89 11 78 f5 26 ee 8f 95 ee c1"
        "dd 28 b6 55 8f e8 f9 e5 b6 08 95 26 c8 6e 0a 60"
        "70 96 67 8e 06 75 6e 24 a9 ce 41 49 3a b9 03 7b"
        "aa 24 dc ab da 9b a5 4d 25 99 05 0c e1 3c bf 9c"
        "64 f0 1d 76 0f 4e dc 5d 32 52 cd 23 51 52 48 a1"
        "d6 1a 2f 5f 54 32 0b 59 66 b7 76 a5 d5 46 20 55"
        "6f 25 17 22 d7 05 e6 f9 98 93 f3 26 66 7f 17 74"
        "a4 61 69 22 78 af ff 26 6a 6c c3 67 88 c3 29 01"
        "10 da 26 ed 65 78 63 7c a6 c4 3f 4d 52 f7 c8 42"
        "66 e2 04 8f c5 84 6d 9f ca 47 1c 6b 0d 1f e5 5d"
        "16 6d 9b 4c 77 c5 ae 9a 5b c5 58 7b 32 e8 a1 c5"
        "78 11 52 b9 5c 42 c4 29 6d e5 fe 51 26 07 2a c3"
        "1b 34 1c cf d6 af 54 d2 9c 9a 37 d1 1a f3 a9 5d"
        "44 7d f0 7a be 44 9a 4b 6d fa ee d1 62 09 42 6d"
        "b0 86 d3 b0 e2 c4 1e 5a 96 4a a6 08 44 48 44 48"
        "01 a0 94 30 46 71 fb 6e cf 45 37 d5 47 79 47 5b"
        "c0 23 73 5d e3 79 74 9a f1 dd 41 aa 04 a3 7c b5"
        "b4 68 ec 2c 0e 89 04 66 4f 47 34 46 08 5e a8 a1"
        "3c 6d 4b 19 b5 4a 9c 33 ec 92 97 e4 d7 fa 33 37"
        "80 6d d0 61 6b c1 a8 bd 08 a2 3b 92 ba a2 19 c5"
        "90 66 c9 d3 6f 71 a0 5b 94 60 2f 26 a0 2e 61 3e"
        "84 f2 de 89 23 c7 f6 9e 09 10 29 11 5e fe 4f f2"
        "31 50 8b 5f 45 07 ed c0 8a 7c ee b7 86 72 da 24"
        "6d f9 55 81 5b ad 9c f3 31 0f a6 ef 19 06 df fc"
        "d0 67 50 41 45 c0 23 39 4d 80 33 cf 78 cd f5 bb"
        "4b a4 6d 59 76 cd 07 44 97 d4 c0 39 59 d1 34 b4"
        "3a 78 49 96 6e b2 62 f4 59 13 90 ed 7f 29 95 e9"
        "9e f5 68 87 7a d1 60 f6 2f 1f 18 8a b4 fb 9f 3e"
        "aa 98 b8 6b 90 52 33 7d 4d ed 01 5f b0 a4 7e a8"
        "7a 0d fb 9b 7c f3 4c 1a 73 15 54 d5 e0 20 99 b6"
        "02 e5 df 9a f1 ee d4 4a ea 20 a7 e8 c3 2c 8c 70"
        "9f 7c de 07 bf aa b0 d0 32 0c 1e c9 4b da 83 c9"
        "41 0f d6 f5 dd e0 dd d9 0a b0 71 0f 1a 6f 81 4c"
        "b7 a8 41 d7 2c 35 26 dc fd ef 40 78 3c 84 a0 fd"
        "15 46 11 47 42 89 4d 37 db 61 55 56 89 06 9c 7c"
        "fd 46 2d 98 9e 9b 8c f1 68 b2 3a 10 61 8f 2e d6"
        "59 da 47 60 91 d2 88 7d 36 f3 cf be dc 87 74 00"
        "53 18 d6 8d 21 ae 45 05 f6 98 c4 eb 0b f6 f2 29"
        "65 6d 7c cd 25 cc 92 77 b2 7f 57 5e e6 0c df d7"
        "72 11 b2 1e 5f 84 91 6a d3 99 3c dd 60 17 0e 0c"
        "c6 3c 60 44 38 6d 90 dd d8 52 67 d7 57 d8 ef d6"
        "81 c6 03 71 77 42 10 a5 b6 2b 2f fb 4d d9 b8 e2"
        "d7 c2 3f e0 0d df e2 2e 5b d0 3e 39 86 b1 af 8f"
        "5c 21 6e 7b 0d e6 ed 1a f9 35 9c f6 c8 45 8c 7e"
        "6b 42 7d 3a 35 95 cf 6b 3b 1e 0a 26 2f 01 2f 5f"
        "17 01 75 cc 2e ac 45 c1 ad 3e cb 89 25 b6 19 c5"
        "53 1e ab fe 00 ae a3 2d 02 45 37 cf 40 a0 2b 93"
        "a6 29 9c d5 eb ec 34 50 4b 50 9f 66 9e ca bc 70"
        "75 3b 94 0b 6c 19 b4 76 9e 10 b9 4f 16 04 17 54"
        "09 63 9e 25 67 56 d4 35 f5 21 e6 54 d2 7d 11 2f"
        "db f5 e3 f3 4b 77 81 f9 8b a9 d8 26 41 1d 60 39"
        "ad 20 0a 1f b7 79 8e 3c f0 70 7f b9 a0 40 ad 1a"
        "c3 b1 96 7f a7 1d dc ec 5a 71 f2 14 7b a8 d1 1c"
        "0d ee 48 ea 32 bd 29 aa f7 56 ef 36 b6 b6 61 d0"
        "7c 18 46 bb 28 85 50 41 e3 e0 f6 b3 63 12 eb 09"
        "be b8 47 e7 63 7d 7f dc 16 fb 80 68 d1 a4 99 c6"
        "e7 15 50 5b 8f 16 a2 b4 b3 74 50 b1 9b 32 c5 1f"
        "3f 8e 66 1b 5f 94 db b3 a6 b2 34 78 33 98 62 24"
        "c4 2d 1a 65 8c 23 8a f6 e0 4b f9 12 06 43 59 e3"
        "fb d5 43 8d a2 18 b4 72 ff 44 30 b4 bc 54 8b 21"
        "de 37 ea 27 1f 3a c9 12 b6 e5 5a a5 61 ea 75 6b",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 1200]
        //     1... .... = Header Form: Long Header (1)
        //     .1.. .... = Fixed Bit: True
        //     ..10 .... = Packet Type: Handshake (2)
        //     [.... 00.. = Reserved: 0]
        //     [.... ..00 = Packet Number Length: 1 bytes (0)]
        //     Version: 1 (0x00000001)
        //     Destination Connection ID Length: 0
        //     Source Connection ID Length: 8
        //     Source Connection ID: fd21df6a65e76e9e
        //     Length: 1183
        //     [Packet Number: 5]
        //     Payload […]: ...
        //     CRYPTO
        //         Frame Type: CRYPTO (0x0000000000000006)
        //         Offset: 3484
        //         Length: 1161
        //         Crypto Data
        //         TLSv1.3 Record Layer: Handshake Protocol: Certificate (fragment)
        //             Handshake Protocol: Certificate (fragment)
        //             Reassembled Handshake Message in frame: 14
        from_server,
        prot_quic,
        "WIRESHARK#13 QUIC CRYPTO[CERT(fragment)]",
        "ec 00 00 00 01 00 08 fd 21 df 6a 65 e7 6e 9e 44"
        "9f bf 12 99 14 ad 16 e2 72 3e fa 7d 03 2f da 9a"
        "78 af 39 2f 2c 30 53 ab 4a 16 56 10 f4 99 c7 57"
        "fb 63 c2 49 d0 43 01 ab aa 00 df 32 d1 3f 90 1e"
        "09 bd 43 5d 7b dc fa 66 aa 70 bb cb da 3d 95 4b"
        "56 70 04 74 40 33 46 40 4e 31 fc a3 a9 67 dc ae"
        "82 df c6 42 05 a8 ac 13 44 d4 0c c1 7b 5c b8 3e"
        "28 74 ee 4d f2 4f a8 0b d2 f5 91 d2 d8 0d a4 bb"
        "a8 6c 4b 14 15 cf 19 84 48 c5 d5 e9 cd 9e 7d e7"
        "f6 51 32 e8 28 14 a7 96 44 83 18 ca f7 a2 00 53"
        "dc f8 66 f4 19 a2 69 c9 7d ff f1 66 f8 26 78 29"
        "51 7f 08 fe d6 ff 1b 03 91 06 dd 79 7f 77 9a 13"
        "8b 0d 7a e7 0b 1d b6 f0 6c 3d 9d 34 4e ce eb 32"
        "e2 74 30 82 99 8e 82 91 be 0d cf 88 6f da 0c 18"
        "17 17 56 95 d9 ac 55 59 10 1a 6d 54 6d fb 75 27"
        "9d 6d 72 68 8a 3b 0e 63 52 9d 5a d4 6c 4f 90 61"
        "e5 67 91 8f 33 eb 86 71 97 11 72 66 de 8a e2 28"
        "a4 92 2a 1a 48 41 7a 21 93 af c8 92 5b f6 29 11"
        "65 17 b6 f2 37 d3 0c a3 32 a8 3e 20 0b 1b e4 69"
        "4c a0 37 13 50 7d 9f 19 a8 31 0e 47 55 d4 cb 66"
        "82 d4 e0 fc 61 96 23 ba 9a 34 19 80 3b 8c e6 8c"
        "00 15 51 a5 b3 fa 7f f7 24 6d 9f 84 8b 7d 55 2e"
        "e5 b4 cb 9e c5 b3 79 14 2f c7 2b 7c d0 fb f5 f2"
        "e2 4d 10 a1 d5 71 27 86 db db e7 33 ea a7 a0 c0"
        "82 08 b9 f4 df 61 fa ee 15 29 44 bb fe 01 89 34"
        "b2 fd 42 fb 1c 61 d5 1e 16 b9 1b 10 8e a4 5c 85"
        "01 76 0e 4e 76 d7 cf 05 07 ab 59 18 29 2b 5c 69"
        "e4 16 02 a8 47 ad 7b 89 bb 17 4b 32 01 8b 82 a2"
        "ae 03 39 ff ca 38 b4 37 77 3d 07 3f 5d da 14 b6"
        "64 db d1 5a e7 e1 d7 83 97 fa 51 f9 f2 59 af 1c"
        "34 75 e2 8b 28 91 10 07 2c 80 3e c6 c5 33 89 9a"
        "14 2c f2 3f 94 8f 73 f8 d1 70 fd cc 07 c1 32 a4"
        "70 cb 3a 7e 93 a6 0a 6f 5c 58 e4 3c 1c 88 16 b7"
        "8f 97 1e f8 4e 52 29 de 92 8b 94 8e bd 9d 04 39"
        "99 5d 79 b3 3c 0d 0a 8b a7 ec 36 5f d2 6c 46 47"
        "5f 2c 93 0d ee 78 b9 9b c8 fd ca 2f d2 b2 75 28"
        "b1 d3 1d 56 b8 5d 8f 06 aa 2e 8d 5d 90 75 61 72"
        "27 2e 5c 12 35 7d a2 a0 b9 27 ef 6c d5 bd ed 50"
        "78 1f ac 7b 6e b5 73 d1 5d 7d 75 93 1c 51 98 1e"
        "f4 a1 e8 ee 12 e4 0a d6 b8 b6 4b a3 d7 f9 64 02"
        "7a 54 2c 57 f3 7f 0f 75 06 96 41 8c 83 92 65 35"
        "15 e4 db eb ec a6 e6 f8 68 73 a3 2f d2 07 34 4b"
        "75 7f c6 d3 79 34 69 dd 68 12 fd bb 91 49 1d 48"
        "84 40 b7 75 06 fb 9e 79 1f 16 06 d4 d0 3c 93 23"
        "9a b0 91 9c 38 21 48 08 15 e0 28 cd 91 e0 45 09"
        "1d 1f 01 4a 8a 9d 9b 86 05 a2 07 67 1c e6 7b f9"
        "ce a5 d4 37 f0 e2 44 3f 5e 87 8d 69 39 79 24 d6"
        "31 7d 80 14 34 42 91 d4 dc 7b 99 ca 17 73 aa bf"
        "af fd 68 4c bc 8e af 70 fc ea 7e 60 3c 00 b0 b9"
        "d6 c2 c3 55 e0 5b 35 e4 03 43 60 32 d8 6d b3 df"
        "c2 19 4e a7 bd 23 d3 c7 a8 c3 c8 9e 89 a1 cd 7d"
        "a8 be d0 43 42 78 ca c9 ed cc 6a 64 80 03 ff e4"
        "9f 8a bb 95 a3 84 5d 87 68 72 c0 be 47 3d c6 b9"
        "f4 ea c3 72 67 4e 6e e0 1b ed 5d 39 ca d2 2d df"
        "ea 23 04 20 ae e5 c2 ce 2c ab 18 90 60 a2 d9 43"
        "ac ea 88 9d 19 47 99 7c 58 ea 37 b2 c5 a9 79 9d"
        "ae 6e 5e 37 61 8e 07 3b 12 10 2f 88 31 2d 5f 69"
        "ef 75 79 7c 38 87 ed 07 23 ba bc 92 aa a8 ae a6"
        "0c 88 23 44 28 95 be 16 24 ff bf cf 95 70 22 03"
        "18 2d 20 53 54 aa 2f 30 02 6d 15 4d a7 22 1e 95"
        "c0 db 58 fd 8b 72 ae 1f 53 38 66 57 66 a8 21 3f"
        "83 c4 23 91 36 4f 48 82 f7 96 c6 e7 54 d9 0e 75"
        "65 0a 8e 8e 80 59 15 66 47 d5 3f 23 c2 94 18 22"
        "5b 89 bb 04 4f 64 bc 2e 92 4f df 72 0a 31 05 45"
        "50 5b 91 97 b8 3b 0e e4 e4 47 39 85 99 c2 f7 40"
        "2e b1 19 10 27 08 e7 3c fc c1 3c 99 2c 09 58 60"
        "8a 57 76 54 69 c8 74 ac ad 3a eb 61 2d eb e0 24"
        "5f 28 1e c4 2c 27 f5 f7 d6 c9 55 4b 46 23 93 de"
        "28 00 5d 1a 4a 24 10 1f 70 1f 3d d6 9c 17 21 d2"
        "6a e3 30 ba 05 2b 9a 77 e5 ad 2a ac 77 27 52 16"
        "42 ad a5 44 d4 d1 bd b8 27 bd ab 8f fa 2f e8 69"
        "14 90 f1 c7 3b 60 c7 ba 76 56 35 65 ff ba 46 02"
        "11 64 a8 2e df de c6 f9 44 e9 2c df 52 47 c3 77"
        "fa 40 01 29 a2 dd fa 71 32 b4 6e 66 f8 6d ed ec"
        "d4 2b 44 ff 94 dd ba 25 80 b7 8d 5e ef b8 ce de",
    },
    {
        from_server,
        prot_quic,
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 721]
        //     1... .... = Header Form: Long Header (1)
        //     .1.. .... = Fixed Bit: True
        //     ..10 .... = Packet Type: Handshake (2)
        //     [.... 00.. = Reserved: 0]
        //     [.... ..00 = Packet Number Length: 1 bytes (0)]
        //     Version: 1 (0x00000001)
        //     Destination Connection ID Length: 0
        //     Source Connection ID Length: 8
        //     Source Connection ID: fd21df6a65e76e9e
        //     Length: 704
        //     [Packet Number: 6]
        //     Payload […]: ...
        //     CRYPTO
        //         Frame Type: CRYPTO (0x0000000000000006)
        //         Offset: 4645
        //         Length: 682
        //         Crypto Data
        //         TLSv1.3 Record Layer: Handshake Protocol: Multiple Handshake Messages
        //             Handshake Protocol: Certificate (last fragment)
        //             [5 Reassembled Handshake Fragments (5031 bytes): #8(997), #9(1161), #12(1161), #13(1161), #14(551)]
        //             Handshake Protocol: Certificate
        //                 Handshake Type: Certificate (11)
        //                 Length: 5027
        //                 Certificate Request Context Length: 0
        //                 Certificates Length: 5023
        //                 Certificates (5023 bytes)
        //             Handshake Protocol: Certificate Verify
        //                 Handshake Type: Certificate Verify (15)
        //                 Length: 75
        //                 Signature Algorithm: ecdsa_secp256r1_sha256 (0x0403)
        //                 Signature length: 71
        //                 Signature: ...
        //             Handshake Protocol: Finished
        //                 Handshake Type: Finished (20)
        //                 Length: 48
        //                 Verify Data
        "WIRESHARK#14 QUIC CRYPTO[CERT(fragment), CV, FIN], STREAM",
        "e9 00 00 00 01 00 08 fd 21 df 6a 65 e7 6e 9e 42"
        "c0 21 9f 0f e1 66 ee 02 6c 48 60 7c 3f ba 6e 88"
        "3f d8 03 21 6a d9 fa 34 13 a9 e3 2b e0 35 4f 48"
        "3e 8f 8d 5f 98 5c 4f 7f 6b 44 81 ed 68 28 61 08"
        "3e f7 83 c6 dc 9a c1 8a 46 21 a6 e0 2e c8 cc 4d"
        "e2 43 9c 18 a0 45 18 39 93 02 03 dc 75 3b ab e6"
        "ca 0c 89 2a cd c2 c1 31 49 a9 ff d9 46 18 32 22"
        "1b 47 c7 64 5b b2 71 5d 48 f7 8e 88 b9 97 40 52"
        "69 b8 47 52 72 75 3f a7 ef f8 9e 0c 5a 83 47 e0"
        "2f 08 79 ed 3e ee c0 4f 67 01 72 bb 13 99 a5 e6"
        "d8 16 46 ea 50 92 96 15 91 3d 5b b0 51 e3 21 f9"
        "45 36 0f fe d7 19 1f 9b 16 a3 45 2c 46 bc 08 11"
        "ad 34 42 63 80 f5 d9 2d 8b 35 35 55 9a b8 b4 03"
        "5d ed 5d 7c 74 51 9f 50 ae 9d 72 0e 79 ec 23 66"
        "b7 49 02 65 cc 3e 00 a5 30 57 4f fd 25 55 69 e7"
        "c6 7e 72 58 2a 26 b3 89 a7 a2 5e d5 8e 11 96 42"
        "d3 b5 92 c9 16 ea 20 00 da 06 a0 13 eb 87 e8 a8"
        "8a a9 e5 13 ea af d5 de 0f 4b 9e 67 d3 0b a6 8f"
        "06 49 e4 1e 87 ee aa d6 a9 3a 83 b7 29 a4 a6 30"
        "e2 66 c7 e7 5d ce b4 0c 94 c8 0f 82 ca 9e 72 8b"
        "75 48 b6 45 57 ac a9 c2 2f 56 a7 f7 71 f4 79 bd"
        "0f 2b 2a d8 64 7d 81 7e 3a 70 63 d4 5d a8 12 bc"
        "45 3f a2 24 cf 7a 80 a1 07 83 b4 eb c4 10 e0 9d"
        "50 f1 fc b5 59 52 cf 5d a3 4a af 52 74 2e 42 a8"
        "b9 aa 4c 56 5a f7 2d 97 9d 49 4a 2e e9 1f f6 74"
        "88 bd 3c 0e e2 2f 84 3d 46 40 bb 5b cd 45 4f 91"
        "fd 60 9a ec dd dc 0d 69 b7 43 fe b8 84 46 2d 1e"
        "c3 01 4c 21 6f a9 15 7f a3 a3 e1 c6 76 28 f1 f0"
        "a7 cd 06 49 8b 99 8d 05 cb 85 0b 78 bb 99 50 4d"
        "94 ae 81 6d 51 98 fe 93 e6 e7 c9 3d e4 d2 21 95"
        "56 0c 81 12 fa e3 27 f2 81 ed d7 1d b9 09 43 94"
        "68 7d b9 83 84 fb 12 c6 14 59 8e 51 2f db 78 2c"
        "e5 92 24 63 f7 09 e4 8a c1 a9 91 8e 92 8d 45 b7"
        "c0 37 ae 87 f6 5d 7f 31 23 f1 5d 60 40 8b 06 3e"
        "b3 88 93 ea 91 c2 63 0d 13 c4 2f f2 c5 26 6f 42"
        "96 f1 79 2f 5e af 10 53 b1 27 7a 93 2b 63 65 2b"
        "28 ac 83 c1 ce 54 d5 b2 0c 61 3a 0a e3 31 05 a1"
        "14 1c fe 4f af a4 6d f3 4b 96 90 15 09 6f 9c 9f"
        "3f 07 37 e2 ea ec 47 75 96 63 6e fe 2e c3 c8 bc"
        "cc 77 6b bb 20 2f f0 9c 8f e3 11 9c 12 a7 0b 7a"
        "b0 dd 8a fe 5d a3 5b 40 c6 b7 fe 70 f6 dd 5c 89"
        "7a 02 90 80 7a 15 f6 25 47 94 10 eb 2b 55 10 71"
        "ad 59 8b 77 cb 74 35 a6 b5 18 bd 0c 84 1d 23 6c"
        "4f 24 37 7b a8 07 30 bc 45 39 4e ea 72 8f be 1f"
        "a2 62 53 63 f8 40 5f 24 32 5d c4 d2 6c 4e e0 ac"
        "06"
        // QUIC IETF
        //     [Packet Length: 62]
        //     QUIC Short Header PKN=7
        //     STREAM id=3 fin=0 off=0 len=41 dir=Unidirectional origin=Server-initiated
        //         Frame Type: STREAM (0x0000000000000008)
        //         Stream ID: 3
        //         Stream Data: ...
        // short header, DCID omitted
        "4c f2 63 73 39 4a 31 5a dc c7 07 55 45 fc 67 15"
        "5d 91 95 03 a0 4b 64 84 d8 9c 4e cc 6b c6 dd cb"
        "bf fd d2 db f3 1e e1 e0 5c 79 18 51 a7 6b 1b 88"
        "b4 d5 7a 8e 4e 89 5b 10 63 db b2 24 df 57",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 41]
        //     1... .... = Header Form: Long Header (1)
        //     .1.. .... = Fixed Bit: True
        //     ..10 .... = Packet Type: Handshake (2)
        //     [.... 00.. = Reserved: 0]
        //     [.... ..11 = Packet Number Length: 4 bytes (3)]
        //     Version: 1 (0x00000001)
        //     Destination Connection ID Length: 8
        //     Destination Connection ID: fd21df6a65e76e9e
        //     Source Connection ID Length: 0
        //     Length: 25
        //     [Packet Number: 2]
        //     Payload: 3f00f8da26704bf489971e20f46a8dfeb19fb55e82
        //     ACK
        //         Frame Type: ACK (0x0000000000000002)
        //         Largest Acknowledged: 4
        //         ACK Delay: 0
        //         ACK Range Count: 0
        //         First ACK Range: 2
        from_client,
        prot_quic,
        "WIRESHARK#15 QUIC ACK",
        "e6 00 00 00 01 08 fd 21 df 6a 65 e7 6e 9e 00 19"
        "9f 21 9c 5c 3f 00 f8 da 26 70 4b f4 89 97 1e 20"
        "f4 6a 8d fe b1 9f b5 5e 82",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 41]
        //     1... .... = Header Form: Long Header (1)
        //     .1.. .... = Fixed Bit: True
        //     ..10 .... = Packet Type: Handshake (2)
        //     [.... 00.. = Reserved: 0]
        //     [.... ..11 = Packet Number Length: 4 bytes (3)]
        //     Version: 1 (0x00000001)
        //     Destination Connection ID Length: 8
        //     Destination Connection ID: fd21df6a65e76e9e
        //     Source Connection ID Length: 0
        //     Length: 25
        //     [Packet Number: 3]
        //     Payload: f46b2f01bf085b0334d7d648155c22e1b3a57fb25f
        //     ACK
        //         Frame Type: ACK (0x0000000000000002)
        //         Largest Acknowledged: 5
        //         ACK Delay: 0
        //         ACK Range Count: 0
        //         First ACK Range: 3
        from_client,
        prot_quic,
        "WIRESHARK#16 QUIC ACK",
        "ee 00 00 00 01 08 fd 21 df 6a 65 e7 6e 9e 00 19"
        "49 0f 79 91 f4 6b 2f 01 bf 08 5b 03 34 d7 d6 48"
        "15 5c 22 e1 b3 a5 7f b2 5f",
    },
    {
        from_client,
        prot_quic,
        "WIRESHARK#17 QUIC ACK, CRYPTO[FIN], ACK",
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 97]
        //     1... .... = Header Form: Long Header (1)
        //     .1.. .... = Fixed Bit: True
        //     ..10 .... = Packet Type: Handshake (2)
        //     [.... 00.. = Reserved: 0]
        //     [.... ..11 = Packet Number Length: 4 bytes (3)]
        //     Version: 1 (0x00000001)
        //     Destination Connection ID Length: 8
        //     Destination Connection ID: fd21df6a65e76e9e
        //     Source Connection ID Length: 0
        //     Length: 80
        //     [Packet Number: 4]
        //     Payload: ...
        //     ACK
        //         Frame Type: ACK (0x0000000000000002)
        //         Largest Acknowledged: 6
        //         ACK Delay: 0
        //         ACK Range Count: 0
        //         First ACK Range: 4
        //     CRYPTO
        //         Frame Type: CRYPTO (0x0000000000000006)
        //         Offset: 0
        //         Length: 52
        //         Crypto Data
        //         TLSv1.3 Record Layer: Handshake Protocol: Finished
        //             Handshake Protocol: Finished
        //                 Handshake Type: Finished (20)
        //                 Length: 48
        //                 Verify Data
        "ef 00 00 00 01 08 fd 21 df 6a 65 e7 6e 9e 00 40"
        "50 af bc a1 b0 ca 6f c0 34 2a 83 53 af 2a dc 97"
        "58 10 12 2d 80 cb ee a3 f6 8d d1 dd 78 a7 c5 8f"
        "63 73 9b 63 0f aa e3 da 63 d2 e1 1f 57 36 13 ed"
        "4e 46 e1 63 4b ec 1f b9 85 e7 fa f1 d3 e6 d1 4d"
        "a4 2e b7 e6 38 df e9 34 aa 87 66 dd 04 3d 62 cf"
        "57"
        // QUIC IETF
        //     [Packet Length: 35]
        //     QUIC Short Header DCID=fd21df6a65e76e9e PKN=0
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..11 = Packet Number Length: 4 bytes (3)]
        //         Destination Connection ID: fd21df6a65e76e9e
        //         [Packet Number: 0]
        //         Protected Payload: 626ad8756000824d638aff175bca68041e0c3d4bf9d5
        //     ACK
        //         Frame Type: ACK (0x0000000000000002)
        //         Largest Acknowledged: 7
        //         ACK Delay: 375
        //         ACK Range Count: 0
        //         First ACK Range: 0
        "46 fd 21 df 6a 65 e7 6e 9e 3d 9f aa 55 62 6a d8"
        "75 60 00 82 4d 63 8a ff 17 5b ca 68 04 1e 0c 3d"
        "4b f9 d5",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 47]
        //     QUIC Short Header DCID=fd21df6a65e76e9e PKN=1
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..11 = Packet Number Length: 4 bytes (3)]
        //         Destination Connection ID: fd21df6a65e76e9e
        //         [Packet Number: 1]
        //         Protected Payload: b90615efc618e68ffae07924b902e090fca7c5e5ce8f6c922b6a8710a1adfcf1bbb5
        //     STREAM id=2 fin=0 off=0 len=16 dir=Unidirectional origin=Client-initiated
        //         Frame Type: STREAM (0x0000000000000008)
        //         Stream ID: 2
        //         Stream Data: 00040d06ffffffffffffffff01000700
        from_client,
        prot_quic,
        "WIRESHARK#20 QUIC STREAM",
        "5b fd 21 df 6a 65 e7 6e 9e 47 cc 77 dd b9 06 15"
        "ef c6 18 e6 8f fa e0 79 24 b9 02 e0 90 fc a7 c5"
        "e5 ce 8f 6c 92 2b 6a 87 10 a1 ad fc f1 bb b5",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 32]
        //     QUIC Short Header DCID=fd21df6a65e76e9e PKN=2
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..11 = Packet Number Length: 4 bytes (3)]
        //         Destination Connection ID: fd21df6a65e76e9e
        //         [Packet Number: 2]
        //         Protected Payload: b652e94983c029e8c881be6069fa89b3cb40dd
        //     STREAM id=10 fin=0 off=0 len=1 dir=Unidirectional origin=Client-initiated
        //         Frame Type: STREAM (0x0000000000000008)
        //         Stream ID: 10
        //         Stream Data: 03
        from_client,
        prot_quic,
        "WIRESHARK#21 QUIC STREAM",
        "51 fd 21 df 6a 65 e7 6e 9e 7b c9 eb 92 b6 52 e9"
        "49 83 c0 29 e8 c8 81 be 60 69 fa 89 b3 cb 40 dd",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 32]
        //     QUIC Short Header DCID=fd21df6a65e76e9e PKN=3
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..11 = Packet Number Length: 4 bytes (3)]
        //         Destination Connection ID: fd21df6a65e76e9e
        //         [Packet Number: 3]
        //         Protected Payload: 94619f78e4bcd2947d540aaefe68aa11119c14
        //     STREAM id=6 fin=0 off=0 len=1 dir=Unidirectional origin=Client-initiated
        //         Frame Type: STREAM (0x0000000000000008)
        //         Stream ID: 6
        //         Stream Data: 02
        from_client,
        prot_quic,
        "WIRESHARK#22 QUIC STREAM",
        "41 fd 21 df 6a 65 e7 6e 9e 41 6a ef 10 94 61 9f"
        "78 e4 bc d2 94 7d 54 0a ae fe 68 aa 11 11 9c 14",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 62]
        //     QUIC Short Header DCID=fd21df6a65e76e9e PKN=4
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..11 = Packet Number Length: 4 bytes (3)]
        //         Destination Connection ID: fd21df6a65e76e9e
        //         [Packet Number: 4]
        //         Protected Payload: ...
        //     STREAM id=6 fin=0 off=1 len=30 dir=Unidirectional origin=Client-initiated
        //         Frame Type: STREAM (0x000000000000000c)
        //         Stream ID: 6
        //         Offset: 1
        //         Stream Data: 3fe11fc00e7777772e676f6f676c652e636f6dff208825b650c3cb842b83
        from_client,
        prot_quic,
        "WIRESHARK#23 QUIC STREAM",
        "47 fd 21 df 6a 65 e7 6e 9e 47 b6 fc c9 64 55 52"
        "5d 22 f0 02 34 fc f7 4e 51 fa d3 9a 74 3f 55 b3"
        "ac 3f 96 e8 16 8d 15 47 21 61 f1 6a b7 58 45 21"
        "a8 3e dd 8f ad ec 0e f3 5d eb ce a1 0d bd",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 42]
        //     QUIC Short Header DCID=fd21df6a65e76e9e PKN=5
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..11 = Packet Number Length: 4 bytes (3)]
        //         Destination Connection ID: fd21df6a65e76e9e
        //         [Packet Number: 5]
        //         Protected Payload: cede183e76b1318d5959fcc1166b6baa8704fc4536fc06a9898cc3a2a9
        //     STREAM id=0 fin=1 off=0 len=10 dir=Bidirectional origin=Client-initiated
        //         Frame Type: STREAM (0x000000000000000b)
        //         Stream ID: 0
        //         Length: 10
        //         Stream Data: 01080381d1d710c111dd
        from_client,
        prot_quic,
        "WIRESHARK#24 QUIC STREAM",
        "49 fd 21 df 6a 65 e7 6e 9e 2d 17 0c 12 ce de 18"
        "3e 76 b1 31 8d 59 59 fc c1 16 6b 6b aa 87 04 fc"
        "45 36 fc 06 a9 89 8c c3 a2 a9",
    },
#if 0
    {
        from_server,
        prot_tls13,
        "WIRESHARK#25 TLS 1.3 SH, CCH",
        // Transport Layer Security
        //     TLSv1.3 Record Layer: Handshake Protocol: Server Hello
        //         Content Type: Handshake (22)
        //         Version: TLS 1.2 (0x0303)
        //         Length: 122
        //         Handshake Protocol: Server Hello
        //             Handshake Type: Server Hello (2)
        //             Length: 118
        //             Version: TLS 1.2 (0x0303)
        //             Random: 11c68c2c51138c19b986fa19a0f1eab318b566e57c309a447c94f90d89523fde
        //             Session ID Length: 32
        //             Session ID: 47a70c71a5e58dd33112e0eb8ff4497807690138585d881b62e0c73130ec140f
        //             Cipher Suite: TLS_AES_256_GCM_SHA384 (0x1302)
        //             Compression Method: null (0)
        //             Extensions Length: 46
        //             Extension: key_share (len=36) x25519
        //                 Type: key_share (51)
        //                 Length: 36
        //                 Key Share extension
        //                     Key Share Entry: Group: x25519, Key Exchange length: 32
        //                         Group: x25519 (29)
        //                         Key Exchange Length: 32
        //                         Key Exchange: 18356c1fc3b38c2e723bad93b0ec295a5dbea7f2861a739ea207f4a8b23e9956
        //             Extension: supported_versions (len=2) TLS 1.3
        //                 Type: supported_versions (43)
        //                 Length: 2
        //                 Supported Version: TLS 1.3 (0x0304)
        //             [JA3S Fullstring: 771,4866,51-43]
        //             [JA3S: 907bf3ecef1c987c889946b737b43de8]
        //     TLSv1.3 Record Layer: Change Cipher Spec Protocol: Change Cipher Spec
        //         Content Type: Change Cipher Spec (20)
        //         Version: TLS 1.2 (0x0303)
        //         Length: 1
        //         Change Cipher Spec Message
        //     TLS segment data (1279 bytes)
        "16 03 03 00 7a 02 00 00 76 03 03 11 c6 8c 2c 51"
        "13 8c 19 b9 86 fa 19 a0 f1 ea b3 18 b5 66 e5 7c"
        "30 9a 44 7c 94 f9 0d 89 52 3f de 20 47 a7 0c 71"
        "a5 e5 8d d3 31 12 e0 eb 8f f4 49 78 07 69 01 38"
        "58 5d 88 1b 62 e0 c7 31 30 ec 14 0f 13 02 00 00"
        "2e 00 33 00 24 00 1d 00 20 18 35 6c 1f c3 b3 8c"
        "2e 72 3b ad 93 b0 ec 29 5a 5d be a7 f2 86 1a 73"
        "9e a2 07 f4 a8 b2 3e 99 56 00 2b 00 02 03 04 14"
        "03 03 00 01 01 17 03 03 0a 76 b1 40 1a a0 33 59"
        "2f cb 94 f4 eb 60 b9 32 4e 4f 39 b5 ec 13 82 c3"
        "ea b0 17 1a aa ae c3 f6 91 dc 2b 88 cb d2 b5 9a"
        "ea 0a c0 bf f8 54 75 7f 50 d6 f9 ea df ba 8c 78"
        "72 80 cf b2 5c 7a 11 25 f4 ab 5c 40 ea ba 9d c2"
        "6a ec 13 9b ce e2 39 6c d0 90 f0 d5 6f a2 90 34"
        "86 77 86 3b d5 6c ab a4 a2 b5 85 14 45 6d 28 49"
        "41 9a 61 9d 12 cc d8 3d 4d 60 5b ef 76 64 7b 45"
        "00 17 99 13 79 57 12 08 24 68 4a 1a 75 c8 b4 64"
        "60 22 0f a9 a2 ea 0c a2 91 e9 8d af d0 7c c9 f8"
        "fd 43 92 b2 11 af 52 19 6b ca 94 1a 72 36 e7 33"
        "14 3b 63 73 10 36 5b 1c c2 8d 76 00 78 76 fa 6b"
        "68 80 5a 42 cc 3b bb 62 c1 73 25 38 54 f1 1c d1"
        "a4 8a 94 a4 46 6d 20 72 47 2d 6e 52 b8 10 7d c0"
        "12 39 84 71 0f 3e 4b fb 4a d6 ad 74 a5 6d a6 50"
        "0b 65 86 33 68 58 f4 e2 5c bb 0e 4e 13 fc 9e f8"
        "be a1 b4 97 0e ae ee b1 82 58 ac 62 f1 e9 62 ad"
        "a1 03 a0 7f 20 ca 25 86 56 26 44 df bf 71 94 67"
        "d7 39 a8 86 8d 7a c1 d5 da bb e9 52 e7 9f 93 a6"
        "f0 8f c8 62 04 7d 7f dc 12 7e df 81 03 e6 76 ee"
        "9e db 01 f3 e5 07 21 c3 21 3c ed ae 50 91 a8 27"
        "dc 38 3e 2a 95 1b c3 24 1d b8 ba a6 66 38 0a 04"
        "d9 c2 44 54 43 f0 43 87 6f d2 84 8a cb 40 2f c3"
        "a0 eb c9 74 66 08 ad 10 23 07 61 38 e6 a7 2b d4"
        "ce 3d 15 30 03 5a 29 22 a3 e8 f3 9e d7 d4 13 a1"
        "61 07 16 3f 68 b6 eb a0 fc 8b 59 bc 1f 58 13 fd"
        "a6 00 10 1b b8 f1 eb 1f 59 26 46 45 00 0e a7 61"
        "d6 c3 29 4f fb 09 d6 97 d0 d9 b0 ac fd 83 f7 5d"
        "42 47 33 d9 f5 35 61 53 bb 4e e7 f4 b5 4a ba fd"
        "74 9d 82 92 d2 38 67 5f 5a eb 06 4d be 90 6f 9b"
        "55 14 6d 2c 40 d3 c7 a6 a8 88 21 37 d3 b9 d8 54"
        "27 7c 26 d5 12 0c 3d 36 ea 09 6a 30 9a 6a 59 1c"
        "97 98 82 39 e0 a4 b9 b8 34 f6 8b 44 00 bf 04 07"
        "01 4e b5 d4 14 5d 43 b8 ca d9 6c 73 d0 51 10 1c"
        "80 31 32 84 11 ce c5 3b 58 0b 44 db 9f 57 6b f6"
        "e2 2d 3a aa ba 75 f6 e2 c8 0a b6 9a 38 b3 a3 a7"
        "a1 a3 ec 32 1a 07 19 0f 12 ea 47 ad 6b 58 61 14"
        "d4 b9 7b 45 6a 62 d0 0d 3b 0d 22 6f 48 11 ac 9b"
        "19 12 7c ea e7 4e 33 43 ea 97 65 78 5e d8 e7 fe"
        "90 a7 55 44 99 df 02 52 88 ad e9 77 89 28 a3 ce"
        "0c f3 0e 49 ea d1 40 54 1a cf 28 77 05 25 46 f9"
        "7e ed 91 9c 0b bc 13 b6 d6 51 ad 98 67 63 3f 25"
        "ac e7 fb c3 e7 5d e0 e1 51 d8 1b 2e 44 44 68 e0"
        "16 72 a7 b2 75 dd cc e0 e2 95 da d4 1a ca af 7c"
        "0b bb bc df 41 ce 50 d2 cd 3a ae 56 40 fe 8b c6"
        "2c 97 21 21 45 bc 8f 52 46 87 6b f6 1a 57 72 b4"
        "bc 1f c7 ed d3 5e b0 63 f0 47 f8 fc 99 5f 56 99"
        "41 59 f6 43 6b 57 d3 67 d0 ba 33 71 ba 15 0c 9e"
        "89 72 5c 46 7d 73 ae 91 3f 8c 1e 45 a1 cb 93 b0"
        "dd fd d7 b9 98 e3 b7 bc fa 57 54 70 75 10 b4 1e"
        "ee db 90 ac b6 3d fb e2 c8 47 6d aa f8 82 9b 21"
        "bb cc 0c 52 a5 5a ab e3 dd bb 6f 54 7d 51 26 43"
        "06 41 f4 e9 75 6f 74 c9 9c 19 48 78 36 fb 23 d1"
        "44 05 a8 19 12 66 2b 30 ff d4 a4 0a d3 eb c9 94"
        "5e e2 9e ca 5c 6b 73 87 39 dd 98 ee 2f af 3b fb"
        "72 f6 43 8c c0 b5 35 e6 c0 64 49 74 a9 5b f1 d4"
        "9c b0 4d b0 4d cf 8f 3b bd b7 8d 38 d7 8f f3 ba"
        "16 d3 4e 3a 20 f4 92 2f a9 1c 99 8d 5d e8 88 d4"
        "74 a2 1f d6 a2 b8 c9 e0 c1 d3 61 a9 32 47 57 90"
        "0f e8 ac 25 28 c4 23 96 25 f8 65 4f 2c a1 37 e8"
        "67 64 61 58 0d b5 4e 1a 9f d9 f8 67 7a 03 59 66"
        "fe 3b ab 25 0c c0 7a 55 78 68 72 a7 95 8f b4 c8"
        "81 6f 7b 16 a0 ab 2f 7c d4 be ca 4c 3b b7 20 cd"
        "41 e1 b5 f0 6f 36 b9 8d 07 99 bb e7 ab 19 56 51"
        "ba fd 66 12 a8 6e b3 6c 2e 87 96 e4 99 4b 26 42"
        "6d e4 09 34 97 2b 80 f2 09 1e d6 89 72 d1 84 3c"
        "09 cc 1a 29 ee d5 45 55 35 e1 c5 08 c4 d8 28 0e"
        "1c 1b 57 22 2e 76 1b f0 05 1e c5 57 e7 55 17 28"
        "fc 97 0e c3 73 a3 dc a4 9f 27 32 fb 71 06 22 3b"
        "c9 a5 28 91 84 05 91 b5 ed 15 f9 0f 2a 2a 44 40"
        "db aa b4 c8 ea 4c 43 50 cf 3d 22 b2 12 78 e4 8d"
        "c4 b0 65 b4 ec c1 fe 9b 25 4f f0 33 aa f2 69 2d"
        "1b aa be f0 99 41 71 43 b6 15 38 4f 1c e3 b2 67"
        "e3 49 40 9f a5 69 48 bb 77 fc 01 13 46 2c 28 d3"
        "5d 69 e6 73 25 cd f8 bc bd 8f 4e f9 ba 0d 5f 6c"
        "2b bc f4 d7 f3 83 7d da 78 02 ce eb f9 a7 66 34"
        "f6 dd 6c d3 33 7b 96 54 6c be 51 b3 2e 91 b6 86"
        "1e bd f2 d0 78 b4 4b fc 8a f1 38 db e2 30 da 67"
        "4f 99 75 05 e3 8a 96 09 dd 93 00 ed 43 27 c9 75"
        "7a c7 a5 ca 74 1f 04 bd cc de f1 08 9a 86 0a d3"
        "66 f0 12 4b",
    },
    {
        // Transport Layer Security
        //     TLSv1.3 Record Layer: Application Data Protocol: Hypertext Transfer Protocol
        //         Opaque Type: Application Data (23)
        //         Version: TLS 1.2 (0x0303)
        //         Length: 2678
        //         Encrypted Application Data […]: ...
        //         [Application Data Protocol: Hypertext Transfer Protocol]
        from_server,
        prot_tls13,
        "WIRESHARK#27 TLS 1.3",
        "17 03 03 0a 76 b1 40 1a a0 33 59 2f cb 94 f4 eb"
        "60 b9 32 4e 4f 39 b5 ec 13 82 c3 ea b0 17 1a aa"
        "ae c3 f6 91 dc 2b 88 cb d2 b5 9a ea 0a c0 bf f8"
        "54 75 7f 50 d6 f9 ea df ba 8c 78 72 80 cf b2 5c"
        "7a 11 25 f4 ab 5c 40 ea ba 9d c2 6a ec 13 9b ce"
        "e2 39 6c d0 90 f0 d5 6f a2 90 34 86 77 86 3b d5"
        "6c ab a4 a2 b5 85 14 45 6d 28 49 41 9a 61 9d 12"
        "cc d8 3d 4d 60 5b ef 76 64 7b 45 00 17 99 13 79"
        "57 12 08 24 68 4a 1a 75 c8 b4 64 60 22 0f a9 a2"
        "ea 0c a2 91 e9 8d af d0 7c c9 f8 fd 43 92 b2 11"
        "af 52 19 6b ca 94 1a 72 36 e7 33 14 3b 63 73 10"
        "36 5b 1c c2 8d 76 00 78 76 fa 6b 68 80 5a 42 cc"
        "3b bb 62 c1 73 25 38 54 f1 1c d1 a4 8a 94 a4 46"
        "6d 20 72 47 2d 6e 52 b8 10 7d c0 12 39 84 71 0f"
        "3e 4b fb 4a d6 ad 74 a5 6d a6 50 0b 65 86 33 68"
        "58 f4 e2 5c bb 0e 4e 13 fc 9e f8 be a1 b4 97 0e"
        "ae ee b1 82 58 ac 62 f1 e9 62 ad a1 03 a0 7f 20"
        "ca 25 86 56 26 44 df bf 71 94 67 d7 39 a8 86 8d"
        "7a c1 d5 da bb e9 52 e7 9f 93 a6 f0 8f c8 62 04"
        "7d 7f dc 12 7e df 81 03 e6 76 ee 9e db 01 f3 e5"
        "07 21 c3 21 3c ed ae 50 91 a8 27 dc 38 3e 2a 95"
        "1b c3 24 1d b8 ba a6 66 38 0a 04 d9 c2 44 54 43"
        "f0 43 87 6f d2 84 8a cb 40 2f c3 a0 eb c9 74 66"
        "08 ad 10 23 07 61 38 e6 a7 2b d4 ce 3d 15 30 03"
        "5a 29 22 a3 e8 f3 9e d7 d4 13 a1 61 07 16 3f 68"
        "b6 eb a0 fc 8b 59 bc 1f 58 13 fd a6 00 10 1b b8"
        "f1 eb 1f 59 26 46 45 00 0e a7 61 d6 c3 29 4f fb"
        "09 d6 97 d0 d9 b0 ac fd 83 f7 5d 42 47 33 d9 f5"
        "35 61 53 bb 4e e7 f4 b5 4a ba fd 74 9d 82 92 d2"
        "38 67 5f 5a eb 06 4d be 90 6f 9b 55 14 6d 2c 40"
        "d3 c7 a6 a8 88 21 37 d3 b9 d8 54 27 7c 26 d5 12"
        "0c 3d 36 ea 09 6a 30 9a 6a 59 1c 97 98 82 39 e0"
        "a4 b9 b8 34 f6 8b 44 00 bf 04 07 01 4e b5 d4 14"
        "5d 43 b8 ca d9 6c 73 d0 51 10 1c 80 31 32 84 11"
        "ce c5 3b 58 0b 44 db 9f 57 6b f6 e2 2d 3a aa ba"
        "75 f6 e2 c8 0a b6 9a 38 b3 a3 a7 a1 a3 ec 32 1a"
        "07 19 0f 12 ea 47 ad 6b 58 61 14 d4 b9 7b 45 6a"
        "62 d0 0d 3b 0d 22 6f 48 11 ac 9b 19 12 7c ea e7"
        "4e 33 43 ea 97 65 78 5e d8 e7 fe 90 a7 55 44 99"
        "df 02 52 88 ad e9 77 89 28 a3 ce 0c f3 0e 49 ea"
        "d1 40 54 1a cf 28 77 05 25 46 f9 7e ed 91 9c 0b"
        "bc 13 b6 d6 51 ad 98 67 63 3f 25 ac e7 fb c3 e7"
        "5d e0 e1 51 d8 1b 2e 44 44 68 e0 16 72 a7 b2 75"
        "dd cc e0 e2 95 da d4 1a ca af 7c 0b bb bc df 41"
        "ce 50 d2 cd 3a ae 56 40 fe 8b c6 2c 97 21 21 45"
        "bc 8f 52 46 87 6b f6 1a 57 72 b4 bc 1f c7 ed d3"
        "5e b0 63 f0 47 f8 fc 99 5f 56 99 41 59 f6 43 6b"
        "57 d3 67 d0 ba 33 71 ba 15 0c 9e 89 72 5c 46 7d"
        "73 ae 91 3f 8c 1e 45 a1 cb 93 b0 dd fd d7 b9 98"
        "e3 b7 bc fa 57 54 70 75 10 b4 1e ee db 90 ac b6"
        "3d fb e2 c8 47 6d aa f8 82 9b 21 bb cc 0c 52 a5"
        "5a ab e3 dd bb 6f 54 7d 51 26 43 06 41 f4 e9 75"
        "6f 74 c9 9c 19 48 78 36 fb 23 d1 44 05 a8 19 12"
        "66 2b 30 ff d4 a4 0a d3 eb c9 94 5e e2 9e ca 5c"
        "6b 73 87 39 dd 98 ee 2f af 3b fb 72 f6 43 8c c0"
        "b5 35 e6 c0 64 49 74 a9 5b f1 d4 9c b0 4d b0 4d"
        "cf 8f 3b bd b7 8d 38 d7 8f f3 ba 16 d3 4e 3a 20"
        "f4 92 2f a9 1c 99 8d 5d e8 88 d4 74 a2 1f d6 a2"
        "b8 c9 e0 c1 d3 61 a9 32 47 57 90 0f e8 ac 25 28"
        "c4 23 96 25 f8 65 4f 2c a1 37 e8 67 64 61 58 0d"
        "b5 4e 1a 9f d9 f8 67 7a 03 59 66 fe 3b ab 25 0c"
        "c0 7a 55 78 68 72 a7 95 8f b4 c8 81 6f 7b 16 a0"
        "ab 2f 7c d4 be ca 4c 3b b7 20 cd 41 e1 b5 f0 6f"
        "36 b9 8d 07 99 bb e7 ab 19 56 51 ba fd 66 12 a8"
        "6e b3 6c 2e 87 96 e4 99 4b 26 42 6d e4 09 34 97"
        "2b 80 f2 09 1e d6 89 72 d1 84 3c 09 cc 1a 29 ee"
        "d5 45 55 35 e1 c5 08 c4 d8 28 0e 1c 1b 57 22 2e"
        "76 1b f0 05 1e c5 57 e7 55 17 28 fc 97 0e c3 73"
        "a3 dc a4 9f 27 32 fb 71 06 22 3b c9 a5 28 91 84"
        "05 91 b5 ed 15 f9 0f 2a 2a 44 40 db aa b4 c8 ea"
        "4c 43 50 cf 3d 22 b2 12 78 e4 8d c4 b0 65 b4 ec"
        "c1 fe 9b 25 4f f0 33 aa f2 69 2d 1b aa be f0 99"
        "41 71 43 b6 15 38 4f 1c e3 b2 67 e3 49 40 9f a5"
        "69 48 bb 77 fc 01 13 46 2c 28 d3 5d 69 e6 73 25"
        "cd f8 bc bd 8f 4e f9 ba 0d 5f 6c 2b bc f4 d7 f3"
        "83 7d da 78 02 ce eb f9 a7 66 34 f6 dd 6c d3 33"
        "7b 96 54 6c be 51 b3 2e 91 b6 86 1e bd f2 d0 78"
        "b4 4b fc 8a f1 38 db e2 30 da 67 4f 99 75 05 e3"
        "8a 96 09 dd 93 00 ed 43 27 c9 75 7a c7 a5 ca 74"
        "1f 04 bd cc de f1 08 9a 86 0a d3 66 f0 12 4b 9d"
        "e2 68 62 ac 88 87 bb cf c4 9a 6b f1 03 9b 1b dc"
        "9e 8b 09 d4 f3 ce 7f bb 4b da 68 d7 d7 78 41 13"
        "bd cc 2d 6b d8 85 19 d5 5d 7d e1 bd c8 71 ba 8f"
        "e0 4c d3 1b da 3c 8c c5 b9 9c 99 55 8e 9b 58 ab"
        "c5 f2 61 1c 7e b1 ac 84 00 4f fd f2 b7 59 94 8f"
        "4b e2 7c 2f 02 ce 87 74 59 45 fc 17 3a da d6 02"
        "25 b9 b1 cb 1c 14 53 fa 01 a4 0a 20 c0 d0 27 79"
        "19 98 67 6a 88 cd e5 9f 47 5d ad 0d 6e e5 3d 16"
        "61 44 21 ab a0 d8 e2 8f bb 7d 58 51 da a1 cb 59"
        "47 3e fb 47 50 eb d3 16 36 75 bc 02 1d e9 90 0a"
        "8c a6 e3 99 aa dd f6 98 33 29 dc c2 7e 17 9f 4d"
        "56 dc ba 94 5a 02 a4 5e 40 75 70 a4 98 a0 e6 6b"
        "81 dc 09 37 a2 84 a1 d6 ae b8 46 c5 7c eb 73 d6"
        "73 24 2b 0b a2 30 20 97 57 51 2b 8c 18 c4 f4 e4"
        "c4 88 b1 77 a0 fa d0 e0 de 1f b0 da ef c3 cf ba"
        "cb 69 61 78 d7 15 84 a1 8f 7a 45 75 ce b0 41 53"
        "6a 7f 64 28 8b 6d 2d 06 f4 21 4a f6 7c 8d c3 df"
        "15 ff 81 f1 d7 84 9a 8e 51 a3 03 76 b0 7e 1f 53"
        "88 c8 ae eb 9b 6b 19 07 67 42 bc 8b 8b b9 76 17"
        "ec 92 8e fb 21 2d b7 8a 91 d7 32 e6 64 4c 84 8e"
        "e1 6b 2f af f9 6e 97 27 3a a2 67 3b a7 03 77 12"
        "89 83 3f 6c 40 6a 54 ad f5 95 a2 bf ef 1a 78 4c"
        "10 b8 af ce 6e ff c3 a7 dd 36 fb e9 88 d1 db 35"
        "49 a2 ef c8 60 04 0d 61 33 6a 6d e2 d2 7b 33 86"
        "2f d7 37 3f ad e1 66 67 22 8e 17 b3 44 06 41 39"
        "70 e2 6f 64 3d a4 4a c7 e5 09 51 a2 62 7d c1 31"
        "93 02 81 c0 40 af 15 cb e7 61 40 71 e5 28 5f 5f"
        "9d c7 ec 4f 95 f6 b3 a2 19 df 69 36 27 e6 66 72"
        "6a ee 48 0d ee ad f7 1f 6d 74 bd 9c 87 77 8a f4"
        "2f f4 42 a7 cd bb 1f 1d 2f 68 ce 9b 3a be 86 45"
        "c6 64 6f d3 fb c8 b8 03 77 2f 02 c4 77 28 51 84"
        "9d c4 60 64 4c 8e 70 92 40 6b 7e b9 ea 8d b2 25"
        "ea de 16 b8 cf cf 00 9c fd f6 01 64 38 9a 7a 50"
        "1d 78 9a a1 22 2e 69 e4 a8 13 dc 0a 3d 43 c3 59"
        "8c 87 0e bd 73 9d cd 96 93 4c 18 77 86 ad 8e 0d"
        "e2 e5 78 27 a3 2c aa 1e fe 44 a2 ff d4 db bd 2e"
        "fc f9 7c 1c 41 9f cb e4 0e 01 4a c9 96 1f 56 14"
        "a4 59 b2 09 26 0d 07 af ea 06 38 18 21 c2 b3 50"
        "53 11 8d 0a 34 bd b6 cc b7 f7 ee 64 29 4e 23 1b"
        "84 92 e4 ba b6 2b 17 d0 62 14 c2 07 17 03 b6 19"
        "ea 7e 65 3d ed 35 ac 61 8d 98 a3 40 8a c4 77 cc"
        "0b 13 c4 20 23 a3 ca 9b 73 c4 c1 2e 29 7f e6 34"
        "08 7d 74 03 c6 5d 55 8d c7 64 a0 ba ed 8d a4 75"
        "df fe 34 ce db 87 8f 52 52 93 bd 78 19 26 11 10"
        "2d 6c 33 57 e4 b2 c0 79 93 42 a5 8d 2a e1 64 ec"
        "91 91 b9 93 aa ee 20 a3 31 6b ed 5f 9c 3e 1d 46"
        "66 ed de 10 08 de a2 01 bb 36 10 b9 47 71 78 d8"
        "f6 54 45 71 9c 4f 56 1c d5 85 02 85 99 a3 85 9c"
        "c5 d0 b1 28 ab e6 9e 33 ae c5 6b 59 4f 6b b8 12"
        "95 83 3e 88 83 cf f0 70 72 a4 3c 08 09 c7 9e 14"
        "0f 6a 54 77 83 f5 f7 26 ce c3 3b 5f e7 27 4e 64"
        "04 61 c8 7a 82 1d f9 3c 2c 24 f6 47 e6 bd e9 a9"
        "96 70 a6 2b bd 45 3f 78 5c 9b ac 2c 63 3d 8d d4"
        "fa ae 8e ce c6 33 e4 08 76 ee 46 82 6b cc 17 60"
        "91 3c a6 e5 5e 53 18 75 05 4d 6d 36 5f 7e ff c6"
        "8b 73 bc 0e c7 29 96 f3 e0 b6 39 5e f6 fa d4 42"
        "6f 95 a1 97 9e 60 34 e7 56 98 db 5d dd 5e 98 8b"
        "16 8f cf 92 58 63 31 6d 47 44 16 7b f8 97 b1 63"
        "4a 8e 65 79 2d b7 1d 81 70 bd 75 72 f2 5f 56 78"
        "01 cb 59 f3 be 1e 63 f7 59 ad f1 6f 25 91 5f e1"
        "9b 86 15 2d 55 56 6e 60 85 29 53 57 df a1 bf 15"
        "c1 3e 7f a6 8d 71 b1 90 a6 46 39 78 a5 b8 d0 87"
        "b1 27 85 a7 3a 7b 6d 96 96 95 32 e8 18 a4 c6 e1"
        "c0 3e 6f 79 69 37 9e 3a 79 3d d8 19 fe 80 83 f5"
        "dd cf 0f 98 3e 1b 98 f8 41 d9 ce 32 ec 41 ca b1"
        "ca 63 37 58 f7 fe c4 4f bf b9 3e 0f 97 69 c9 26"
        "c7 14 cb ab 8a c4 e1 95 9a 28 8e 7a e3 d4 e5 4c"
        "ce 06 31 df 60 08 5f 7e 3d f2 2c 8f 39 5d 8c b4"
        "fc a6 28 69 f0 55 8a 5a 6e 79 62 42 40 dc 69 6d"
        "ec 0c 82 92 93 08 63 1a 78 35 22 69 e7 8e 28 b6"
        "a0 f7 c6 57 e4 5a a3 bb 08 ae 04 61 3d e0 84 7e"
        "dc 01 a2 1c dc 6b f5 42 95 69 80 59 af 4e 75 ff"
        "78 61 1a dc eb 77 31 e4 6e f8 6f bf 83 9a 9c 7e"
        "a1 32 0f 62 2a 41 19 97 6c 4f 23 9f 36 01 a7 43"
        "07 55 13 83 15 cc ce 0a 02 04 d8 fb 65 e5 54 1e"
        "5c eb 77 d9 47 55 70 aa d1 39 b6 0d a7 20 38 59"
        "64 65 44 51 0b 02 bb 9d 5e 20 5a 14 0e f2 a0 ca"
        "76 e5 ce e8 3a c7 93 e9 93 ee 64 dd 1a 3f 1c ac"
        "ef c4 1b a4 e3 af 7a 43 c8 9b 8b 4c 1a a2 d6 42"
        "92 9b 91 f7 6a f2 61 a1 fe 6c 1b 5b 32 63 d0 a8"
        "59 d1 22 db a9 9c 6e e2 f5 9c 77 76 2d 0c 03 15"
        "6b 6a b9 00 2b 32 c3 2d fd 0b 57 f3 63 d7 dc 72"
        "db a6 27 2b 2f 66 5b d0 ed 97 ad b8 1c 50 3e 35"
        "6f e0 53 d6 ac bd 4c d2 f1 d2 03 63 69 34 3a f8"
        "a9 82 04 f9 6d 7c 80 f0 b5 cc 3f 02 e5 c5 9e 3b"
        "22 0d ec 43 81 c3 c9 45 15 58 37 b4 96 24 33 63"
        "c7 00 12 1f 2c bc 0b 68 28 ec 7b b6 41 fb 01 2f"
        "90 68 d4 83 92 bf 8b 66 29 9e f9",
    },
#endif
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 645]
        //     QUIC Short Header PKN=8
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..01 = Packet Number Length: 2 bytes (1)]
        //         [Packet Number: 8]
        //         Protected Payload […]: ...
        //     CRYPTO
        //         Frame Type: CRYPTO (0x0000000000000006)
        //         Offset: 0
        //         Length: 622
        //         Crypto Data
        //         TLSv1.3 Record Layer: Handshake Protocol: Multiple Handshake Messages
        //             Handshake Protocol: New Session Ticket
        //                 Handshake Type: New Session Ticket (4)
        //                 Length: 307
        //                 TLS Session Ticket
        //                     Session Ticket Lifetime Hint: 172800 seconds (2 days)
        //                     Session Ticket Age Add: 1991081788
        //                     Session Ticket Nonce Length: 1
        //                     Session Ticket Nonce: 00
        //                     Session Ticket Length: 281
        //                     Session Ticket […]: ...
        //                     Extensions Length: 12
        //                     Extension: early_data (len=4)
        //                         Type: early_data (42)
        //                         Length: 4
        //                         Maximum Early Data Size: 4294967295
        //                     Extension: Reserved (GREASE) (len=0)
        //                         Type: Reserved (GREASE) (60138)
        //                         Length: 0
        //                         Data: <MISSING>
        //             Handshake Protocol: New Session Ticket
        //                 Handshake Type: New Session Ticket (4)
        //                 Length: 307
        //                 TLS Session Ticket
        //                     Session Ticket Lifetime Hint: 172800 seconds (2 days)
        //                     Session Ticket Age Add: 2184364348
        //                     Session Ticket Nonce Length: 1
        //                     Session Ticket Nonce: 01
        //                     Session Ticket Length: 281
        //                     Session Ticket […]: ...
        //                     Extensions Length: 12
        //                     Extension: early_data (len=4)
        //                         Type: early_data (42)
        //                         Length: 4
        //                         Maximum Early Data Size: 4294967295
        //                     Extension: Reserved (GREASE) (len=0)
        //                         Type: Reserved (GREASE) (60138)
        //                         Length: 0
        //                         Data: <MISSING>
        from_server,
        prot_quic,
        "WIRESHARK#28 QUIC CRYPTO[NST, NST]",
        "52 6b 12 b3 5e f8 31 c5 24 98 8a ed f6 0f 49 3a"
        "95 c3 42 51 4f 4a b6 f7 83 5c 39 35 9a b6 fb 7f"
        "df 5c c8 8c c6 a1 28 a7 be 49 91 37 2a 01 ce 5c"
        "5a 5a 3b 57 46 36 7b 62 2e 2b 2d cf 3c d9 1e a0"
        "8a 22 d9 82 7b 17 2a 93 39 f5 e0 f8 df 66 65 e5"
        "86 98 09 df cc 5f ee d4 8f 1a b1 9d 70 17 01 f9"
        "89 c6 8f 0f 2e 9a a8 09 f1 08 c3 90 9c bc e3 12"
        "89 2f e7 5b 7c 8c 21 c4 e2 87 f3 e8 fe 4f 47 9b"
        "c7 37 c1 b9 12 04 71 18 f5 6e 3e a2 bc ee 83 92"
        "46 39 2a 5f e4 d4 60 ed e4 5f 4c 3a 72 65 8e 3f"
        "60 00 16 aa bc 75 06 51 cd 19 ee 43 bb bc 2e 2a"
        "e7 ae f8 e4 b8 d3 ad 44 d3 ff 56 83 bf fd 2f a9"
        "80 95 b7 5a b3 c8 11 a7 f6 01 4e 92 8b 7c 34 12"
        "8b e3 31 6d 05 4d 5d 4f b2 30 b3 5b e3 da 35 ea"
        "94 b0 ed 5c 58 3a 6b 8b 38 0f 25 96 18 3e fe 19"
        "fe ce df bc 9b 6e 7f a0 bd 76 1f df e8 24 a1 28"
        "d5 cc a0 61 a5 49 56 19 c5 be c0 2c da e0 27 54"
        "f7 cc a2 62 cf cf 01 4e ef 79 85 53 ba da cf 5c"
        "02 39 cf e1 46 54 36 3a 09 5c 5c cd 7e f4 21 71"
        "ba 1a b0 70 15 9a d4 71 93 2f 01 03 29 ed 2b e8"
        "39 5e 72 9f d7 d6 f8 64 50 07 7e d3 58 f5 d4 21"
        "b2 7f 63 e9 63 3d 55 d7 47 be d0 d4 f9 f7 28 2d"
        "7c f6 a5 84 17 52 aa ce b6 4c f1 b2 cf 50 86 0c"
        "3f 56 91 0c cb 53 8e 58 50 9d 16 80 f9 69 fe 59"
        "96 98 a9 4d 08 bc 86 cb 7b 3d 03 f6 25 87 28 14"
        "0d 59 b3 f1 b8 a4 0c d1 6e 66 0e 0c 29 15 80 c4"
        "1d 13 82 1a 64 7a 87 ad ce 26 95 20 f0 67 0f 87"
        "27 08 2c 6a 0e 96 be b1 66 c5 8e 1e 3b 19 c6 da"
        "a0 f5 29 bb 20 b1 9e 1e 1c a5 da 70 2c 03 65 45"
        "01 d0 43 8a 9e e3 f0 19 8b a3 20 86 d6 17 1c ac"
        "69 e6 e4 03 c1 fe 46 41 75 0d 23 e4 97 cc 7c 43"
        "d5 c4 d0 bc df af 4b a9 3c fa 3c a9 a9 b6 31 5e"
        "54 1e 35 74 e7 95 cb 94 6c 56 f3 ae 34 fa fe 91"
        "ed 82 2a ad 36 c1 3f 1f 58 6a 9d 15 13 24 8c 13"
        "f9 c8 17 a6 db a7 63 8b e3 e6 59 e8 42 e3 fc 22"
        "15 ac 78 15 22 c7 0a 1b ac 35 b4 8b 8e a9 60 ea"
        "ed 04 36 f3 2a 1b d6 6f cc f2 78 10 f7 03 b0 74"
        "64 78 92 0c 1f 5d 61 e7 64 a8 3d e8 b3 7f 65 30"
        "4f b5 5f 43 e1 2c a8 a5 51 1d 75 3a 95 09 ab 49"
        "b5 4d b2 33 df 1e ba 4e c9 9a 62 6a 8a 94 d1 c2"
        "d7 81 13 e9 48",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 121]
        //     QUIC Short Header PKN=9
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..01 = Packet Number Length: 2 bytes (1)]
        //         [Packet Number: 9]
        //         Protected Payload […]: ...
        //     HANDSHAKE_DONE
        //         Frame Type: HANDSHAKE_DONE (0x000000000000001e)
        //     NEW_TOKEN
        //         Frame Type: NEW_TOKEN (0x0000000000000007)
        //         (Token) Length: 70
        //         Token: ...
        //     NEW_CONNECTION_ID
        //         Frame Type: NEW_CONNECTION_ID (0x0000000000000018)
        //         Sequence: 1
        //         Retire Prior To: 0
        //         Connection ID Length: 8
        //         Connection ID: fe21df6a65e76e9e
        //         Stateless Reset Token: 959879e23da411c6d3986538f78f2ff0
        from_server,
        prot_quic,
        "WIRESHARK#29 QUIC HANDSHAKE_DONE, NEW_TOKEN, NEW_CONNECTION_ID",
        "50 57 01 5a fe 57 dd d0 92 b5 0e cc 85 18 d1 98"
        "22 7b a8 68 f6 9b 9f 02 24 a5 91 ec 03 f5 ca 42"
        "bc 50 c4 4e 8f 7d c9 a0 c9 e4 70 de c9 44 06 d4"
        "48 2c c7 f7 c5 f7 49 86 5b 73 17 1d 15 f0 b1 fb"
        "8b 47 d1 34 7a 4e dc 6e 2f d2 63 3e fe 62 2d 67"
        "06 02 34 d9 72 35 ab 48 be 5c 6d e7 02 ab d7 f9"
        "63 aa 94 90 8b d9 e7 b7 00 bf 4d ef ab 80 85 53"
        "5a 7f 64 bb 2d 04 33 cb 23",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 34]
        //     QUIC Short Header DCID=fe21df6a65e76e9e PKN=6
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..11 = Packet Number Length: 4 bytes (3)]
        //         Destination Connection ID: fe21df6a65e76e9e
        //         [Packet Number: 6]
        //         Protected Payload: 84dc95f38bf1881b987e10aab420c6d9cc501154cc
        //     ACK
        //         Frame Type: ACK (0x0000000000000002)
        //         Largest Acknowledged: 9
        //         ACK Delay: 0
        //         ACK Range Count: 0
        //         First ACK Range: 2
        from_client,
        prot_quic,
        "WIRESHARK#30 QUIC ACK",
        "5b fe 21 df 6a 65 e7 6e 9e fb 66 62 c7 84 dc 95"
        "f3 8b f1 88 1b 98 7e 10 aa b4 20 c6 d9 cc 50 11"
        "54 cc",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 23]
        //     QUIC Short Header PKN=10
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..00 = Packet Number Length: 1 bytes (0)]
        //         [Packet Number: 10]
        //         Protected Payload: ffc43c4d1f6c92f9f7d99c7473a65cf0b3231a86ca
        //     ACK
        //         Frame Type: ACK (0x0000000000000002)
        //         Largest Acknowledged: 2
        //         ACK Delay: 0
        //         ACK Range Count: 0
        //         First ACK Range: 2
        from_server,
        prot_quic,
        "WIRESHARK#31 QUIC ACK",
        "46 3f ff c4 3c 4d 1f 6c 92 f9 f7 d9 9c 74 73 a6"
        "5c f0 b3 23 1a 86 ca",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 23]
        //     QUIC Short Header PKN=11
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..00 = Packet Number Length: 1 bytes (0)]
        //         [Packet Number: 11]
        //         Protected Payload: 95b5d0446b3b9dae51da00d1fac004ac502f6a5ed3
        //     ACK
        //         Frame Type: ACK (0x0000000000000002)
        //         Largest Acknowledged: 4
        //         ACK Delay: 0
        //         ACK Range Count: 0
        //         First ACK Range: 4
        from_server,
        prot_quic,
        "WIRESHARK#33 QUIC ACK",
        "4c 6c 95 b5 d0 44 6b 3b 9d ae 51 da 00 d1 fa c0"
        "04 ac 50 2f 6a 5e d3",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 28]
        //     QUIC Short Header PKN=12
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..00 = Packet Number Length: 1 bytes (0)]
        //         [Packet Number: 12]
        //         Protected Payload: 171e2a05617950ea86bce31c231fc8bda2ae0e82078fa203aa23
        //     ACK
        //         Frame Type: ACK (0x0000000000000002)
        //         Largest Acknowledged: 6
        //         ACK Delay: 1210
        //         ACK Range Count: 0
        //         First ACK Range: 6
        //     STREAM id=7 fin=0 off=0 len=2 dir=Unidirectional origin=Server-initiated
        //         Frame Type: STREAM (0x0000000000000008)
        //         Stream ID: 7
        //         Stream Data: 0380
        from_server,
        prot_quic,
        "WIRESHARK#34 QUIC ACK, STREAM",
        "43 ea 17 1e 2a 05 61 79 50 ea 86 bc e3 1c 23 1f"
        "c8 bd a2 ae 0e 82 07 8f a2 03 aa 23",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 35]
        //     QUIC Short Header DCID=fe21df6a65e76e9e PKN=7
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..11 = Packet Number Length: 4 bytes (3)]
        //         Destination Connection ID: fe21df6a65e76e9e
        //         [Packet Number: 7]
        //         Protected Payload: 43fb0780a4ab977e4b57727b2c653d44d41b7c64792f
        //     ACK
        //         Frame Type: ACK (0x0000000000000002)
        //         Largest Acknowledged: 12
        //         ACK Delay: 4250
        //         ACK Range Count: 0
        //         First ACK Range: 5
        from_client,
        prot_quic,
        "WIRESHARK#35 QUIC ACK",
        "49 fe 21 df 6a 65 e7 6e 9e 9d 90 a9 50 43 fb 07"
        "80 a4 ab 97 7e 4b 57 72 7b 2c 65 3d 44 d4 1b 7c"
        "64 79 2f",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 22]
        //     QUIC Short Header PKN=14
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..00 = Packet Number Length: 1 bytes (0)]
        //         [Packet Number: 14]
        //         Protected Payload: a6e22fc04b12f366d028a1acc40939c0e5e3d001
        //     STREAM id=7 fin=0 off=0 len=2 dir=Unidirectional origin=Server-initiated
        //         Frame Type: STREAM (0x0000000000000008)
        //         Stream ID: 7
        //         Stream Data: 0380
        from_server,
        prot_quic,
        "WIRESHARK#36 QUIC STREAM",
        "44 f0 a6 e2 2f c0 4b 12 f3 66 d0 28 a1 ac c4 09"
        "39 c0 e5 e3 d0 01",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 36]
        //     QUIC Short Header DCID=fe21df6a65e76e9e PKN=8
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..11 = Packet Number Length: 4 bytes (3)]
        //         Destination Connection ID: fe21df6a65e76e9e
        //         [Packet Number: 8]
        //         Protected Payload: 8e5a2d93f0bbfc201976e44542c6e95f7073a4c3c1edc5
        //     ACK
        //         Frame Type: ACK (0x0000000000000002)
        //         Largest Acknowledged: 14
        //         ACK Delay: 0
        //         ACK Range Count: 1
        //         First ACK Range: 0
        //         Gap: 0
        //         ACK Range: 5
        from_client,
        prot_quic,
        "WIRESHARK#37 QUIC ACK",
        "50 fe 21 df 6a 65 e7 6e 9e 07 d4 3d ba 8e 5a 2d"
        "93 f0 bb fc 20 19 76 e4 45 42 c6 e9 5f 70 73 a4"
        "c3 c1 ed c5",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 1194]
        //     QUIC Short Header PKN=15
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..00 = Packet Number Length: 1 bytes (0)]
        //         [Packet Number: 15]
        //         Protected Payload […]: ...
        //     STREAM id=11 fin=0 off=0 len=2 dir=Unidirectional origin=Server-initiated
        //         Frame Type: STREAM (0x000000000000000a)
        //         Stream ID: 11
        //         Length: 2
        //         Stream Data: 0220
        //     STREAM id=0 fin=0 off=0 len=1169 dir=Bidirectional origin=Client-initiated
        //         Frame Type: STREAM (0x0000000000000008)
        //         Stream ID: 0
        //         Stream Data […]: ...
        //         [Reassembled PDU in frame: 45]
        from_server,
        prot_quic,
        "WIRESHARK#38 QUIC STREAM, STREAM",
        "4b 9d 6b df 38 46 0b b9 65 7b 1d 43 27 42 a2 e0"
        "86 8b 96 c2 57 f6 a2 4f 35 75 1c dc 48 e6 5f 92"
        "bc 41 12 5d 3f 4f 32 94 24 39 fa 56 f8 b8 14 0d"
        "c4 04 05 fd 04 1d e9 7f 0d f3 c3 e2 f2 08 ee 58"
        "8b f2 90 5a 14 56 15 04 ed 4f 55 3d 63 63 65 a6"
        "0c e9 99 a3 e4 cc 0b 9c da 3d d2 96 f4 bd d8 ea"
        "ad 91 97 ba 44 d8 d5 2f 5f 11 3e df 76 72 1c a6"
        "c9 60 9e d0 fa 43 4a 95 e2 71 63 d6 38 bb ac 01"
        "c3 0a e1 bc b9 e4 9e 1e cb bf 40 26 4a 36 c4 1d"
        "74 5b c2 d2 41 7e 96 8a b3 04 a3 80 24 a0 63 ae"
        "e2 f7 62 f8 84 34 ed 3b 12 e1 b2 bd be cc 3f df"
        "c7 98 11 37 82 65 87 0b da bb 90 e6 34 bd 4f 6b"
        "b2 07 ba 79 c6 50 1f 94 31 bd 3f d6 37 26 93 82"
        "4f 5c 4b 9e 1e f3 46 84 ea be d2 24 a0 ca 45 b8"
        "8a 36 e9 b9 52 2a 30 59 c6 6b c2 95 7e a3 86 a0"
        "87 a0 73 75 f6 85 0c fa 76 62 ce 1d 35 6c 66 31"
        "2a 6b 4d 75 96 a4 d9 74 0a 8a 53 76 46 58 ab e4"
        "34 98 57 0f 64 13 be dd 17 7b 47 32 f8 db 7d 39"
        "e5 fe 78 be 8c 65 79 26 52 9b b4 4f 57 90 4a e1"
        "2c 78 56 8e fd 7d 48 1b ac 61 55 97 b7 25 3b 27"
        "b6 0f 80 f7 6c 03 5f 43 aa 31 e8 81 5d 42 d5 a7"
        "51 74 81 66 cd ed a8 66 22 f8 32 2c 1a a0 16 4c"
        "17 8c fe 61 17 26 ee 92 e5 f7 ec 88 7e b1 72 8c"
        "00 6f 05 17 90 f9 7e 01 21 82 59 bc 08 6b d6 fb"
        "15 4c 07 3c 18 71 f7 d6 c5 31 28 5a 6c c9 e4 c9"
        "5d 00 ad 90 64 28 e7 03 66 65 03 ea de 97 be f2"
        "ad 31 e0 6e 8c c9 5a 92 8a 28 b0 3f 2d e5 d4 85"
        "4a 4b 16 58 06 29 23 23 5d 9b bc b4 bd 13 ee 2b"
        "79 5c a3 bd 3f 7d a4 df 52 ad 68 96 4f f0 19 98"
        "2e 22 b1 3a ed 0d b2 95 a3 f6 b9 dc d5 ba ab 16"
        "9f 74 9c a7 61 b4 e0 3e 0a 65 db c1 d7 56 79 c4"
        "69 20 59 5e 92 6e 1f b3 7a 2b e8 02 b3 91 82 a0"
        "94 c3 04 9d 32 d2 00 da 50 86 f7 2c 98 89 8c cd"
        "9f cf 24 4c 6e b9 bf fc 6f 38 23 b1 54 a8 9e ca"
        "3c 9c 60 12 44 d7 dc 1b 7d bc 75 44 ef 91 58 51"
        "a8 05 07 94 68 bb 35 93 f3 60 dc e1 e1 44 85 3d"
        "ab 80 69 63 c6 e4 9b 44 84 39 11 2b d2 1f 58 7d"
        "08 b0 9d 7f 35 61 e9 14 2e d6 06 a0 1c 5a 99 e8"
        "d7 db 1d fb 39 75 c8 ba 88 10 8f f4 ee 7e d2 b6"
        "8f ed d3 c0 1d fb c6 4f a5 4a ff ae 47 2f aa ea"
        "72 f4 de 72 6b cd 3a d5 0b a6 47 fb db 1e 19 ac"
        "0a 26 36 3c 06 b4 2a 78 1a 38 b2 22 02 18 2b b1"
        "61 ae 07 b6 81 6a 2b a8 57 e5 2f 6b 79 87 e8 8a"
        "a4 4b 89 5a c2 55 59 0b ba 57 a7 6a 80 34 e2 6c"
        "05 5a eb 65 39 b3 ad 62 c1 f9 00 69 46 2d d3 98"
        "e6 ee 0b 7e 93 b7 aa 17 03 13 db da f0 40 de e3"
        "c7 eb 96 7b e3 32 ca 41 69 e7 5e f3 27 dc 25 18"
        "e6 cf 3e a9 1c e1 8d 8e 15 de ac e7 2f 64 8f 84"
        "6f 1c 75 33 0e 90 52 e1 2d ef 64 bc e2 4b f9 da"
        "86 e8 55 0b b9 7a c5 1d ef 3d 79 aa 98 6d 18 5e"
        "50 7f 03 44 20 ce 4e 8e e7 fa 28 e7 f3 a7 4f 40"
        "ca ce fc 73 86 33 3f 14 21 32 c1 51 c5 90 35 b9"
        "1a d2 81 32 d2 cb 05 07 35 fa f6 6b a0 eb c7 6b"
        "35 f3 bb b9 39 24 d7 aa 45 ad 91 e9 ba c6 d3 e0"
        "6f 07 01 15 04 0d a4 31 a8 f3 e9 e7 08 2c 2d e3"
        "38 15 2b 6f 08 8e ec e6 7c f1 71 6b 1a 91 c7 88"
        "87 4c 0d 46 84 8f 9d 23 4d ee c8 8e 11 67 1e be"
        "30 5a 51 2d 32 81 36 cc d0 f7 e2 68 1d e1 1b d5"
        "ad 14 d8 02 06 84 67 60 82 d3 83 08 81 e8 21 be"
        "ad a1 5a c1 0f b5 6c 24 7c f5 56 e8 3b c1 2c c4"
        "5e f8 a9 11 a3 50 7f 15 2a 76 4a a5 23 60 dc 75"
        "96 cd f6 c6 c0 f8 4a da 77 68 be 91 8b 76 8d 2e"
        "af d9 08 31 e0 e4 99 94 33 32 c5 33 69 2e 97 6d"
        "43 8f bf 4b 93 f0 d8 11 cc aa 1a db 3f fd 15 2a"
        "8d b2 4c b1 0c 1d 50 b5 8b c2 c6 e1 1b 68 35 38"
        "87 97 86 04 59 d5 57 12 cb 8e 42 32 28 f6 77 84"
        "96 b7 64 eb 3b 80 f9 56 63 dc 69 a9 63 16 68 b1"
        "fd 3f 40 f4 d0 dc cd 99 05 0c 10 e0 9e 91 5b 99"
        "2d b3 13 53 7f b9 b6 50 11 16 8e a9 85 3f be 1c"
        "39 b9 66 f2 6a 09 a0 f2 e4 2f 28 02 a9 f5 8f 30"
        "79 29 eb 84 36 17 9c 29 04 bd a7 0f d6 e5 98 1d"
        "84 07 a6 9e 69 90 b3 ca 2b d3 74 d8 42 6d 3c b5"
        "78 b3 7e 18 b6 68 ab 94 30 46 f6 f8 1c 47 a5 7e"
        "56 a4 7e 6a fb 11 85 ae 38 78 38 c0 ba ec ac e9"
        "d6 55 f9 37 23 9a d9 f0 fd 46",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 1200]
        //     QUIC Short Header PKN=16
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..00 = Packet Number Length: 1 bytes (0)]
        //         [Packet Number: 16]
        //         Protected Payload […]: ...
        //     STREAM id=0 fin=0 off=1169 len=1178 dir=Bidirectional origin=Client-initiated
        //         Frame Type: STREAM (0x000000000000000c)
        //         Stream ID: 0
        //         Offset: 1169
        //         Stream Data […]: ...
        //         [Reassembled PDU in frame: 45]
        from_server,
        prot_quic,
        "WIRESHARK#39 QUIC STREAM",
        "50 3f b0 b8 f8 0f f7 26 bf a2 c3 f2 e3 15 81 b8"
        "46 c7 48 dd 3d fe be 15 25 c2 b5 92 47 f9 15 7b"
        "56 55 36 5e 23 52 05 b6 83 3e f9 a6 f9 88 e8 58"
        "2d 65 b2 16 1a 90 4c 26 4e 0e 52 3e 68 96 e0 1d"
        "01 91 3c 2c 28 6d 49 5f bc 94 7f a5 f8 9d e4 d6"
        "79 0e 91 f4 49 40 20 ca 04 96 95 82 59 e1 6d f6"
        "ab e5 50 f8 7c 91 0f fa b6 40 15 c3 b6 bf d4 f0"
        "c4 a5 bd 10 9c 25 78 bb c9 1c 3b 56 93 1d d0 1d"
        "02 73 9d 4d 83 b0 11 86 86 14 78 2f fe fe f5 2c"
        "fe b7 64 d9 38 2a f1 1a 76 fe d2 c6 16 3a 72 43"
        "f5 aa 5d b6 c8 fc cb 40 d1 60 6e 42 34 be 3e 11"
        "63 77 71 4d d2 c2 82 3d da 33 94 4c 1b 4b ca 5c"
        "a7 19 2f cc 2f dd 65 44 bc ae c0 78 2a 06 42 59"
        "70 a3 c0 c9 c5 25 ee 61 12 e2 41 05 1a 5a 84 83"
        "86 38 6d 6c 6b 89 f5 2c f4 45 35 0e a2 a0 3a 53"
        "ff c7 c3 75 61 1f 7b 0e 38 33 16 7e 87 d5 a4 38"
        "cb da b7 53 ba 01 3b d6 d3 fa 9f ca 64 b4 cb 4f"
        "9b c7 3c 54 bc 26 ac a3 c6 71 84 24 5d 0e f6 1a"
        "dd 04 5f 3e 4c ed 54 93 6b b7 59 d6 30 f3 7e 2e"
        "ec 84 7c 5a 7c 73 ff 74 07 cc 44 49 fa c2 b5 bb"
        "da f8 1f c4 35 77 15 ae 7e ce cc e1 7d 9a 20 ae"
        "0d 32 9e fe 11 1d b9 f8 b6 d2 b2 0a 5f da 18 6b"
        "f4 2d 8a 13 d5 6e 02 d3 65 20 95 9b 41 e9 83 48"
        "7d 5d 16 1e 33 fa ee 7a 19 d7 b5 fb a2 8a ae ad"
        "9d 74 17 1c b1 26 35 0f bf 71 18 cc 6d ab ca 57"
        "bb 0c 7d d3 fc df 6a e4 e9 a8 ee f7 9c 95 dc 1d"
        "7c bd 0e 80 f6 0b 38 97 9f e1 6e 47 33 f9 e1 b8"
        "72 b0 87 62 7b 92 01 8c d4 8a e5 9d 8f bc c1 9c"
        "07 e5 0b 13 3c e5 c3 17 48 8c 4e 6a a3 5c 77 53"
        "67 54 36 8c 79 2f 15 92 39 b4 db 89 f7 69 e2 1e"
        "96 43 f4 8e cb 6d 24 75 d8 34 ae ca 01 1f 06 1c"
        "df 16 71 6d 89 d5 fd 27 da 39 cc 9e 42 62 f9 9a"
        "b6 9a 81 6b 93 74 06 8e 1b 36 a6 c9 75 55 80 9a"
        "d5 17 09 40 ff 35 f2 df e3 e3 c3 a4 b4 15 5a 28"
        "2e 6d 05 72 76 10 eb 04 3a de 76 eb fc 7c ae d6"
        "40 84 c9 54 e8 3f 85 e6 25 d8 5e bb 9a fa 88 85"
        "69 68 d5 11 33 80 ef 29 31 17 06 16 2d 33 09 9b"
        "0b 81 6c 45 7a 5c f4 de ef 8c a4 48 5c d6 af ed"
        "c1 93 9a cd 2d b8 67 62 53 b1 88 b3 4f cd 03 4e"
        "de 97 2e 33 38 9c bb 9d 50 a1 31 f0 b1 55 2a d9"
        "bc bb 44 11 e8 71 f0 77 8a c0 ae bc 2d 43 99 53"
        "e3 c2 e4 92 e3 c4 ca 08 80 55 95 92 de f5 cb 91"
        "d3 96 39 b1 24 64 54 1e d2 be 34 af 9c 75 50 d4"
        "f3 ff 6b 12 bc ff 8d f2 40 d2 1a 96 1e be 50 8f"
        "1e b8 22 83 d3 23 e0 d5 7a 82 ee 4a 90 49 65 94"
        "9d c1 32 c0 f5 82 3c e0 1d c8 4d 14 46 6d 6f 56"
        "43 ac 8d f7 be bb 10 9e f0 30 89 f8 6e 35 4e 26"
        "02 52 4b 68 0b c4 b5 d6 8e ef d6 05 31 3d cc ed"
        "f4 5b 09 ce 4e 95 94 7f 36 7d 42 d4 28 51 05 ab"
        "63 2b 5a a7 3a 57 a4 cf 93 8c 39 e6 6a 84 e7 f3"
        "47 7a 38 fb 91 33 ed 74 da 81 58 a8 76 91 5b 60"
        "b8 c5 48 5b 81 57 7b 1b 25 ae fd e3 be d8 13 01"
        "02 14 51 f1 9b 49 26 e5 c5 94 a5 12 bc 1c 81 60"
        "d7 e5 d2 05 a5 fc ed 97 46 c4 39 38 53 78 3d 64"
        "b2 8e d8 eb 2e 16 18 39 cf 80 f3 b2 fc 01 94 aa"
        "9a 00 52 39 0c 2b d6 04 c4 34 af 30 d2 4e 63 10"
        "29 9e 2f 3f 39 57 b6 cc d0 cd dc 77 fd c6 be 49"
        "31 fc 26 f7 20 af 39 f2 ed 6a 64 3a 57 ef d4 57"
        "14 47 23 7b 8f 9b 4d 06 a4 14 10 0b 8c a3 ad 58"
        "75 ca 83 74 1f 32 90 80 f9 88 8a b7 0e 2f 9a 13"
        "62 f1 bd 34 9d 9d e3 24 43 1a 67 11 03 b1 0e 20"
        "16 49 35 0b b5 d7 e9 31 3d 24 56 a0 93 97 32 13"
        "d9 e9 a5 de 55 6a 24 c3 49 fd bf 45 f7 d6 59 d7"
        "76 47 a0 d0 dc d7 2c 46 a9 4b ee ca 6f 76 d0 b3"
        "23 b0 1f 72 fc a8 56 7c 31 cb b3 02 3b 8c 10 4c"
        "24 18 6b fa ea f1 97 87 d3 5d a4 d8 0b 31 0a 0e"
        "27 b8 1b 99 8c d9 92 ca 05 58 eb b4 86 42 55 91"
        "d7 3a 38 e9 21 9b 17 47 1f ce ac 98 d6 6a dd 9f"
        "23 e7 c7 51 d8 6a 9b 47 26 7c 51 8d 6f 44 99 73"
        "bc 39 ed e4 b8 8d d7 fd f6 60 d1 56 44 e6 f1 68"
        "96 84 eb 8f 93 75 9b 68 c0 31 5b 4f 38 76 a2 ae"
        "d6 d9 fc 41 98 12 4b a9 a7 66 7f 11 36 cd 04 e2"
        "47 c1 ec 79 3a 2d 5e 16 e9 4a fd 60 f1 b1 92 fa"
        "fb 9c 1a 15 88 4e 99 a9 7e 99 b6 a7 36 93 80 e1"
        "4c 20 29 e4 ee c3 30 e3 f1 04 2a ac c2 31 70 da",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 1200]
        //     QUIC Short Header PKN=17
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..00 = Packet Number Length: 1 bytes (0)]
        //         [Packet Number: 17]
        //         Protected Payload […]: ...
        //     STREAM id=0 fin=0 off=2347 len=1178 dir=Bidirectional origin=Client-initiated
        //         Frame Type: STREAM (0x000000000000000c)
        //         Stream ID: 0
        //         Offset: 2347
        //         Stream Data […]: ...
        //         [Reassembled PDU in frame: 45]
        from_server,
        prot_quic,
        "WIRESHARK#40 QUIC STREAM",
        "41 c0 db 16 e6 bc 9d 45 9e 30 88 e7 5d 80 33 ee"
        "6a bc d7 12 fd fd b8 45 7e 48 8d 51 2b 3c 36 9a"
        "13 6a dc 1b 6e 12 8d 49 e5 08 f2 ca 2a 99 68 79"
        "4d d0 19 f3 db 6a 2a e0 92 05 c9 0c 41 9a af e2"
        "f0 bc 0c 10 8d d7 58 71 0c 5b 99 75 c5 3d 79 e4"
        "9f 89 06 58 5a 31 fd f0 bb e2 b7 33 4d 02 e7 8e"
        "43 55 17 bc 2f da dd 6d 13 0c 5a 36 94 4c 18 d7"
        "c4 0c 3d bb 63 6d 4e c4 cd 35 b9 f9 36 87 60 1a"
        "ec 5c 1b 79 c6 5f b4 9f f0 45 a2 9c 62 c5 85 10"
        "36 0f 26 dd 1e 35 2c de 31 28 f8 3d d0 b2 f9 50"
        "0a 42 70 21 5c 5b 89 2c 42 f5 c1 63 2b e4 7a 2e"
        "83 72 8e 3b cd f3 21 7a 8b b1 bb 9b 82 3b 9a e9"
        "b9 fe 9d 59 b0 fc 8a 68 25 e0 de 3a ff 73 fc cd"
        "a4 19 b5 7c 61 05 eb 95 87 7f 6e 77 6d e8 b5 a8"
        "18 e6 1c f2 af 51 49 83 4b f9 5f 8d 55 b2 85 1a"
        "73 0c 8d 93 50 06 88 15 ab c0 9f 21 63 f6 4b 67"
        "8c 01 0e f0 61 9a ee bb cd db 22 4e 1d 3b 70 1d"
        "f6 42 81 f4 21 3e 1b d7 77 18 d6 18 f9 e8 96 a1"
        "f7 3d 11 32 1a 39 45 5b 4d 09 25 6b de 8c 59 44"
        "2d ac bf 74 04 ea 9b 1e fe 14 18 56 d1 2c 9c f4"
        "74 6a 66 dd d8 d5 48 0d e0 46 b7 7d b6 ca e5 93"
        "90 a3 7f 7e 5b 24 ec 00 0f 95 63 17 5b d6 79 fe"
        "67 78 e9 3a e8 83 88 60 ee c1 ce d4 39 a9 71 eb"
        "d9 c2 57 1e ec ec 35 9e c5 6d f9 f5 be 13 18 5c"
        "ce cb f5 93 29 c0 d8 ee 4a ac 32 b9 40 fc 84 75"
        "03 7c c8 89 94 09 8a 3d 6e 2d 80 6f ba 70 fb 20"
        "82 55 29 f1 01 03 1a 38 aa f9 06 c9 e4 a2 f9 d4"
        "00 12 03 e8 e8 c1 ee 20 11 9d 1c f9 a2 35 16 03"
        "f9 bb 17 91 6a 44 95 c1 9f e7 bb e7 bc 7a 90 2f"
        "35 53 04 20 80 7e bc 32 44 63 3b dc ba db 1b 5d"
        "2e 6d a8 1b e9 49 fa b3 aa 13 74 4c 8e b0 43 50"
        "b1 3c 04 db f4 8d 63 48 42 94 03 b9 fe 58 6d 4e"
        "7b ea 45 87 6c dc ae 02 9a 92 7a 08 04 09 a2 c4"
        "93 dd fb 15 52 c0 e7 e8 70 d4 e2 18 c6 40 61 cf"
        "5c 53 09 3b e9 21 5d 29 58 08 db 1f 1d 52 cd 16"
        "dc d2 89 91 1f af 6c 49 44 62 88 3d df 16 b1 48"
        "44 ee a4 35 40 7a 2b 0a 6e 43 3e 68 0f c3 53 9a"
        "24 19 eb 0e e4 7a ac 87 7f 1d 24 2f 13 d9 05 39"
        "50 3f cb 38 2b aa c6 cf 53 bc 4c 41 b5 24 4c 37"
        "4b 68 05 46 ed 00 be 8a a5 95 6e b3 4a d1 8c 39"
        "ee 52 2f 23 5f da 3e 80 7c ac 69 18 1b 65 d4 ac"
        "c5 bf c3 3f 2e bf ea 06 09 c2 11 75 b9 d3 c3 f7"
        "73 f1 dd 72 2d dd 43 0f 48 a2 d2 11 89 e9 04 54"
        "18 ee e8 8c fc 8c de 34 50 71 b2 6f 3b 26 c0 d2"
        "17 e6 99 13 7c 52 b0 ab e2 f8 d2 13 32 7d 6e e6"
        "d2 e8 7f 46 5e 64 01 88 cf 94 9c 55 11 82 56 ac"
        "60 38 00 8c 99 bf 49 09 a0 ae 6f 3c 8c 87 89 ab"
        "fe b3 0d 26 8b c4 45 62 69 1f 04 3d d8 bf 90 36"
        "71 d9 17 11 77 85 25 0d 71 b0 ff 52 c5 e4 bc eb"
        "66 9b 5b b9 b4 d5 c4 f0 d1 f2 d2 a0 3d ee 9a e7"
        "28 de 50 5f 0e c5 a8 c9 b2 27 0f 5f 79 29 9e 3e"
        "0f dd 88 f0 41 b5 e2 1e c5 73 28 9f 21 cc e5 ed"
        "bf 69 56 a8 af 09 5e 28 d7 d7 b3 5d 87 bb e3 ea"
        "f1 ae 61 ea c1 26 7b 1d b4 18 ff 57 44 de ed f7"
        "62 fc c4 a8 2b 85 cb 94 c0 51 06 b2 8e bf c1 4f"
        "bd 22 1a 5f 3d 6e 34 d4 1d 9f f9 13 c7 ae 57 04"
        "21 04 43 46 52 81 0e 10 94 d0 91 21 bd 37 c3 1b"
        "14 e8 32 74 22 ef 09 a0 b7 6a ee ad 52 65 8a dd"
        "5d a2 11 ed 82 ca 15 2c 78 8c 4f cc 73 14 ea e5"
        "0e 9b fa 32 91 14 06 06 cb a3 e2 59 bf 35 93 1b"
        "cb 1a c2 83 ec e3 33 e3 81 9c e3 1f 1c c5 4a eb"
        "ef 1d 35 1a d8 fc 81 14 f7 d5 e1 ec 97 7c 37 13"
        "bf ca d9 c0 b9 9f 6b d0 01 ce 8c d5 6d 19 91 b0"
        "ce 42 a6 25 c4 84 18 8d e0 d9 bf d3 b1 31 a5 f1"
        "a4 75 b1 59 5c 24 7b 31 7b 77 c0 3e f4 da 31 1c"
        "f8 78 02 55 34 49 9a 9d 47 04 7c 4b 5b ef 01 1b"
        "cc 22 f7 73 83 88 30 53 33 9e a1 32 85 15 23 a4"
        "5a fe cb 12 da db 64 31 bd 8a c9 ff 73 02 a2 78"
        "42 43 34 c4 85 80 15 27 91 5c 31 c6 ed 28 91 84"
        "a5 22 ff 60 01 d9 eb a5 ec 10 12 c2 bb c7 ec d7"
        "e8 90 90 e7 66 81 e8 8b fd d8 a6 d9 be f7 fe 75"
        "f9 e8 ee 59 2f 85 18 de 40 c8 99 eb 70 87 e1 d8"
        "9b e1 ac a2 bc 02 98 ef 28 92 16 4a 7c 31 9a 13"
        "11 dc 7d 9e 7b 81 70 81 f2 ed 9e f0 c4 fe be a0"
        "65 27 c5 18 3b 7e e7 bc 28 b7 b8 19 84 a9 13 5c",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 1200]
        //     QUIC Short Header PKN=18
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..00 = Packet Number Length: 1 bytes (0)]
        //         [Packet Number: 18]
        //         Protected Payload […]: ...
        //     STREAM id=0 fin=0 off=3525 len=1178 dir=Bidirectional origin=Client-initiated
        //         Frame Type: STREAM (0x000000000000000c)
        //         Stream ID: 0
        //         Offset: 3525
        //         Stream Data […]: ...
        //         [Reassembled PDU in frame: 45]
        from_server,
        prot_quic,
        "WIRESHARK#41 QUIC STREAM",
        "55 a6 d7 dc ad 2a 75 95 12 91 53 28 3c fe 7f 00"
        "a8 f1 25 0f 83 f8 16 40 ab 86 0e f3 29 9f 34 51"
        "a9 be e6 6e bb 44 2b 5f 3b a7 38 3e b0 83 e4 39"
        "34 99 be 30 f7 c6 1b ca 18 bb c1 17 c2 3e e9 24"
        "f6 cc f6 0c 05 7c 8d 84 9c fc 89 28 60 1a a4 97"
        "10 36 3e 3d 11 75 bf 46 af 02 a1 10 d3 74 af cd"
        "78 d7 a5 1b a4 b8 bb e3 dc 46 72 80 37 f9 b3 be"
        "80 51 34 dc ca 93 cb 4b 10 f7 1e 24 f1 0e b5 d5"
        "6f ad 12 58 ec 5f d0 4c 27 b8 3c e6 97 c3 14 48"
        "d4 58 98 df ac 31 52 ed 0a 1b 67 14 4f 23 aa 12"
        "9a ab 04 82 85 bf 62 d8 8a ee a2 fe ce 2a ca fe"
        "22 5c e3 28 22 85 4b 3d b2 e7 2c 74 62 04 bc c0"
        "53 8f 95 f6 3f cd 23 b9 b7 7d 5f c3 0e 0c b4 3c"
        "4b 20 30 b2 5a ac a7 2d 97 97 bb 75 2b 1d 16 c1"
        "bb 2c 4b de 05 76 0c c4 14 b8 93 a8 da 90 63 86"
        "80 59 f3 51 e3 51 dc 31 d6 07 47 05 91 b4 2e 87"
        "c0 f8 fa a9 91 76 41 e8 5b 0e 66 26 d7 2b 88 cb"
        "89 1d c3 89 af 66 2e 09 82 bc 0e 58 ab 1c b1 cf"
        "46 18 f0 fa 33 77 60 de da bc db 52 64 a4 e2 e4"
        "27 11 04 eb 7a 74 9c 43 ed c7 31 f3 82 15 0a 21"
        "dc c8 4f 66 ac 24 70 39 62 1c b9 38 5a ac dd f4"
        "35 65 2e 87 ee 67 49 e2 54 ff 8c c6 b0 59 06 84"
        "78 bd 87 ac 2e a1 a3 b6 20 bc 40 60 9c de 11 c8"
        "21 b0 30 4d 28 63 ca 8b 88 d8 fa b5 48 2e 50 ab"
        "4e 50 92 69 f0 e7 74 98 ae f9 e4 d4 df 40 e0 e8"
        "bf 4d 9a 8f 66 8d e9 c4 49 64 a3 07 d8 a6 9a 23"
        "8a 99 98 c8 1d ea d9 67 ff ac c1 cb cf 34 c0 e5"
        "81 3f b3 19 8f 2a 6a 7b 31 a2 e0 47 73 60 1b 19"
        "99 31 58 6a 25 0c 6c 35 51 4f bb 13 cc 4a 15 b4"
        "59 85 83 36 ab 88 76 f7 03 24 bc be b5 34 cb f0"
        "96 8b 97 08 ac 93 8a 2f 3d c8 6e af 32 35 2d 5a"
        "80 aa 0d e5 1b d1 4c 05 88 04 72 10 68 5d 66 cf"
        "c9 07 98 5c 94 ec 61 df 86 48 ab 6d 5b 86 78 0b"
        "7c 13 6a 77 54 05 92 13 61 07 51 f4 78 3c ed 63"
        "c6 0f e4 3e 5d 12 d8 92 96 83 04 64 b6 45 2f 43"
        "25 3e fb 9b bc f3 b1 96 c2 d0 0a 22 de 22 01 12"
        "b6 78 b5 f1 1a b8 33 91 b9 ba 73 92 7c c4 cb 90"
        "43 e5 1d 88 86 9b 22 c0 d2 d6 49 bd 2c 37 aa 04"
        "34 a6 17 6f 56 8b 00 58 3a 56 d5 fc 4e 9e cd 67"
        "84 d4 46 d4 f3 bc 88 c5 22 3a db 7d f0 e7 c7 03"
        "39 c5 e2 41 84 1e a2 04 9c 60 36 15 6b 58 23 3f"
        "7c 52 b3 00 34 df 76 3d c6 d2 dd bf 14 c0 1e 7c"
        "66 63 df 6c 4d 7f e1 a3 5c d5 7c 86 83 f2 00 d9"
        "ea 56 5c 2c 46 8f 41 c0 21 b9 38 6f 4a b5 b7 16"
        "c1 0e 8e 68 59 67 83 5d 92 a9 be be e6 51 28 4d"
        "39 59 a3 87 4a 52 9e b2 54 9c 6e 57 c4 48 b0 d9"
        "d9 4b 4c 0b 5c 18 f0 11 3c 0c 89 9c bb c0 b5 53"
        "cb 04 58 1e e8 98 29 bf 93 f6 fd 81 f1 fb 48 34"
        "bc 06 55 e0 73 55 16 46 fd 45 73 b5 34 e5 c8 c9"
        "59 b7 25 8e f0 4c 91 b9 41 e2 07 59 c5 2a 64 fa"
        "76 5b 52 5b 15 a3 f5 02 3e c8 be c9 45 0a 36 2f"
        "35 90 68 f2 7f 8a b7 45 bb 0f 41 84 23 69 9d 23"
        "4e 2c e2 b1 8f bd 8d 64 76 8d 28 d5 c4 3c bb 07"
        "ea 6f aa 6f 6c 71 cc 7e fe 26 c2 2d ce 50 d0 60"
        "ae 0e 75 de 31 1e 96 45 ec 05 a7 60 0f 8c 18 c0"
        "7a a2 05 53 38 de 41 22 6b b0 8e 1e 9b a6 b2 b8"
        "7b 08 4c 2b 4a 74 d7 94 d2 db f1 10 59 4c 59 32"
        "e2 db 13 0d e6 fb 6a 54 0d 1d fb e2 9b f7 5b 21"
        "07 e1 f0 b0 26 26 ac 52 c2 94 4e 28 74 fe 99 67"
        "0b b1 20 b6 b5 7d ab ae 3d 2a b6 c4 d5 c0 fd b3"
        "d8 6a 80 6a c2 ee f0 bf 49 7d 40 be d3 ce 5d 01"
        "43 df 3c 7c df 25 56 9c 6c ba 94 c2 5f 53 81 e5"
        "29 9e 89 13 13 2e 38 6d b6 70 65 4a 4f dc 42 8d"
        "9b 1e db 8e da 5e ac 69 47 de db b7 85 de 6b 23"
        "71 67 e4 6c 85 18 be b5 24 a6 16 0b 41 83 04 62"
        "df 46 89 68 70 54 d1 16 65 4b 8f 2e a3 ed 95 15"
        "48 ac 1c 34 ad 4b e1 06 43 cf 47 33 4d 93 2d 21"
        "8f f1 ce d3 d1 f1 f5 04 26 1a 52 78 26 64 5a 3e"
        "3d bc fe 0a a3 2a 95 8c 0f 70 82 f6 8f 96 64 77"
        "bf 7e f4 c4 6b 00 ab 6e c4 95 fd b5 33 ad 55 d0"
        "5e f8 7e c0 ad dd 5f 10 f9 72 87 bb 50 5d 53 1d"
        "6c 2b c0 56 b2 6d 8a d6 5e 05 4c 6c 30 2e 83 d7"
        "3b 6d a0 b1 f7 71 82 7a dd b4 4d dc cf 08 1c 0e"
        "3e 28 b5 88 69 be e9 de 0c 2b 07 5f 8c 6b 1b e1"
        "aa c0 22 fd 8c 1d c1 bd ba a0 2e f1 7b ae 8a 92",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 1200]
        //     QUIC Short Header PKN=21
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..00 = Packet Number Length: 1 bytes (0)]
        //         [Packet Number: 21]
        //         Protected Payload […]: ...
        //     STREAM id=0 fin=0 off=7059 len=1178 dir=Bidirectional origin=Client-initiated
        //         Frame Type: STREAM (0x000000000000000c)
        //         Stream ID: 0
        //         Offset: 7059
        //         Stream Data […]: ...
        //         [Reassembled PDU in frame: 45]
        from_server,
        prot_quic,
        "WIRESHARK#42 QUIC STREAM",
        "40 5f a6 de 6c 3e f6 79 6f 33 d9 cb 91 5c 64 50"
        "44 46 34 ce a0 d0 41 f0 f6 3c 08 19 d3 ca 39 2c"
        "61 f4 3b 03 79 e1 77 d6 97 bc a4 fc b0 88 ce 5e"
        "35 76 f9 d1 c9 30 8d af 12 82 5c 06 40 fc 7a b9"
        "a7 c9 c8 b0 28 b5 3c 7b 18 62 0e 31 1a ce f9 f8"
        "10 1e 1f 32 13 1c ec 4a 50 26 45 df 56 70 0c a2"
        "97 bf f4 30 0e 5d 2f 78 6a 6d 1d cf ec f1 cc 29"
        "51 3f c3 40 3d 20 2f af 29 be ae 71 d2 2d a6 62"
        "9a 1d 66 4d 06 64 d1 ef 54 88 3c 8e 63 fe dd c0"
        "ea 22 77 5e ee 3b 13 f1 29 5a 06 43 b2 e8 c6 43"
        "d5 aa 3b 1a 5a 28 49 21 02 52 57 48 37 dc 0c 58"
        "bd d9 c2 d1 b8 d6 67 f8 1d e1 29 07 cd 18 9a 1d"
        "a9 f9 d1 f9 48 ea 48 9a 79 7a dd c2 13 d4 8e 24"
        "b9 85 9b 9a b8 77 d9 26 43 e3 3e 20 89 1b 8e 55"
        "0e e8 95 c1 e0 d3 ff 77 c5 77 34 26 77 be 04 1d"
        "9a 9d 91 13 62 7f b9 ea 10 db 6c ab b9 16 41 6b"
        "88 dd 7a 98 4e d3 b7 e3 d2 ac 07 2d 68 05 eb 69"
        "8a f0 1b 87 7c a0 5e b2 94 6d cd a2 ae 69 9b f5"
        "9d 98 8e 27 8a 02 5e ed e2 09 52 c9 1a 64 a7 12"
        "a2 8d 7b f1 cf 4b 17 cf 61 53 3a 05 e8 39 00 96"
        "28 43 7a 99 e9 98 27 1d ba 3c fb 7d 13 5a b7 2e"
        "f4 58 15 2c bd b3 77 fc 88 b2 bf a2 41 24 0f 80"
        "a0 b6 9c 46 56 77 f5 c2 d2 62 7d e7 98 12 11 c3"
        "a6 1e f3 2a 4b 85 47 5f 4c a6 9f 0a b5 a5 5a 8c"
        "2f 15 7e 77 9d 5d c4 2e be d5 79 d5 9d 74 b0 65"
        "7b 68 a0 42 b6 9a 9a 34 fc ac b3 41 36 6e d9 41"
        "cb c4 0e d4 2d c6 47 6d 74 b6 d3 11 ce fb a2 07"
        "a5 cb 7c d8 67 dd a7 96 d2 16 a1 34 af fe d9 38"
        "50 e4 06 48 6d eb 48 fd 17 43 cb a4 4d ee 36 e8"
        "0b ac bc 9a 5e 1b 0c 8f 09 6c cf 82 f0 09 50 59"
        "c6 ba ac b4 9d 6c 46 77 1e e2 a4 c0 5a b8 cd f2"
        "58 cb 4f 93 7c 93 09 e2 fc 23 5d ec 15 92 56 86"
        "1c b8 54 85 d7 c6 0b 93 71 93 d5 52 28 5d 54 37"
        "4e 4f 80 f8 01 d3 24 d0 e1 e2 d4 30 25 c1 f9 c3"
        "01 b3 90 f0 3d 73 95 10 a6 8f 0b 73 4c 25 e0 b1"
        "36 ea 97 a5 78 9a 15 32 fd 73 f1 c8 d5 ca dc de"
        "ba 9a c4 23 9a 50 8e e5 af de fd 18 5a b4 1d 9d"
        "42 25 46 23 36 c4 ca d9 dc 42 d5 e8 2a c5 e2 5f"
        "16 fb df 78 23 79 de 39 b1 15 4c 00 83 16 f6 cf"
        "80 3d c0 ce 45 ca 3d 1e 21 7f 51 68 0e 73 81 9b"
        "cb e2 55 18 9d 2f ae 1c 43 63 9b 91 ee 5f e7 4b"
        "47 8a d7 e1 2f 53 51 3e f2 7a 7c da 02 b7 1c c1"
        "8d 6d bc 92 22 92 68 32 17 e4 c1 e0 de b2 95 75"
        "db 52 5f d0 dd 05 6f 96 ec 5d d6 70 8f 55 ce 74"
        "55 76 2a a6 e9 b8 86 9a cb 74 9f 80 06 b6 42 77"
        "07 19 77 57 a1 03 0b 55 5c 0b 83 83 77 2a e9 95"
        "8f c6 1a df b7 ab 87 42 e7 91 0b 5c 5b bf b2 10"
        "f2 ac 5a 62 b3 95 7d 7c ee 95 d0 20 b5 bb 38 b4"
        "35 75 13 ed 82 e2 d8 72 7b db bc 5f ac ac f9 09"
        "e0 a9 b1 08 72 b0 7f 2a de 24 cf 78 a9 78 89 ee"
        "07 6a c5 9a 90 ea 28 a8 76 f2 62 87 9e 8f ec bd"
        "4d 57 f8 82 b7 df 41 b4 15 db e2 8f 20 cc 6f 87"
        "57 ba a6 02 37 63 09 7e df 55 bd 25 8f 6e af b6"
        "4e 6b 83 bb df d5 7f 0f b8 f4 59 4b fa 81 9e 42"
        "ae 3a 34 2a 56 c2 b1 e6 d6 21 47 53 4d 84 cf c2"
        "5a 80 3e ad fa ef a6 1d 2f 5b 4c 26 11 46 e9 d5"
        "21 29 51 95 3e f6 f5 96 3b 57 cb c1 20 b0 19 5b"
        "e5 25 1a 81 f6 9e 14 1c b6 84 5b 32 27 99 13 e8"
        "25 54 bf 91 33 1a fb c1 ae 31 93 0e 97 9a 3d bb"
        "52 10 a4 d1 ca 3b c4 0a 2e 3a d2 c5 57 ff 31 a2"
        "ad 22 0b 9d 00 fd dd 7e 4b 9c cd 22 d7 d6 7f 7d"
        "24 f1 93 51 86 6b 68 ec 3a e9 f9 7e af 4a f7 6a"
        "28 05 fe 03 45 bc f5 66 1a bd 7f 5d 54 e9 a1 38"
        "8c 10 7f 7f 1e f0 0e 7a 87 3f 8f 9e a4 bf 6a b2"
        "15 62 35 be 1d b9 1b 7d e4 be 43 a2 9e 13 da b1"
        "02 1b 66 f9 6a fc b5 90 c3 c2 cb 47 19 b7 c3 9e"
        "6c 94 fa c3 6d 2f 32 a0 10 46 fa 36 1c 52 bd 0e"
        "85 f5 d2 1a 9c 85 7b b1 6e 0a 90 b8 e5 51 97 1c"
        "7b 49 a6 c7 67 3e a9 a9 83 ba 83 c7 87 4a b8 e7"
        "08 33 47 bf 41 e9 51 24 a1 e7 1b ce 86 be eb 16"
        "a7 12 25 98 08 d6 35 ab ab 8b 57 d9 c7 49 6c b6"
        "3a 17 7c 16 d1 10 4a 49 dc da 27 d2 91 45 12 3b"
        "76 4d 85 65 cb 41 e5 f8 9f 2b 83 3e 63 a1 df ab"
        "91 ee 97 80 3a 1c a8 cb f9 48 cf 79 10 9d dc 77"
        "93 4a d9 92 b2 a6 c9 0e 1b 39 29 5a cf 5b d2 86",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 1200]
        //     QUIC Short Header PKN=19
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..00 = Packet Number Length: 1 bytes (0)]
        //         [Packet Number: 19]
        //         Protected Payload […]: ...
        //     STREAM id=0 fin=0 off=4703 len=1178 dir=Bidirectional origin=Client-initiated
        //         Frame Type: STREAM (0x000000000000000c)
        //         Stream ID: 0
        //         Offset: 4703
        //         Stream Data […]: ...
        //         [Reassembled PDU in frame: 45]
        from_server,
        prot_quic,
        "WIRESHARK#43 QUIC STREAM",
        "58 67 6b 51 c5 b2 59 e0 93 c2 ac cd 18 5c ef e4"
        "c2 6c 3e 97 03 a2 75 96 d8 08 74 e3 a3 dc c7 57"
        "39 e2 9d c0 dd 4b 0d f1 40 ba 26 ec 16 1d 89 32"
        "e2 ce 2d f0 f9 a8 f9 fc dc 4e 10 07 c3 bf 13 61"
        "ff f5 5f 2b 13 cb c6 66 7a c6 9a 8a 20 55 7a 4c"
        "b5 a0 66 12 da a1 d2 d8 93 51 29 8e 6a 6d 7d 12"
        "9f 58 05 5e 98 a4 b9 cd b5 17 de 04 b7 11 f4 62"
        "31 38 ee 85 f4 d8 7a 89 aa 8c 17 dd a4 91 6f 47"
        "7e e2 b1 ca 7a 83 e8 26 f1 5b bf b8 49 8d c9 a6"
        "74 f6 e7 8e 20 f4 2a ef 5c 31 ed 37 72 68 30 3d"
        "aa f5 bd f4 3e b4 39 a9 51 69 f0 72 b1 c7 cc f5"
        "3e 66 cd 0a b1 e7 5f 4d ab 90 da a2 78 3c ff 42"
        "5f 9b 5d ed 14 a0 76 f0 44 66 c6 95 1e 00 79 c4"
        "17 28 97 d0 00 43 b0 f9 6b ae 86 6c 77 a0 44 64"
        "ab c2 0a 1f ef 07 a2 7f b4 53 d4 19 d7 e8 49 a6"
        "59 2a 23 7b b6 8d 5b c2 b4 89 39 27 3f e6 fb 03"
        "3d 53 8c 4b b1 06 5e dd 0f 96 4d 0b 4e cd 94 1d"
        "19 01 39 d4 a5 9b c3 12 37 cc 27 41 2c 58 75 4d"
        "04 9f d8 f4 80 f4 64 da 35 49 5f f6 59 13 f7 4b"
        "32 19 ab 96 04 fd 6e 80 46 5d 5b fb 2f 72 8e 31"
        "08 66 16 44 af 6c 4f c5 9b b8 1a 38 0e c6 9c 80"
        "77 52 33 85 9a 36 dc 60 48 6b ea 4d 15 fb d2 4c"
        "1f 10 cf 5c 0d c8 82 7a 40 26 49 30 85 0b c0 71"
        "d0 07 cf 13 5a 9a 66 3f d0 25 6f b2 93 0a fe c3"
        "ae ac a7 ac c9 3c 0e 2e fd a2 cb c7 81 f6 d6 a7"
        "28 47 0a 72 88 6a fd 5e 52 5e d1 e8 b8 9f c3 2a"
        "6d f7 b8 cc 3e 26 53 c1 d3 c9 3a 6b d1 9f 29 db"
        "fe f1 77 de 6b c5 dd 26 fb 8c 46 35 9a d1 7e db"
        "5b aa 19 ce 49 b2 5e fc 3f e1 a0 50 5c da 41 c7"
        "f0 61 27 a5 91 e4 1f 2c da c4 76 89 ac ad b5 45"
        "35 da b3 d2 24 21 a7 02 90 cc a5 0b 89 f5 0e 24"
        "5d e8 12 62 a3 56 14 be 57 f7 9a a2 86 46 1e d1"
        "90 4c ea d7 50 2b dc c6 05 ea 27 25 b8 5d 57 96"
        "07 d4 b7 aa 4c bf f7 06 dc 08 87 5d 4f 5d 3b c1"
        "ec 24 5d bc 2c e2 1f d3 35 10 43 ac c0 de 30 f2"
        "2d 60 ea 94 9f c9 f1 81 f5 f0 70 1c 29 41 18 d0"
        "3b 5a a1 66 74 18 61 01 f2 e3 4f d6 1b 3d b8 a6"
        "24 db 09 f0 58 bf 52 98 cc 8c 32 e8 2f 24 ad 2a"
        "57 d0 de 61 e7 cb 58 32 7c 6c 0c 2e 53 ed db a2"
        "b5 f0 05 9f bf c4 1d 38 18 5e 78 d2 dd 91 e7 11"
        "8c b9 8c a1 ef d1 56 1e 39 58 94 b0 7e 1a 94 41"
        "f4 de 60 36 50 30 48 fc d1 d8 ce 3d d6 3a 87 d8"
        "7b 32 c3 0f 8d ed 99 e6 28 9c a6 24 1c 08 4e 23"
        "6f 02 74 1b 80 20 9f de c2 81 c0 d2 d0 f2 33 6f"
        "45 0c 37 be 9e 28 43 e4 fd 2c 5c 5e e5 2c 2a df"
        "b0 23 78 e6 fd 32 a6 cc 61 39 fc b7 63 dc 48 41"
        "e2 65 d5 90 0e 76 39 ec d7 6c 69 77 ac 59 5f 9f"
        "be aa 23 37 fa 80 e7 c2 44 b9 e2 ff 64 b2 9e a2"
        "66 eb 6e aa 88 56 0f 95 c1 e9 13 1b 6c 29 c7 24"
        "18 2a 34 b7 88 11 d0 f8 6f 09 c5 ec ab 53 94 6d"
        "8a 35 56 6b 9c 10 1a ad 7b d9 f0 90 57 82 3b 42"
        "19 e4 af 2c 8f 54 6f 51 fc ea 6f c6 79 63 c7 95"
        "b5 e2 01 3a 1c e4 56 f6 4b 31 69 a5 42 bd 89 a5"
        "be dc 09 56 1d 9f d9 5c b7 be ac bf 39 63 39 59"
        "e4 47 2f b3 00 bf 3a d3 be 8a cb 23 d8 82 79 84"
        "04 b2 53 d0 36 cc da f0 1f af 05 5a db 08 c6 7d"
        "75 4e a8 b6 b5 aa cc 55 86 ba cd bd c3 23 27 cb"
        "15 16 ca 0b e3 2c 15 37 2d 0c 96 66 d9 bb 0e 18"
        "01 9d 47 79 af 0c 98 06 9d 81 ae bf 2a 60 d6 bd"
        "86 6f 99 33 c1 e6 e8 58 06 38 05 97 77 1b 4d 07"
        "66 1e 6b 72 8f d2 50 6e 93 15 a7 1d 53 08 82 8e"
        "6b a0 5f f5 0c 88 ce 6e 63 f4 b7 59 a2 bd c5 4e"
        "c3 ac 08 ce c4 2e 89 53 80 79 df c1 fc 7c 25 82"
        "57 f9 f9 96 8f da ee 87 df ed 22 2a be 28 68 f9"
        "f9 67 6d 67 4f 35 fb 08 99 b6 50 ef 57 a9 ec 90"
        "e8 8a 7b b3 6f ad f4 92 9d bc 38 0e 2a 31 9d 73"
        "76 4f 2c a7 a8 d4 7d 48 10 6c 4a c1 29 ac 93 53"
        "40 c4 fa 67 a9 9a 3f 4f 81 fe d4 4e e1 56 fd 6f"
        "9a ba 87 96 42 87 b8 93 bd dd 81 fd 52 75 f5 0a"
        "4d fc 73 fe f2 34 b7 7c 74 98 df a6 d5 1a c5 63"
        "0a 33 f1 d4 ac 88 98 89 fa 87 ab cb dc 67 71 67"
        "cf 33 a9 c6 e2 2c b6 f3 99 32 99 49 9d b0 2b d8"
        "7d b9 ee 27 66 0f 13 bf 54 9a 64 cc 2d d1 2e f7"
        "b8 1d b4 2c b4 c5 02 e9 c1 67 4f e0 ff 00 65 d7"
        "d1 17 19 6b e8 d1 26 3f 3a 84 58 84 df 76 b0 de",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 103]
        //     QUIC Short Header PKN=22
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..00 = Packet Number Length: 1 bytes (0)]
        //         [Packet Number: 22]
        //         Protected Payload: ...
        //     STREAM id=0 fin=0 off=8237 len=81 dir=Bidirectional origin=Client-initiated
        //         Frame Type: STREAM (0x000000000000000c)
        //         Stream ID: 0
        //         Offset: 8237
        //         Stream Data: ...
        //         [Reassembled PDU in frame: 45]
        from_server,
        prot_quic,
        "WIRESHARK#44 QUIC STREAM",
        "58 e2 c9 ef 90 c8 6b 5f f4 79 49 fd c4 66 bb 24"
        "28 0f c1 35 b9 48 59 35 0d af db ee 2b 2d ab 4d"
        "ed 12 a2 52 d3 1a f4 98 ca 2f 7e 79 1a 99 c8 0a"
        "6b a2 4a f2 bd aa 29 80 92 45 8a c7 fd e3 e7 95"
        "bc a4 27 98 73 b3 9c 28 95 ab 1e 1f 32 12 c3 58"
        "79 cd 23 f6 15 4e f9 d5 0c 7c 2e c3 ba 2e 72 60"
        "ab 31 bc 5c 94 10 97",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 1200]
        //     QUIC Short Header PKN=20
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..00 = Packet Number Length: 1 bytes (0)]
        //         [Packet Number: 20]
        //         Protected Payload […]: ...
        //     STREAM id=0 fin=0 off=5881 len=1178 dir=Bidirectional origin=Client-initiated
        //         Frame Type: STREAM (0x000000000000000c)
        //         Stream ID: 0
        //         Offset: 5881
        //         Stream Data […]: ...
        //         [8 Reassembled QUIC STREAM Data Fragments (7528 bytes): #38(379), #39(1178), #40(1178), #41(1178), #43(1178), #45(1178), #42(1178), #44(81)]
        //             [Frame: 38, payload: 0-378 (379 bytes)]
        //             [Frame: 39, payload: 379-1556 (1178 bytes)]
        //             [Frame: 40, payload: 1557-2734 (1178 bytes)]
        //             [Frame: 41, payload: 2735-3912 (1178 bytes)]
        //             [Frame: 43, payload: 3913-5090 (1178 bytes)]
        //             [Frame: 45, payload: 5091-6268 (1178 bytes)]
        //             [Frame: 42, payload: 6269-7446 (1178 bytes)]
        //             [Frame: 44, payload: 7447-7527 (81 bytes)]
        //             [Fragment count: 8]
        //             [Reassembled QUIC STREAM Data length: 7528]
        //             [Reassembled QUIC STREAM Data […]: ...
        from_server,
        prot_quic,
        "WIRESHARK#45 QUIC STREAM",
        "50 77 88 d9 59 1f 29 0c 5f 5f 1c a9 6a 60 2a ac"
        "9f 1a 84 e4 50 ff 81 f1 65 44 54 cd fc ec 99 ec"
        "b6 4a a7 78 92 07 84 33 9d ca 9b 28 1f b2 36 47"
        "d2 c6 bb b8 fd d5 5f 8d 1c 9f b5 2c 52 57 66 43"
        "fb f7 ef 45 e1 c3 59 51 a0 29 c9 a6 76 27 91 74"
        "8e 16 47 b1 58 29 9a 20 74 d8 97 4d 9f 2d 26 8a"
        "71 f9 82 f1 79 ca f7 e5 b8 02 4e 7e 4d 34 1e be"
        "d4 9d 61 24 1b 1a c7 b5 e1 3c 92 f1 ee 47 d6 7f"
        "1f 00 81 74 2f 36 86 94 ba f3 92 80 e9 73 0f fb"
        "60 58 ad 37 74 09 a7 ec 23 fd 9e 25 fa 19 4e 45"
        "c7 e2 ea 5f 7c 42 e1 49 9c 26 0d 2a 43 ad e2 e5"
        "aa 1d 83 f9 cc 60 e1 db 18 d2 5a 26 05 50 3c ba"
        "d2 d4 c0 26 08 c0 77 ee 3b 2d 80 06 a7 3d 0e 57"
        "07 de 37 b0 48 94 a6 21 c4 be f5 4e 50 1a 4d 75"
        "82 8a 88 37 10 ab 6d 9b ac 95 5b b3 8d 5d 20 c6"
        "f6 d6 3f b3 dc e7 d9 6e 87 07 c7 f6 7c 40 69 16"
        "30 54 c4 58 53 1b b2 a4 a9 5f 71 ee 1f 39 1b 4f"
        "ff a3 6b e3 fd fe a2 44 b8 8f 14 b1 3d 93 6b 05"
        "c4 f4 49 a4 4b d2 80 69 53 2d 67 6a f1 24 43 a1"
        "20 1c 03 c4 6f c8 b2 f2 1c 7d 90 34 93 17 8c c2"
        "6e 29 98 0d 4d 1f 07 f5 a6 b1 b9 d7 4f 6f 64 57"
        "3c ab 7e 51 b3 5a 05 81 43 15 87 96 80 95 1c 7d"
        "f5 80 9d aa 17 02 f6 f6 7e 3e b3 51 e9 e1 3f e0"
        "87 9c d9 af 28 db 73 e2 db 4e d2 1b 96 1d c8 85"
        "aa 70 56 ad 55 91 ba ea 97 2c 82 e4 35 ba f1 27"
        "da 6b 0d b9 3b 1c 63 c4 bd e4 6a 33 49 9b 86 9e"
        "b3 25 b4 ab f2 94 b8 1f 6e 32 ad e4 1f fd e4 7e"
        "4d 92 69 78 b2 d1 af d9 31 b3 90 72 09 b7 88 b0"
        "64 8a 07 93 63 06 df 05 e8 fc 63 a7 b2 64 24 00"
        "5d f3 53 40 68 05 3f 98 52 05 a7 e8 6a 8a 5d 36"
        "02 99 88 b3 92 b9 9b 7c d3 2e 98 ea 95 d7 fd 3d"
        "24 a8 12 f9 93 f0 f4 23 df ec c5 96 ea 37 da 4b"
        "6d 37 22 84 a4 ca 58 2f ed 9e 7c 4a 06 71 a7 6e"
        "3f d1 70 e2 c4 74 84 32 f7 78 99 4b 6d e9 e0 5d"
        "da 00 3b a3 13 94 60 28 45 69 41 3b c1 94 3e a4"
        "74 a8 a2 6c aa a7 ab 49 f2 6a 6b 06 2d 57 ee 00"
        "53 33 f7 aa a1 5a 85 29 95 8b a5 16 e2 7d 58 a0"
        "f5 49 ec 6e 12 06 dc 03 67 d1 9f c4 55 fc d3 7b"
        "f5 72 f9 c5 ad 99 58 9a ac 7f 10 d1 46 19 d5 7b"
        "67 07 59 67 9a 2a ed e8 f4 41 8c 33 00 71 0f 3f"
        "92 7b 41 00 91 37 9a 92 dd f1 6d 9d 4f 56 d3 46"
        "d8 52 4d c2 e3 ed 08 2f 7c 42 e5 46 a4 17 05 ce"
        "74 1c d3 2e 9e 97 c6 1a 0d b6 50 14 db 67 26 bf"
        "cb 0a 9b d8 52 e1 d0 e9 f5 40 a2 6f b2 ad 66 64"
        "0a d9 c9 b5 8c 6d 37 94 66 ee d5 9a ea 9f fb c2"
        "d2 ec d8 9e b9 95 aa 31 fd 89 52 a7 16 b6 33 31"
        "a9 6f fb 49 7c 68 4c 5f ac fe bb 12 21 59 ba 4d"
        "88 15 76 d6 f6 87 93 d8 c6 b0 8f 2d 46 9f f2 c5"
        "24 7e 73 9e ba 8d cb 52 aa 87 de 2a 63 c8 d0 dc"
        "64 a2 3a f8 bf 16 2d 95 42 4b eb b5 bb c0 52 73"
        "43 23 91 ca 5a f2 a7 73 0e 36 e5 da cd 81 52 5d"
        "01 ec 50 cc 2f f8 b3 6e 37 d1 d7 66 17 49 b7 bf"
        "57 f3 84 af 7f 84 61 7b ab c1 71 5c d3 10 f0 05"
        "44 a5 03 cb 7e 96 92 a2 dc 97 48 8a 31 ca eb 10"
        "ff aa 5e 85 bf 6e 65 7d da f4 15 49 b8 33 66 b9"
        "87 12 39 b9 25 8a eb ca 6d ba a5 8d c5 a8 1c b6"
        "1b 0a b2 63 bd 02 8c 19 c6 f6 b3 8f 18 ea a9 90"
        "c9 4e 57 96 a0 a5 bc 45 4c b4 62 c9 a4 8b 45 bb"
        "b4 b5 80 50 85 14 df 07 ab ef 33 e8 73 65 6e 4f"
        "11 f9 28 1e f9 c8 ff 58 52 83 11 d9 ca 95 45 10"
        "ab 70 9a c2 a8 11 28 e1 6d f2 16 fd d4 57 d2 98"
        "b1 12 76 72 6f 39 b1 90 fa e8 e3 91 39 38 db 53"
        "b8 0a a4 bb f6 c2 98 9b fe 3c 4f 5c ca 1a 9a 75"
        "4f a5 af ee b7 35 78 7e c5 e1 c6 17 0b ef 91 16"
        "f5 8d ca be 63 b8 a4 54 43 a9 0b 31 bf 40 8b 77"
        "63 7d d4 64 62 0f 30 d2 6c 4c d2 36 7c 00 8f d3"
        "70 d4 81 a1 fd f8 29 e9 73 07 b1 74 46 cd 35 e9"
        "c2 c2 dc 9f 5a 05 7a 5e 99 84 ba da 63 21 dd 94"
        "34 e8 6d 67 82 86 09 ce 8a 4f 41 6a c7 21 dd b8"
        "b0 56 21 a3 09 12 2b 48 58 8e f3 29 7e 7d 97 80"
        "b8 67 da e4 9d 5d 4c 9e c6 fb e4 ca c4 c8 5f 30"
        "af f5 12 90 4a 9d e1 18 88 fc 40 c5 1b 70 11 5f"
        "37 6e 4d 46 28 c6 24 55 27 bf 00 e4 61 ba 24 00"
        "cd 99 5b bc f7 16 7a 4c ce 60 d0 2e 5d 53 c8 61"
        "27 b3 6d e2 45 66 dd 42 28 03 bb f5 1d 5e e5 cf",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 36]
        //     QUIC Short Header DCID=fe21df6a65e76e9e PKN=9
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..11 = Packet Number Length: 4 bytes (3)]
        //         Destination Connection ID: fe21df6a65e76e9e
        //         [Packet Number: 9]
        //         Protected Payload: 5118aa952eb339fd7cca24e35749c267096c511a4a22f9
        //     ACK
        //         Frame Type: ACK (0x0000000000000002)
        //         Largest Acknowledged: 16
        //         ACK Delay: 0
        //         ACK Range Count: 1
        //         First ACK Range: 2
        //         Gap: 0
        //         ACK Range: 5
        from_client,
        prot_quic,
        "WIRESHARK#46 QUIC ACK",
        "54 fe 21 df 6a 65 e7 6e 9e ca d5 cd 71 51 18 aa"
        "95 2e b3 39 fd 7c ca 24 e3 57 49 c2 67 09 6c 51"
        "1a 4a 22 f9",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 36]
        //     QUIC Short Header DCID=fe21df6a65e76e9e PKN=10
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..11 = Packet Number Length: 4 bytes (3)]
        //         Destination Connection ID: fe21df6a65e76e9e
        //         [Packet Number: 10]
        //         Protected Payload: 764a9fd4674faa70dc03f52fe3acf333beb3543755460d
        //     ACK
        //         Frame Type: ACK (0x0000000000000002)
        //         Largest Acknowledged: 18
        //         ACK Delay: 0
        //         ACK Range Count: 1
        //         First ACK Range: 4
        //         Gap: 0
        //         ACK Range: 5
        from_client,
        prot_quic,
        "WIRESHARK#47 QUIC ACK",
        "5e fe 21 df 6a 65 e7 6e 9e 5c e7 59 d1 76 4a 9f"
        "d4 67 4f aa 70 dc 03 f5 2f e3 ac f3 33 be b3 54"
        "37 55 46 0d",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 38]
        //     QUIC Short Header DCID=fe21df6a65e76e9e PKN=11
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..11 = Packet Number Length: 4 bytes (3)]
        //         Destination Connection ID: fe21df6a65e76e9e
        //         [Packet Number: 11]
        //         Protected Payload: 56610dead5a2ff39294b8045ce3712ea6b8b740435a5cf3e05
        //     ACK
        //         Frame Type: ACK (0x0000000000000002)
        //         Largest Acknowledged: 21
        //         ACK Delay: 0
        //         ACK Range Count: 2
        //         First ACK Range: 0
        //         Gap: 1
        //         ACK Range: 4
        //         Gap: 0
        //         ACK Range: 5
        from_client,
        prot_quic,
        "WIRESHARK#48 QUIC ACK",
        "4b fe 21 df 6a 65 e7 6e 9e f8 21 b7 9c 56 61 0d"
        "ea d5 a2 ff 39 29 4b 80 45 ce 37 12 ea 6b 8b 74"
        "04 35 a5 cf 3e 05",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 38]
        //     QUIC Short Header DCID=fe21df6a65e76e9e PKN=12
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..11 = Packet Number Length: 4 bytes (3)]
        //         Destination Connection ID: fe21df6a65e76e9e
        //         [Packet Number: 12]
        //         Protected Payload: 56e463abef466412df683b912c99bdfdd791c55750ed04dac4
        //     ACK
        //         Frame Type: ACK (0x0000000000000002)
        //         Largest Acknowledged: 21
        //         ACK Delay: 0
        //         ACK Range Count: 2
        //         First ACK Range: 0
        //         Gap: 0
        //         ACK Range: 5
        //         Gap: 0
        //         ACK Range: 5
        from_client,
        prot_quic,
        "WIRESHARK#49 QUIC ACK",
        "4a fe 21 df 6a 65 e7 6e 9e 9e eb 0e 08 56 e4 63"
        "ab ef 46 64 12 df 68 3b 91 2c 99 bd fd d7 91 c5"
        "57 50 ed 04 da c4",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 36]
        //     QUIC Short Header DCID=fe21df6a65e76e9e PKN=13
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..11 = Packet Number Length: 4 bytes (3)]
        //         Destination Connection ID: fe21df6a65e76e9e
        //         [Packet Number: 13]
        //         Protected Payload: e31bcc6d00d22b0bdad8c5d742af60f4ee47f47cc8a726
        //     ACK
        //         Frame Type: ACK (0x0000000000000002)
        //         Largest Acknowledged: 22
        //         ACK Delay: 0
        //         ACK Range Count: 1
        //         First ACK Range: 8
        //         Gap: 0
        //         ACK Range: 5
        from_client,
        prot_quic,
        "WIRESHARK#50 QUIC ACK",
        "5d fe 21 df 6a 65 e7 6e 9e 60 2a 34 19 e3 1b cc"
        "6d 00 d2 2b 0b da d8 c5 d7 42 af 60 f4 ee 47 f4"
        "7c c8 a7 26",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 162]
        //     QUIC Short Header PKN=23
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..00 = Packet Number Length: 1 bytes (0)]
        //         [Packet Number: 23]
        //         Protected Payload […]: ...
        //     STREAM id=0 fin=0 off=8318 len=140 dir=Bidirectional origin=Client-initiated
        //         Frame Type: STREAM (0x000000000000000c)
        //         Stream ID: 0
        //         Offset: 8318
        //         Stream Data […]: ...
        from_server,
        prot_quic,
        "WIRESHARK#51 QUIC STREAM",
        "45 11 35 a9 c8 ca c6 b5 bc 98 d4 69 9e d6 1b 97"
        "5c ff 90 2e 64 a6 45 92 d3 76 23 4b b9 77 2d c0"
        "03 d0 2d 57 5f 4b c9 e2 38 9b e2 14 41 a2 25 f7"
        "ce 8b 97 29 7a b9 64 86 d0 4d 3c 72 61 a9 dc 97"
        "ae 8a cd f9 1b 72 62 23 bd be 52 8c b5 5d a3 f1"
        "89 b8 6d eb 72 2d 26 6e 38 a3 0c ee 1d ae 19 08"
        "9a 59 91 91 63 aa c3 e9 cb 27 74 8d e1 d3 2a 8f"
        "aa e9 66 72 2a 58 a6 1d 78 f0 05 1d d3 a4 5d e2"
        "24 cb 32 c6 19 4c 4a 39 60 d5 9e 1c f4 6a 23 1e"
        "05 49 96 b1 33 3c 25 ff bc 3c 3f e7 7f 9a 22 ea"
        "47 05",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 1195]
        //     QUIC Short Header PKN=24
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..00 = Packet Number Length: 1 bytes (0)]
        //         [Packet Number: 24]
        //         Protected Payload […]: ...
        //     STREAM id=0 fin=0 off=8458 len=1173 dir=Bidirectional origin=Client-initiated
        //         Frame Type: STREAM (0x000000000000000c)
        //         Stream ID: 0
        //         Offset: 8458
        //         Stream Data […]: ...
        from_server,
        prot_quic,
        "WIRESHARK#52 QUIC STREAM",
        "43 fb b3 f4 8b 0e 58 6c 12 13 a7 03 48 70 f8 2c"
        "32 c7 f3 b1 73 b0 8d 55 03 98 23 c7 2d 19 c5 c7"
        "2b e4 40 9d 44 44 5e dd 03 fc 03 bd 1e 3a 05 bc"
        "7d e2 11 48 c8 b7 c6 c3 48 c8 26 54 01 db 53 be"
        "68 3f b4 5c 2d ed 77 e4 7a b5 43 9d 69 53 a2 95"
        "b8 74 78 71 e5 c7 96 ce 64 c1 09 66 2b 11 06 92"
        "1a 7f 8a fd 0a 6a c1 70 e1 a8 ad a0 53 3a a8 ed"
        "64 da 77 8a 9f 85 26 da 8f f2 90 5d d5 90 c6 66"
        "a4 32 0e 7b 98 7e 20 22 a3 6f 75 0a 12 bc ea 45"
        "5a 34 ed 8e 6a 9d 7a 4d 7f 01 4b 55 a7 f3 31 5b"
        "dd df 2c 83 22 a1 20 69 c5 2b 62 e5 4c 33 10 b7"
        "b6 6a 9d ac e7 18 30 b4 ee e8 6a 27 ce e6 e6 ef"
        "9b 89 f9 d9 94 85 6f fe ae 17 22 77 36 f0 98 04"
        "a1 38 4a 8d bf 91 aa f3 f1 9b 3b e8 a0 88 e7 5c"
        "89 d1 91 0a 63 1a d7 29 90 f0 87 d4 33 e3 6d 0c"
        "60 f6 0d 9a 78 3a 84 e9 4f 16 d2 f4 65 1b 19 c4"
        "b9 af f5 21 4c 65 12 4b 9c 17 11 08 3b f7 79 fa"
        "5c 86 b4 38 11 b8 28 26 f4 f2 c2 c3 dc 8d f4 fd"
        "06 3f c6 cb e2 c3 e5 9d 4e 7c 37 86 4d 80 5a d8"
        "86 10 22 41 14 4e f2 c9 31 59 75 fc 0a b5 07 bf"
        "28 8f 0d 86 f0 da ed 52 ef 7a f3 f8 10 34 dd a4"
        "29 24 f1 a4 85 ef a4 26 fb 1f 05 ee 7f f8 59 08"
        "c7 73 2e 95 f7 af 0a 9a 2f 3c ed 2e a4 01 1c d2"
        "56 9c a1 2b 21 f6 be 06 1b f6 ec bc 0a e2 ab c7"
        "3d b7 ed bb 34 b6 0a ac 45 88 a4 e7 4b ff 56 51"
        "17 9c 03 15 7d af 45 c1 97 43 a8 3d f4 d0 3c ba"
        "de be 18 60 47 03 25 2f b5 0b ad cd b1 ce 67 9b"
        "f9 6e c1 0a 81 3c 57 58 a1 70 f4 8b 35 57 70 cc"
        "12 e7 86 48 a2 ab 75 60 62 a6 fa 42 c5 17 10 f4"
        "b0 ae 04 a9 32 24 8b 61 6e be 1d 0e 0d 4d 5c aa"
        "88 69 55 2a 64 72 bf 8f 12 44 ac 88 92 83 01 32"
        "da 85 f8 af 4f 59 f6 13 1c 54 f8 7f 61 b8 f9 c9"
        "30 39 dd a0 7a 2f 0d 25 83 f3 5c 73 1e be 6b 7e"
        "70 63 48 46 a1 1b d6 9f 65 64 38 fd a4 eb 45 0e"
        "50 1f de 85 44 ea 83 01 2a dc 01 32 53 f3 1b dc"
        "df c4 49 2b a2 a4 5b ed 67 9c fa ee bf b3 7c 94"
        "57 21 66 d7 6d 7c 75 51 3b 04 6d 50 51 23 b6 be"
        "78 59 03 65 f5 b9 3b 71 33 a4 8f 27 da 4c 6d c9"
        "9f 98 1d 7e 00 fd 57 dc 84 37 77 5b 5b b9 52 58"
        "04 27 38 b6 5f ca b3 e0 11 b2 d7 6d 23 7e 17 b1"
        "0f ed ee 0b b5 9e fe 5e 04 61 7c d7 3a c8 bc 96"
        "14 1c d5 97 68 19 3d 56 ba bf b6 c4 57 e3 e5 eb"
        "bb 4e aa e6 ac 9e 23 16 eb 34 2f ad 44 cb df 23"
        "2b 4f b2 56 aa 5e 55 59 b0 40 c4 cd 50 21 66 ca"
        "88 43 52 8d bf 3d 2b c0 b4 ca 1b 7c 1b f2 73 91"
        "cd a6 c0 4b 77 1f 10 6c 50 5e 38 27 9e e3 7f b4"
        "62 a8 3b fa 29 09 bb cc e3 50 08 98 41 45 7c e0"
        "3f 6d ec e6 cc 33 43 ab 7e 8f 76 23 02 9a 28 c0"
        "67 3d 16 07 a2 bc f9 7e b2 c3 1e f2 f3 f8 d0 65"
        "6e 03 2e c3 57 6c c5 33 58 a2 83 1d a5 5d e4 cf"
        "21 52 3d 03 1f 58 96 9a c2 67 02 5b 7a 97 b0 d9"
        "6c 84 27 2e c2 2b cf 11 99 fa e5 35 fc 06 3b ce"
        "6d 29 6a 90 c8 76 b2 bb e0 9f 9a 31 46 45 53 0c"
        "0c f5 d8 83 fd d5 99 cf 09 cc 5c bb 0f 94 e2 cb"
        "4d 29 75 aa 2c dd 4d 9f 8f 5c fe 97 09 be 10 7f"
        "2b 02 74 91 92 a0 dd 25 ca e7 a9 59 9e 62 06 bd"
        "57 21 1a 46 2c 6f 68 ab 2a 8b 91 b6 e9 4b db a3"
        "52 35 44 88 e0 a7 ef 21 e7 4f dd b5 09 1d c4 f5"
        "94 a2 0f 71 30 7e 73 42 1e 36 d4 7e a1 01 c0 5e"
        "3e 86 09 f1 e8 b7 dd a7 ea 0f f8 c3 69 5e 16 f9"
        "42 63 ce 95 00 da db d0 ed 86 fa 77 a2 4e c5 b2"
        "cd 0e 48 00 ad d7 55 ec 3d 3b 72 4b 4a e5 b6 44"
        "1f 05 71 d3 1e 70 c1 06 6c 3c c9 1a 36 ce e7 81"
        "1f 24 05 62 01 f8 0b 15 3f 0c cc a7 d6 49 27 8a"
        "be 2c 61 3e 3c bf 2e 4b bb d1 b4 b1 83 3d f4 04"
        "91 c9 a3 52 79 02 6d fb 03 80 bf 46 2f e1 60 46"
        "72 52 1a 9e 14 af 41 43 9f d4 2e 5d 52 85 84 ec"
        "c6 eb ca 07 a3 90 8e 93 2a 96 da c9 c5 e4 5b c8"
        "2f 46 d0 b1 2a 76 63 6e 8a d4 8b ac 25 71 e9 69"
        "8b 47 cc e1 80 ef 39 09 c8 40 f2 24 33 e4 5b 2c"
        "aa 7e 1c 5f f4 12 31 69 13 29 06 7e 1e 94 61 66"
        "13 88 c2 05 2f ed 1b c9 42 e0 2b 53 8f 25 12 fe"
        "bf bf e0 2b 4b e4 e3 3c a8 bd 2d bb 6a 8b 4b 16"
        "db 60 3f ac a9 d1 c5 5e 7e 34 4a 8e fd c0 b4 4c"
        "4f 8e 8d 24 1e 52 72 93 35 cf 60",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 1200]
        //     QUIC Short Header PKN=25
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..00 = Packet Number Length: 1 bytes (0)]
        //         [Packet Number: 25]
        //         Protected Payload […]: ...
        //     STREAM id=0 fin=0 off=9631 len=1178 dir=Bidirectional origin=Client-initiated
        //         Frame Type: STREAM (0x000000000000000c)
        //         Stream ID: 0
        //         Offset: 9631
        //         Stream Data […]: ...
        //         [Reassembled PDU in frame: 61]
        from_server,
        prot_quic,
        "WIRESHARK#53 QUIC STREAM",
        "5d f8 f4 fc 6c 18 65 b0 9f 96 44 39 6b 35 b0 45"
        "58 6d 6c 7f f5 bf 9b e6 98 49 ba 7e c4 e0 b2 36"
        "c0 cf df 0a e7 76 d0 ec 14 c6 70 1f d1 53 6d c8"
        "35 53 bb f8 c3 16 bf a5 bd c7 ac 82 31 e1 f2 fa"
        "11 4c da 6a b0 d6 82 60 ad c4 39 a9 cb 8d 48 48"
        "90 10 ee 41 ff 9c 04 ed ee a1 ca 78 20 f4 ea f0"
        "2d 52 23 75 1d 8d 58 df 63 bd e4 a6 71 ac 29 32"
        "82 b8 01 c5 9a 93 7c 86 42 60 10 da 46 94 e5 88"
        "30 31 3a c3 90 bb c1 c6 d2 3a ee c5 fc 9a fc a9"
        "7a aa 63 76 15 23 f9 15 75 da 55 3b 98 26 4c 7f"
        "00 4f af 46 1c 42 0d 7e 24 ca c9 1d b4 3b 19 26"
        "be 7c 1e 2f bb 9f 87 19 f9 7a 24 7a 63 01 3f 29"
        "ce 2f fb 97 a0 cd 87 62 92 0c c2 d2 37 1a ef 13"
        "8e a4 0c 45 21 ea 4c dc 39 9c 76 2d 5d a9 7a 69"
        "59 7b ec d2 77 64 e6 17 17 bc 5f 7f 32 53 08 18"
        "c6 f2 fe d0 b5 bc a0 40 3a e0 45 71 0c ad 89 bb"
        "ba ab a5 e0 bf c6 83 19 02 6c f9 83 82 50 eb fc"
        "25 36 b3 97 a8 45 d8 a2 9f df 7d 9b 92 07 e9 c3"
        "32 9e ad eb 86 8e 2c 3e 1a 6f 00 d5 18 fb 36 5f"
        "e2 da 18 65 c4 8c 48 ec 8d fe ea ed 0a bc 33 c9"
        "8f 46 01 8a 88 64 e4 3b 78 ed 39 6f 33 f7 8e 10"
        "58 81 df bf 7a 81 c7 0b 9a 0c ec f1 af 1d 4f 36"
        "1f 3c 6d 48 e6 41 4b e0 df 61 d4 5b e3 37 0c 17"
        "2b 1e a6 e3 4d 7e 5e 17 51 3d db 1e b6 ab 81 c6"
        "d8 77 7e 77 f4 28 16 71 ba 1f 99 44 a0 5a c1 ad"
        "62 5d 59 46 68 45 bc fe a7 d6 82 d9 94 9b fa c6"
        "77 52 1b 89 75 21 49 9f c7 bc bd 43 21 95 8f 3f"
        "1a df 82 ca f5 bf 40 bf 4b d5 01 bb d9 6b c1 37"
        "01 e6 a0 4d f4 0c 98 f0 20 5f b9 d1 1b 4b 2c f1"
        "3d 97 55 30 bd a0 59 41 ce 54 50 e5 eb 10 1a f4"
        "34 2e c3 6d 02 31 b4 94 f4 27 7e 2d 94 f7 00 0c"
        "1d 7b fc 65 6b 72 ad 6b 27 6e ef 22 28 b0 00 39"
        "27 38 fd 9f 20 2e ab 59 f4 da 82 4f b3 dd d1 4b"
        "7a c8 d6 ac 13 7a ca 85 5d d5 e4 16 8d 3b 4c a1"
        "ac 71 93 fc a0 c0 74 23 c5 69 e9 ce 14 05 3b ea"
        "7c 4d 0a b1 1f d7 bc 5e 06 11 13 32 1c 76 17 07"
        "6a f4 73 28 b0 97 a9 13 64 ad aa e5 51 6d 9d 89"
        "c0 3e 8c 84 7b 49 2f e8 6a 02 a2 3c 9a ce 2c 08"
        "48 12 e2 cc e0 b6 30 9e 95 f7 97 9e b0 dc a3 4b"
        "ab 69 2e 2a 06 82 73 2a c8 97 4b b2 69 ee 99 eb"
        "b6 4b cd 70 1c e2 49 2f 4f 8e 90 54 d4 3c a4 09"
        "53 95 a1 b4 cc 95 31 e1 e1 63 06 fb 79 ed 30 64"
        "ca 8b f2 2d c1 1a fe 74 ee de 78 c9 1f e0 5a 38"
        "71 5c f6 92 61 48 61 65 2a 38 a1 55 3f c0 7b 7b"
        "23 2b 8b a8 53 ac a5 09 22 a6 b7 77 b4 e0 cf 32"
        "77 3a 8d b1 b3 98 c3 fc 0d f6 5a fd 51 63 0b ff"
        "c9 a4 30 e2 d2 98 f6 8f 2f 01 80 03 fd 72 6e 7c"
        "51 ea 12 15 c3 82 93 10 3a 6d 3e 3f 53 01 03 03"
        "21 94 7c 5c c5 36 a0 88 40 96 0e 12 8c 2c c5 5d"
        "ed 68 06 dd 9b 03 2b dd de 4b e5 22 4f aa 74 bf"
        "60 16 6c 23 f3 d1 04 95 d7 1c 03 32 bc fb e7 b4"
        "62 f4 92 17 39 44 c5 cf d3 bb c5 4d 73 7f ef 08"
        "77 8c 0b a8 e9 81 e9 d1 87 63 cd 5a ad a0 23 95"
        "f2 a4 bf 7b 61 a1 c3 d2 e3 8b 51 ef e2 9a 51 07"
        "4d 45 21 72 a8 0e d3 99 92 b8 88 f9 f2 1a c7 45"
        "f6 1a 55 ad fa 10 4b be 90 34 6f 82 16 f3 a4 0c"
        "ed d7 80 91 1c 40 a3 02 b4 3a bb 09 c4 6f fb 3a"
        "5a 4e 10 72 9f 2e 2b a6 7c 8d fe f6 c4 18 d3 df"
        "aa d1 99 ed d2 53 f0 c3 09 66 42 4c a0 e5 bc 5f"
        "cf 7d c9 e5 0f 41 b8 d6 b2 b5 25 ef 01 e9 e5 0d"
        "cc 32 ec 2d 14 a0 53 ee 8e 98 77 c1 ae a4 34 73"
        "18 f5 c5 2a 7f ac c5 bd 83 17 41 12 fe b9 67 f5"
        "f2 b9 fb 51 18 31 a7 63 a2 cd 6d f9 d1 81 27 1e"
        "45 d0 6d 51 16 b5 90 10 ec 75 0f db d0 8d 8e 1b"
        "a3 05 1e dd e6 06 21 fe 28 82 e9 72 95 3f 61 de"
        "f0 93 17 c6 1a 82 cd 86 0f 2d b2 47 00 15 ee ed"
        "06 4a e3 24 eb eb 71 77 c9 3e 2b fc c3 ea c6 30"
        "da 17 85 8b 66 06 d1 11 fa 5b 61 62 27 c7 fe 7c"
        "f8 6d a6 f2 cd f6 e1 0f 11 18 7c 03 ee 92 8e f9"
        "23 85 9e 7c 99 ed 02 6a aa 7f 3e 20 00 c6 22 39"
        "42 f5 16 f1 36 d7 12 65 a2 43 5d 89 c4 61 e5 12"
        "de ae ee b6 97 d3 4e ce 9e 07 f7 c4 c2 18 0b db"
        "d1 be a8 00 09 8e 6e f1 fa 82 d8 01 7c c1 cb d6"
        "dd 8a c9 b4 e7 d9 6c 3e 73 82 cc d3 ba 76 14 c3"
        "06 22 65 0f 86 f5 ba 28 97 3e ca 81 5e b0 2a ba",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 1200]
        //     QUIC Short Header PKN=26
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..00 = Packet Number Length: 1 bytes (0)]
        //         [Packet Number: 26]
        //         Protected Payload […]: ...
        //     STREAM id=0 fin=0 off=10809 len=1178 dir=Bidirectional origin=Client-initiated
        //         Frame Type: STREAM (0x000000000000000c)
        //         Stream ID: 0
        //         Offset: 10809
        //         Stream Data […]: ...
        //         [Reassembled PDU in frame: 61]
        from_server,
        prot_quic,
        "WIRESHARK#54 QUIC STREAM",
        "4a 20 42 79 80 3c 21 cb e8 26 31 d7 37 3e a3 3e"
        "16 8f 97 b9 8a b6 35 43 21 90 eb 49 06 af e3 f1"
        "41 37 3f a0 93 db 63 a0 db 6d bb dc a5 08 a2 2b"
        "b7 89 c5 b6 2a 30 fb 88 1c 12 dd a2 24 a2 6f b0"
        "95 b3 cc ed 74 2b 51 c0 27 10 f8 5b 11 d7 5f 90"
        "22 a6 85 68 91 c3 ae ad 13 f9 96 df f6 1e 21 a5"
        "2a 1a b5 c8 7d 90 b1 e8 d5 61 a3 51 66 51 3c cb"
        "c6 48 8c 40 ee c1 88 0b a9 a9 35 b8 00 98 dc 59"
        "c5 56 85 c7 63 9d a1 34 7d fb 46 c1 3f 76 33 b5"
        "9a 09 58 bb c2 e5 46 0c 1b 95 5f ec d1 3c e5 ee"
        "04 96 d6 2b 71 e9 a9 c3 89 ce ea 52 91 b4 ec cf"
        "0a a5 79 5f 12 17 74 2c 61 22 43 67 2e 1b 49 44"
        "90 6b 1a 56 d0 88 aa 13 58 64 2f 9a 5d 2c d1 50"
        "72 a2 24 86 4d d2 36 93 4f cf 35 14 91 19 39 91"
        "57 d4 59 ea 42 92 b4 2b d0 9d c0 74 0e b2 23 46"
        "24 e5 27 13 58 a9 c1 91 f3 b7 5c 22 b2 55 a3 2f"
        "70 d4 e1 2c 33 5e a2 49 d6 57 ab ab 0e fd 30 73"
        "d0 cf 56 b6 b9 c4 95 fb 09 29 79 44 ae ed 3e 41"
        "74 c1 e7 5f 35 25 d2 1e 71 1e 0e 23 be 4f aa f5"
        "6d a0 38 42 47 3a b5 d0 fd cb 6f 41 74 be 49 30"
        "47 fe 60 b9 8d 4f be 04 3b 1b 71 e1 b9 a3 fa 84"
        "9c 1d 3b e6 2c f4 f9 3a 75 a2 6f bb 15 0a eb ad"
        "5d d5 02 ec 28 4b e6 b2 e4 7a 98 3c 6e a1 e2 1e"
        "5d 9d 03 3e 18 b4 56 b3 29 1e ec 74 0d c5 a5 93"
        "87 14 6e 78 83 55 fc c5 63 2d 81 fe 0f f6 33 74"
        "d2 e8 1f 3d bd 19 ac f1 ec 87 80 38 64 dd 22 b4"
        "bb 00 29 09 7a 2e 26 6d ff 42 ac 1b c8 d5 8a 38"
        "31 86 a6 72 2c 5d bd 22 e8 34 dd 51 3d 83 63 5a"
        "b3 d0 e2 25 3f 41 10 1d d4 cf c9 51 38 98 e6 cc"
        "d8 00 83 d7 d2 37 fb 93 79 dd 8a 46 ed 3f 39 c3"
        "84 e3 1d 5c 65 63 19 ed fe be a3 60 4a df 34 ed"
        "b4 5f ad cc 43 86 42 0d f1 fe b2 67 04 48 15 72"
        "d2 4b aa 2d 3e 78 5b 90 a6 35 77 23 0f 68 c6 a8"
        "78 7a 1b ba 31 0d 4f a3 c3 4e ce ae 0e 13 35 47"
        "6c 58 e3 96 50 ed fc 36 de d5 c7 1a f4 6c 59 05"
        "77 74 c0 40 d7 e1 7a 90 df 9b 99 fd 91 07 f0 8f"
        "71 e5 77 62 e5 22 ea a4 9a 07 2a 95 f1 de 8a 1f"
        "83 1f 26 5c f6 8d 3e 1c fc 41 0b 12 60 48 f7 35"
        "f8 63 6a 83 5d 01 41 5a d9 49 8a c5 08 58 c5 5d"
        "bb a7 43 c8 5a 7c e2 c3 a2 0a aa 4e 26 ce c2 d8"
        "bd 73 fc b7 a6 39 e6 82 0a df 23 bc 4b 96 cd 5c"
        "8b fc 93 60 f6 80 b2 69 62 b6 fe 53 26 76 fd f9"
        "40 6e 71 f0 13 b3 3e 35 2f 9f 69 e2 33 69 fe 79"
        "96 e5 8e 3b fa 0e fe 69 50 e4 32 56 da e1 2c cd"
        "ba d6 01 f5 37 74 4a 5d 38 51 a6 5f 7c 50 45 c8"
        "83 55 ba 7b a0 24 af 62 a2 f1 e3 64 63 4b 3b 96"
        "ee d2 82 16 f5 01 02 aa d3 ae 6b 95 ff d8 5e 91"
        "ba da 0a 7b 7b 7c a8 83 6b 01 db 09 34 70 e1 05"
        "ee 42 50 95 fb a6 16 a7 eb a7 d7 3f 8b 6e 0d 4d"
        "aa b8 ab 7b a2 a7 d5 40 95 0e b7 86 57 9f 2a 60"
        "ce 91 c0 f3 89 71 69 a6 98 c5 96 cb 6c 8d c3 ec"
        "d1 82 9a 05 df 9e d6 24 da 93 84 bb 44 de bd 31"
        "ef 50 69 5a 74 54 2b 83 81 ec d7 e6 25 b2 93 15"
        "61 bb 80 f7 e8 97 83 3c 5c 94 2e 98 8b ea a6 af"
        "23 45 fb ab b6 60 af d4 86 23 75 af e1 e7 fe 70"
        "68 6f 59 ac 4c a4 03 d3 87 45 b0 d1 06 9a 36 b6"
        "e5 52 14 63 27 bb 49 b9 c5 f6 ed 9d 0f 36 22 25"
        "e2 6c d4 f0 8b 23 4b c7 ce 65 76 95 23 6e 9d 74"
        "2e 5b 9f c9 df 33 7c fb 67 fe 13 fc f0 2f 24 0b"
        "ce 12 1e 4d db ec 9d 43 b3 6f ac b0 63 e3 78 70"
        "5a e7 af 8f f7 ad 52 b7 00 ab 1b 57 1a 2c 6f 54"
        "c9 c6 76 20 f4 91 3c ed 4e c5 12 78 9f 7c ae f3"
        "28 7d 38 1e 7f a4 e9 60 e1 47 29 2e fc 7a d8 72"
        "03 5d 40 c0 1c af c0 94 8a d9 1b 5e 8e 0f 9d 84"
        "56 c9 6b b1 8a c5 04 3d 25 9b e3 52 ca 80 8e 1c"
        "fb bb 80 ad fc 99 ba 8d 43 42 c0 7c 64 83 93 53"
        "3f cd dc b2 7e d3 1b 4f 94 3d 76 c5 ad ed a5 4d"
        "f5 ca f2 8a ad 11 3d 35 43 9f dd 3b 73 13 37 7d"
        "66 3c 28 4b 6d 7a 39 d2 50 cb 78 73 16 d1 5c 34"
        "df 92 b2 af f2 e8 3b 4b 9f 38 cb dc 3c e4 5d 71"
        "a3 8d 66 ea 30 68 e4 e2 a6 20 88 0d fc f8 b4 35"
        "bd 8c aa 17 5a d6 9a 2a db f8 18 f2 00 f9 80 04"
        "36 0b 62 33 4b e7 5e 66 81 85 4e f7 1e 83 24 0a"
        "c9 e5 2d 98 6a 6d 86 85 5e ac 18 02 83 11 8d c9"
        "95 86 24 fd c4 0b df 45 a5 e1 49 f9 17 03 d7 87",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 1200]
        //     QUIC Short Header PKN=27
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..00 = Packet Number Length: 1 bytes (0)]
        //         [Packet Number: 27]
        //         Protected Payload […]: ...
        //     STREAM id=0 fin=0 off=11987 len=1178 dir=Bidirectional origin=Client-initiated
        //         Frame Type: STREAM (0x000000000000000c)
        //         Stream ID: 0
        //         Offset: 11987
        //         Stream Data […]: ...
        //         [Reassembled PDU in frame: 61]
        from_server,
        prot_quic,
        "WIRESHARK#55 QUIC STREAM",
        "56 42 f3 63 d1 6d 85 65 4e 3a 51 ad 31 69 31 cf"
        "7e 83 54 6a ac 5b 4a 40 9e a4 0e c7 71 9b a7 46"
        "d0 a4 b4 74 a5 0e 13 f5 1c a6 19 9e ab cf 5a 05"
        "e5 84 13 68 e1 56 d8 a9 22 d1 1d 33 73 79 56 14"
        "b0 b7 c7 fe 0d a0 47 fa a0 44 8f e3 e0 db b1 a9"
        "d4 6b 75 5e ea 2f 6a 0c 53 42 8c 11 d3 b7 54 2f"
        "ef ab 99 d1 a6 ac 54 b7 34 0b c7 c8 1d 80 30 6a"
        "59 17 bb ad 36 e9 4b 68 a9 a0 ee 51 04 76 99 9e"
        "b6 5d d5 82 23 23 1f 92 f5 ca 28 fc 6b b5 9b b4"
        "85 f3 3e c6 db 01 7c 8b 13 32 7a c6 da 4f fb 73"
        "50 85 3b c2 85 82 35 eb 8b 0f 7a 7d 63 06 eb 6e"
        "5b c9 11 47 9f b4 24 1e ef 31 a5 50 67 83 35 c9"
        "2f ee 0f 86 36 15 0b e9 20 be b3 36 d9 da 06 86"
        "5e 23 3b 01 e2 6e c0 b4 98 dd e1 b3 b3 0b f5 fb"
        "de ee 54 f9 4d c3 5b fa f9 46 0a 1a eb bd 14 f3"
        "40 40 04 fa df 7d 33 fb 36 58 87 03 5f 18 b8 f9"
        "f5 b0 ce d0 ae 92 c5 ce a9 45 b9 8b 0b a3 d9 d2"
        "75 79 4b 92 15 08 77 33 9e 91 45 b8 72 d2 f0 ab"
        "22 47 56 8f ad 53 5b a1 8a 89 45 77 b7 3b 4a 86"
        "48 b8 36 04 09 e5 66 1e c1 96 dc c2 ea b2 16 3d"
        "ff b3 0b 3a d9 4b 40 b9 32 89 1f 59 00 4d 74 ee"
        "44 09 28 7d 34 36 06 5a 97 7d a8 62 3c 4e d9 9d"
        "d0 fe 90 1c 97 d0 fd fb af 8f 25 84 76 f2 9d 4a"
        "1c 9a a6 3b 6e 04 67 f0 bb aa 4b 6a 09 6f ed a5"
        "d3 6f 4e 38 f5 99 47 6e 0e c8 1b 23 80 a9 f4 b5"
        "5f 31 59 cf 2e db 44 62 6b 3e 82 27 24 90 30 f7"
        "f9 be fa 1d a4 5e 77 cb 21 ff 6c bc fa b6 3b f5"
        "55 e4 01 51 95 2e 8d 02 5d 49 95 b4 52 f8 b0 b7"
        "a9 31 c5 16 1c d5 c4 a3 fa ba 2f 6f e0 9a 4c cf"
        "38 54 3f ce 98 28 72 7f d4 a2 4f 85 d9 12 9b d5"
        "92 99 8c 9c d5 5f 12 b7 18 16 98 f5 6f 95 86 91"
        "14 b4 cf 80 e7 21 fd 5a 16 8a 19 a6 d8 7d 60 40"
        "f6 bd fb 0b 36 99 a9 d7 c1 7a a1 97 1b 48 be ac"
        "ef cc 4f fb e0 97 8e f8 a6 e0 60 32 94 8f 0b d5"
        "73 b6 ce 58 0b 58 2b 90 6c 78 67 14 46 e8 10 f4"
        "98 a7 91 ef f0 89 bd ad ea 27 47 87 fa 77 bd 95"
        "e0 ba ba e2 4d 7d 23 f7 a4 6f 34 33 01 b1 ba 05"
        "c1 0d 94 4f e9 93 0c 1d f6 b0 1a 4a ac 79 f3 cc"
        "c6 f5 26 0f 26 36 a8 31 18 3a 40 e7 9d 1e 68 a9"
        "67 b9 da 11 c4 80 93 a1 e4 e1 f1 90 7c 96 36 d3"
        "32 9a 2d 68 82 d2 ba e8 a3 69 b6 cf 11 26 e6 b1"
        "04 21 97 86 0a f4 46 09 77 3c 7e 56 b0 28 59 84"
        "79 63 e3 46 97 38 be 39 92 62 37 8f f3 cb 74 52"
        "42 59 97 08 db 0b 8f 80 e0 c6 e0 53 90 1f c3 6e"
        "99 06 ba 2b 74 0f 68 ec 40 ba 9e c6 82 b9 57 63"
        "07 6d 4f e3 d1 f1 4f 28 78 70 17 0f 93 18 c7 33"
        "27 fc 7f 4b 4f dc d2 26 b4 41 ab ba 02 5d 16 da"
        "c3 be f9 f2 13 08 f6 8d 53 37 c7 11 68 c5 63 fa"
        "e1 72 65 f1 4d 2a 44 a3 43 e6 44 79 b3 9f 0b ad"
        "45 d5 65 a7 95 f1 e3 d1 16 58 4d bf c2 40 3f ec"
        "d7 cc 8d 2f c4 c0 fa d8 27 48 4c 89 1c f2 78 96"
        "f3 18 2b 53 bd 6b 9e d3 6d b0 a4 b0 0e e5 ae cf"
        "e0 b4 39 fa dd 39 a2 0f 31 f3 b5 b2 c5 0a b1 c5"
        "ca d7 86 cb 44 2e ed b5 54 4f 35 69 a0 50 d2 f1"
        "fe 84 06 b0 57 9e 9d a8 a4 6f 54 a9 94 ff ec d8"
        "e1 62 c4 03 b1 2b 8b 2e cc 43 d9 72 91 49 b8 43"
        "9f 69 ba 24 bf 42 7d 66 bc 67 51 ae d9 35 7a f0"
        "0a 9b 13 c4 e2 18 79 8b e3 26 01 f4 d3 f2 4a 58"
        "d4 0f b4 10 30 24 33 a7 36 f5 0f 9f 31 a1 68 98"
        "3e 44 24 14 52 e4 0d b7 df bc dd c7 97 f3 5d 0c"
        "e1 8c 81 fd f3 db 72 bc 6e f9 58 12 89 30 ae 57"
        "c6 44 7f 5c 08 79 4e 48 7e 24 e6 5c 83 1f c1 25"
        "c7 59 cd f9 fb 77 3f d8 94 fa d8 b3 11 51 ff 34"
        "85 58 5e 4b ac c9 69 1f 2b a7 5d a5 06 a1 71 47"
        "a8 d9 a0 66 c5 6e b0 e4 c1 44 73 07 a2 23 c1 3e"
        "6b 8e 73 09 c6 b7 84 6b 58 f9 04 bf 8e 4b cb dc"
        "9c 62 af 47 d7 05 c7 4b b3 45 96 2c d8 c7 78 ea"
        "06 77 0f fb 25 31 06 21 d8 c6 af f2 36 3e ef 95"
        "67 45 7b 74 a2 f3 16 fc a8 97 cb 14 db ee 3d d4"
        "38 7d 28 6d f1 7d 39 5c c5 cc 8f 6f e0 87 62 e6"
        "1c ce 89 ab 0f 68 96 f5 e6 25 55 59 12 1d f8 1c"
        "b3 50 7d 36 bb 03 6a ae 42 6d 6b 96 4c 65 b2 41"
        "cb 6e 79 c1 63 d6 22 5c 62 77 3a a3 0c 4a 30 24"
        "22 8c 01 61 4a a9 7b 51 58 f3 45 07 89 a5 d1 73"
        "01 f5 97 87 7f 0f c5 8b 7a a7 19 20 67 f3 fa 85",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 1200]
        //     QUIC Short Header PKN=28
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..00 = Packet Number Length: 1 bytes (0)]
        //         [Packet Number: 28]
        //         Protected Payload […]: ...
        //     STREAM id=0 fin=0 off=13165 len=1178 dir=Bidirectional origin=Client-initiated
        //         Frame Type: STREAM (0x000000000000000c)
        //         Stream ID: 0
        //         Offset: 13165
        //         Stream Data […]: ...
        //         [Reassembled PDU in frame: 61]
        from_server,
        prot_quic,
        "WIRESHARK#56 QUIC STREAM",
        "40 19 62 e7 03 b3 2f 8b d4 ea 50 bf 26 bd d0 74"
        "07 0c ec 88 c8 ad 4c 2c 93 5d 73 aa 1d 16 fb 8c"
        "f2 e5 f6 4d ec 6d ce 65 bf 41 6a 17 c8 4b 6e f5"
        "00 cc 63 12 fc 04 cb 2f c6 ee 6b 16 d9 5d 2f 32"
        "29 05 be cd 89 ce 86 e4 52 72 98 d7 8e 3f 61 8e"
        "8c 17 fb fe eb e3 f7 49 fb 85 4a ee 85 e2 ff b1"
        "28 e9 1f 40 f1 8c 88 bd b0 3f f8 76 62 05 2e b4"
        "62 60 88 25 76 6d f4 7f 7c ee a9 17 99 68 60 ac"
        "b7 2a 75 d3 07 3c 90 ab 84 ce 3d 96 d1 36 be 43"
        "a1 36 a1 18 4d 13 ee df 6d 06 61 85 07 c4 c2 04"
        "9d 9f f5 80 58 04 91 00 96 a1 79 8c aa 32 e2 ad"
        "4c f4 47 be c8 f1 4f e9 d4 e3 5e ba 6b b0 06 b8"
        "2f 4a 20 e7 60 4a 1b 1c 5a 33 31 db f4 d1 bb 8a"
        "42 ad e7 68 54 20 29 42 82 6f b7 7e cf f5 48 88"
        "95 40 f8 5f 8f 30 00 eb 89 4f 6b af e2 64 56 0d"
        "f5 d3 4e 08 92 5c 13 95 94 c6 4c de d7 20 45 02"
        "8d b9 70 36 8b 7a 93 d2 bb ba 91 59 f7 a8 a0 50"
        "49 b1 9b f9 18 02 43 b3 90 f4 ce 57 9f 16 c9 f1"
        "79 22 7c 27 3f bd 9b ec 8f 45 d3 a8 03 51 66 21"
        "29 47 0b cf fb f2 c1 f7 b5 92 cf 14 19 cf 06 00"
        "fa ac 90 db 04 cb f3 63 de 34 9a 84 b7 fd a2 4a"
        "e4 db b2 c5 d4 3b 3a f3 f4 4e 0c 27 2d 75 82 ac"
        "d1 c7 fa f8 1f b6 75 ea ad 6a ed bb 61 6a 2c be"
        "b3 ca ff 0d c6 fb c3 73 b2 a3 e9 6a d7 ae 8f 16"
        "6d 72 b6 f2 d0 04 bf 92 c5 9a e7 ca a7 32 8d 67"
        "46 b4 d7 aa c3 c2 41 75 fc 55 95 db e6 bb 86 76"
        "ce cc 63 af 37 06 b4 b3 82 77 cc a3 f7 b6 0c 0c"
        "19 56 2f 45 58 76 e2 ea 46 1c 4c 41 6d 8c 0c 82"
        "2a 0c 6e 4b fc b2 0a ea 4e e9 6a f3 36 71 f5 04"
        "e4 2f ab 06 90 57 56 9b b5 24 07 d8 b3 28 eb dc"
        "1f 0b 56 1b cb 98 08 48 99 94 9f 7d 09 b6 15 2a"
        "50 6e 11 18 6d cf e1 30 01 61 09 60 e8 59 71 2f"
        "cd 38 33 76 72 7a 76 b7 02 1e ec c4 31 ed fc 15"
        "ec 74 e0 f1 5d 20 3e 51 a8 d2 3f 60 10 49 14 b2"
        "17 a8 95 55 f0 9f 8e 29 0a 0f 42 f8 df 8a b6 6f"
        "9d e7 13 e0 74 43 ad fc 6a 79 7b 72 c0 82 16 bf"
        "62 d4 bf 36 9d 19 55 1e c0 85 d9 0a 85 1e 32 8a"
        "9f e5 d8 a2 ec 4f d7 da c9 38 ec d9 cd 4b 28 a7"
        "cf d6 96 1a 54 34 6d 20 cf 61 e5 b8 51 c7 9a ad"
        "58 58 2d 04 59 7b 46 bf 8e 6f b6 46 f2 aa 0b 07"
        "53 81 95 83 b5 07 cd 08 13 d1 dd 18 d3 5b d8 ce"
        "a9 ec ad 30 9e 75 53 f0 24 3b ce d2 22 1f a7 5e"
        "76 c5 38 a6 45 18 5c fc 51 be 84 b6 2e 94 32 27"
        "f7 3b 3f c6 c7 ed 82 2e f3 1a 6c 59 37 16 da f7"
        "75 fd 4a 7a 11 1e 28 d1 74 bf a4 77 66 4d c7 e8"
        "be 60 9f a6 e3 73 0a 83 30 b7 97 53 fb cb e5 e9"
        "b0 63 b1 43 37 46 f6 96 ed 83 d5 e2 38 72 fa ce"
        "aa 28 72 bb 89 3a e4 f2 fe c1 3b aa e9 75 0b 3a"
        "d6 13 25 ce c9 60 6a 77 cb ea 12 33 cd 69 fc 23"
        "d0 37 73 41 50 bb 97 d1 4e 2a b3 17 13 77 77 d9"
        "b7 c8 82 2a d8 c3 1a 6a fc dc da ea 7a b1 33 0b"
        "24 8d 7e 79 33 62 0b 19 1f f0 2a ae 0a 65 12 e1"
        "49 76 0f fe 3c 8b e9 dc 18 73 89 ca 3e 99 94 07"
        "bd 35 94 63 4e 93 8c 4e 73 93 22 b0 80 40 f7 36"
        "04 8c 73 e6 2f 4b c8 34 86 a7 31 dd b1 4e f0 15"
        "cd 23 ab 2c 15 af 38 4a 50 5b dc be cc d6 03 1f"
        "aa 85 4e 76 29 f2 4e 90 8c cf 4d 30 4c 77 37 98"
        "5f 38 5e 94 4d a5 5b 0e 44 b1 97 64 95 77 0a 3f"
        "51 ee bd 6b aa 44 f4 e9 42 69 5b cc 94 c0 d2 c3"
        "3d 15 fd ee 03 e2 ce f0 9b 5b 62 09 d8 67 53 84"
        "5b e8 82 4e 49 7d 32 84 48 24 1f 80 5f df 7d ba"
        "05 8e b9 51 9c 6d f4 0b a1 ee 62 fd a4 4c 2f 35"
        "b5 53 42 c9 67 31 8d 57 2d e0 d9 07 d5 04 a5 d6"
        "dc a2 32 0d 96 8b 8a ad 2f c2 c1 81 51 fa 36 77"
        "d4 92 85 c9 dd 13 2f 00 1f 20 0f e1 00 49 ba 81"
        "19 a5 01 ae f3 3b 07 6a 04 ee aa 30 fe 28 c6 ba"
        "ea 12 f5 89 76 5d 73 4d 19 1b e9 93 57 2e 5f 23"
        "41 e5 73 33 b9 1f ec 9b fe 40 bc 0b 4a 44 0e 09"
        "df 51 07 51 a3 ae 75 44 44 f8 0e 90 ce 0e 64 2b"
        "92 b9 ea c6 2b 47 dc e0 73 35 17 81 30 ab b8 47"
        "8c 36 62 94 c4 65 a8 c5 36 28 10 fd 46 b1 35 19"
        "be 82 7e 01 cb cb d4 24 77 80 6d 29 f1 75 6b 09"
        "5a 09 f8 2a 3a 89 ca a7 76 19 73 58 d5 3f c3 09"
        "70 45 dd 5d 9e aa 0b 48 a3 a5 b1 34 f6 1c bc 42"
        "ec 93 7b d9 d9 46 4e 9e 67 fe 43 cf bb 85 c2 24",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 1200]
        //     QUIC Short Header PKN=29
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..00 = Packet Number Length: 1 bytes (0)]
        //         [Packet Number: 29]
        //         Protected Payload […]: ...
        //     STREAM id=0 fin=0 off=14343 len=1178 dir=Bidirectional origin=Client-initiated
        //         Frame Type: STREAM (0x000000000000000c)
        //         Stream ID: 0
        //         Offset: 14343
        //         Stream Data […]: ...
        //         [Reassembled PDU in frame: 61]
        from_server,
        prot_quic,
        "WIRESHARK#57 QUIC STREAM",
        "4e b3 a4 09 40 27 c4 1a ff 6e a8 ab 15 f7 b9 41"
        "82 65 98 9f 7d 54 a8 0e 2e c4 2d 0b c6 01 70 0b"
        "19 5c 2e 19 d0 2a 45 1e 04 d1 7e 09 23 84 3e 3f"
        "42 32 48 58 b7 10 fd 9a 96 e2 a7 47 a1 74 21 35"
        "24 b2 58 cb e3 53 79 a5 5b 4f 18 48 19 28 00 02"
        "fd 73 16 fd 92 24 40 55 01 05 7d 45 a0 7e 14 0e"
        "b4 a4 c6 2d c4 49 fc 41 a6 aa a1 80 9d 40 18 b4"
        "f2 28 28 27 88 be df c2 33 99 e6 d9 20 f0 af 85"
        "2f 65 d3 64 7f 54 8a 3c c0 56 c5 dd da 51 82 a9"
        "ff cf a4 b5 cc fe ff 56 1d 90 0f 74 29 b1 87 40"
        "10 a6 d8 02 23 0b 27 16 87 23 b5 97 e2 1a b9 74"
        "63 d1 85 a3 46 f1 30 7a 5e 03 da 01 8e 21 d0 55"
        "01 50 ef 0e 94 8f ab 95 61 4b 7c 81 61 a9 fd 92"
        "f0 78 15 f7 5b f4 6a b5 3f fa 0b 66 3c 70 5b f8"
        "1a a6 f8 3b 87 e1 12 82 fa 03 6c b4 61 30 a4 86"
        "65 43 b8 6b ee 31 8d 48 e3 f7 e3 ee 87 55 2d 8d"
        "eb 62 92 0f e1 76 8a b4 95 0c d6 3c d5 e8 8e 56"
        "e2 bd d6 49 59 f3 bb 98 9b b2 a9 c4 eb 8d 6b 6b"
        "f1 e2 69 5d 6a ed 71 4e 7a 0f a6 e7 c2 e7 3d 1d"
        "12 31 74 c2 40 01 99 f8 d4 dd 2b f5 0c 5c f3 fe"
        "ca 90 a5 1b 34 db 48 63 86 a3 c8 6b d3 8a 57 4c"
        "4a 1d e6 3c 4c 4d e7 d4 35 20 95 47 d9 e6 d4 10"
        "a3 98 0a d4 8f 35 f2 28 2e a1 24 53 5b 95 d6 5d"
        "6d 3f 7a bb af 1b 51 24 cb 67 43 fe 14 21 23 a8"
        "4b a7 36 c3 5d 8a 29 3f 29 b0 27 94 3b 6c d2 c0"
        "c2 ac a8 47 e9 d2 1e 40 44 ec b7 7f 4a 74 0f f6"
        "c5 a4 f0 57 3f 61 43 b5 6d 00 b6 3c f1 f5 c2 a6"
        "21 d9 b0 af a5 2c 3d 52 b8 7a 02 a9 2f b6 60 be"
        "eb 64 65 32 b6 0e f3 d7 e2 bb 3f f2 68 0b 10 06"
        "f3 9b f2 e3 d1 f6 ac e0 7b 56 a6 f3 dc 17 37 4f"
        "7a 26 cd df be b6 25 6a 53 f7 3f d1 6d ac b6 db"
        "33 ce ee 78 9b 2c e4 80 6b 75 8b 41 2b a9 82 d2"
        "43 1a b5 98 fb 9a 62 a4 60 96 8f 07 48 b3 94 00"
        "11 c6 14 ca 8e d8 8a cd e2 18 35 31 38 5d 48 64"
        "fb 6c 9f ec 15 ef 0d d8 4e 7b 97 70 9a 2d bb 72"
        "76 24 1d da 16 04 20 88 df 4b 4f 06 66 bf 00 1e"
        "5d c5 71 83 7e 14 08 4a d2 28 1c 3b 5b 8b e2 ac"
        "68 6a fa 6a 18 78 1d b4 95 58 f4 ad 03 b9 ae 2a"
        "d6 8c ed 17 13 d9 be 3a 0b 88 eb b6 e9 f7 fb e1"
        "c3 12 e8 bd 3a 6a f1 80 7f 81 c7 59 79 6c 27 76"
        "5a a2 26 5d 8a a9 d4 d5 7f 46 c1 60 9e d4 0e 12"
        "0b 99 44 84 79 9a 00 c4 ab 09 d1 61 97 23 6b 50"
        "c9 54 d3 b4 52 70 f0 ad a2 20 ac fb 3c 8f 09 fc"
        "f7 26 0c bb b6 27 03 0b 21 89 55 54 e7 eb 7b bc"
        "6d ad 04 36 57 a7 77 06 c3 c4 b9 ec 3e 06 44 16"
        "d7 c7 02 4b 00 f6 a6 72 7a f5 8a 87 56 6f da 95"
        "38 ed ea 0f c5 a4 0c 9b c3 71 2a 7d c0 bf 39 2d"
        "40 c1 8a d0 38 01 39 55 64 34 49 14 00 55 03 f7"
        "c6 da 17 96 d2 74 d9 f6 33 0d b3 be 72 b6 c7 ef"
        "59 73 63 69 37 b5 97 fd c7 52 56 26 bc 55 f3 57"
        "90 91 c8 c3 4e 4c c1 b0 4a 05 23 22 d3 1e 13 d4"
        "a0 e3 4b 3d 3a 4b 0b 94 0b dc 35 92 1c ae 18 81"
        "06 51 6a fe 91 53 1e d2 9e 03 3e ba 71 e5 64 97"
        "81 a5 f2 02 cf b5 8b 89 e3 c0 48 ab 9c 81 59 4d"
        "19 e5 9e 16 22 27 1b 75 c7 ff a6 9b db 5c 83 7e"
        "84 a1 c6 83 50 1e 28 2d d4 3c 85 5b 5d 59 ff f7"
        "2f 7f 97 de d9 70 0d 72 18 70 1d 93 29 aa 5d 37"
        "a1 df f9 d3 a0 bc 1a d1 cb c7 70 1b ae 07 47 ed"
        "7e 7a be 15 f8 c0 ab f9 57 93 73 01 90 a1 2b 5d"
        "3b 34 c5 13 26 3f 0f a9 1e 1a c3 67 0c 21 70 09"
        "2d c2 b4 5c a6 7d 3e 4d 2f 37 aa b3 68 cc 6e 7b"
        "38 82 e3 eb d2 83 fd 15 0b e1 b2 1e 02 38 bb ff"
        "09 ea 14 00 07 0e 3f 21 fa 41 a3 de 12 c5 90 9b"
        "3e 3f a4 8c 1e d0 d6 b8 16 8b 74 5d db f4 b8 7f"
        "e7 98 dd 45 ad 55 f1 54 aa 13 ef 48 4f 39 f0 b6"
        "b1 86 09 88 27 3b 48 00 51 64 c0 16 e4 90 e2 15"
        "97 c9 c2 2c 5c c0 4f 5d c2 b6 4e 73 f8 1d c4 3e"
        "33 28 fb 28 21 db c9 cf 45 de e8 86 4b d8 ab 63"
        "db 46 8c 53 a7 eb 07 3b 55 aa 37 6f 32 16 30 ae"
        "b2 82 7d 97 79 b7 2f 7f 5e 93 79 1e 37 a8 ad 2a"
        "bc 7b 15 8c e9 89 76 d4 3d 15 7f a9 98 28 71 36"
        "71 ec 1c 18 8c d4 63 1b 8b 06 fb 1b ec 28 30 20"
        "02 c7 8d ec b0 94 82 45 2d 8d 2e 62 cc 6d 7b da"
        "78 70 a7 14 4b 7a 54 b6 55 0d d3 a1 56 16 30 fa"
        "41 f6 02 a2 3d 29 d4 6f 35 04 35 81 b1 40 68 57",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 1200]
        //     QUIC Short Header PKN=30
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..00 = Packet Number Length: 1 bytes (0)]
        //         [Packet Number: 30]
        //         Protected Payload […]: ...
        //     STREAM id=0 fin=0 off=15521 len=1178 dir=Bidirectional origin=Client-initiated
        //         Frame Type: STREAM (0x000000000000000c)
        //         Stream ID: 0
        //         Offset: 15521
        //         Stream Data […]: ...
        //         [Reassembled PDU in frame: 61]
        from_server,
        prot_quic,
        "WIRESHARK#58 QUIC STREAM",
        "52 42 80 d9 3b 35 bc 8e 30 47 f0 07 41 9b a6 12"
        "e2 41 b5 86 4e 2a f3 e4 92 65 40 7c 40 fc d0 b3"
        "77 d0 c8 25 a2 6b 70 49 e7 e0 fa 89 dc af db 1a"
        "d5 62 b0 31 3c 2a ba fe a2 98 b3 32 47 77 f6 ad"
        "50 1b da 8a cf b5 51 eb 90 26 e7 15 64 26 e9 c5"
        "8d 35 21 9a a3 0d 12 bc b6 41 b2 41 28 0d c7 92"
        "d4 f8 2b 0d fb b3 59 c2 ac 77 12 60 a9 d0 78 c6"
        "ae 5f 80 ff 18 a3 54 82 71 3f f8 28 8d 47 d8 63"
        "70 62 30 8e cf ea 74 d6 00 74 e2 9d 44 22 5f ad"
        "6e f2 53 df 1b 94 e0 b3 c4 8a 70 43 83 89 e1 49"
        "a0 9b 3e 89 95 07 14 92 46 be 81 e0 db 92 23 6a"
        "d6 1a 3d 32 3f e3 b7 03 c9 ac 47 90 61 46 23 5a"
        "10 70 c7 fb 26 a1 3c 82 90 6b 63 d4 58 fe e0 3a"
        "ab ae 73 0e a0 43 28 28 40 cf fd e7 98 ea 9b 8e"
        "3a a8 74 44 04 92 7f 16 fe 70 0b 8c 35 f4 82 20"
        "06 38 c9 fd 78 4b a9 b1 bf 94 83 69 18 ad 2c c3"
        "41 21 db 79 ad 7b ed 00 82 1c a3 be 31 8e fb 36"
        "cc f9 fe bd ed a1 b3 4d 03 22 5c de 09 d0 fb 01"
        "b1 dc 64 69 9c 52 a1 17 da 75 16 2c 87 dd ca b2"
        "ff 83 a1 36 76 df 24 1d ef a0 aa 4d 9d e4 9a c5"
        "c7 e4 47 be 5e 80 09 38 7d df c6 eb 31 08 a2 1f"
        "03 14 02 eb 74 27 72 67 78 95 c6 20 cb 64 0e 23"
        "6a b5 4e f2 fb c7 92 46 61 0b f8 e6 05 57 1d 5e"
        "4e fa 97 ae 58 74 33 a0 5b 38 15 0c 0d a8 9b da"
        "21 d3 f3 9f 98 7b b2 9f a7 5e c5 10 6b 5e c7 30"
        "48 e3 5c 6e 66 df 5e ac b9 fe 50 82 b4 d0 1f d7"
        "53 0d fd be ff 6e bd 87 81 71 f6 c6 b3 a0 e8 58"
        "f0 fc 41 1f bc 92 2a c6 e9 ab 3c 82 77 cd 29 1a"
        "49 19 76 20 1e 2f 2c 30 99 c1 08 4f 26 77 88 ac"
        "37 32 4d df 90 b4 b1 1f 58 e0 d8 41 27 c1 69 40"
        "38 75 02 07 39 1d 07 a1 f5 8e 61 71 4b e9 97 be"
        "4a 12 f2 1e e0 36 3d 3d 4f f6 67 11 70 4c c7 b3"
        "ed 97 2b 1b a6 d0 22 f2 7d a5 21 1a a5 b4 6d 9e"
        "9f 48 c8 31 1a 1f a2 42 52 fb 1c c2 95 43 40 ff"
        "f2 e9 eb 5d 6f b9 2a 84 7e 4a 7f 56 ad 5d d7 1c"
        "2e c9 7a fb 68 0c 2f a6 3d de 6f 6e 8a 84 ed 39"
        "98 78 b1 e4 3a c7 36 3f b7 a7 66 23 b9 81 d6 4a"
        "7e 45 69 89 ba 82 e2 44 8e d4 1b e4 73 e6 8a 32"
        "31 cd 5e 57 a4 ac d4 a3 7d c5 a7 e9 d6 4c b1 a8"
        "30 bd 64 49 d7 58 20 e2 a9 ce a5 0b 69 b9 52 80"
        "37 d8 27 9a 98 c7 92 42 48 91 8c 24 22 63 6e 7a"
        "a5 87 43 9d 66 4c fe bc 6f 26 4e ee ab d2 8e 21"
        "47 bc 4a 13 2c 45 54 17 f0 7f 3b 80 99 b1 55 75"
        "25 f0 b8 17 0f ac 0a b8 20 41 41 ba a9 8f 18 5d"
        "4d b4 50 d7 eb 3d a2 02 c6 60 39 32 2e ad da be"
        "9a f9 3d 01 9a 2f 7f 9c fe 9c 10 01 5d 38 57 9c"
        "8e 6e 9a e8 c8 e7 10 16 ee fd 2a 03 6d 1e 9f d7"
        "07 36 34 5e 0c 04 e4 bf 93 b4 6b a6 1d d7 14 d6"
        "f6 e4 0f 56 09 9c 13 51 65 e3 6e 78 60 9d 14 5d"
        "44 74 39 3b c0 11 f4 4f 0c 48 05 e9 e2 9d fa 4d"
        "f3 1e 8a 08 89 c8 ef ed 27 60 0c 71 ab 16 dd b4"
        "5b a6 9e c4 b2 0f c3 fc ed ab 6e bc 44 54 a4 e3"
        "46 df 9b 24 fb 3f 62 2f 74 bb 59 94 7d ea 1c 7f"
        "1a 92 d8 e5 87 93 0d 47 22 86 47 98 70 b7 b8 70"
        "ef 62 5e 67 76 89 25 71 a6 e3 4f 73 2b 6b 53 ae"
        "43 12 91 14 14 d1 9b 94 ad 8c 21 49 81 f7 83 b2"
        "af cf 7b 8a 2c cc a5 22 7b f0 ab ba a7 cd 23 bc"
        "38 1b 11 9c 21 86 86 ce 15 c4 3a bf f7 80 3a 86"
        "9e ad 25 f9 91 f8 ce f3 23 45 fa 2f 37 15 4a 59"
        "12 6a 6d 4e 81 2c 81 6e 83 9a ae 81 86 db d7 02"
        "18 70 c0 cc a3 8e 4d ed 03 fd 87 dc 17 2a 5c df"
        "ca 08 01 cd 5d ba 7e 2f a1 7e 54 b0 0a 4f cf 63"
        "be 4d 15 3b 53 ae 58 4f 68 bc fa 49 4a 41 3b 92"
        "fb fd 8f 1a bf d5 2c b7 e8 3d 88 24 be 04 88 e6"
        "89 68 59 2d 87 f5 d3 32 61 a7 a9 2f f9 f6 29 d4"
        "71 8b 68 2b 8a b2 3f c4 ff b0 49 c5 1b f8 24 0c"
        "4f 9d 7e 47 72 e5 bd 22 b2 36 17 be 5d 17 ba d8"
        "41 9b 9e 82 40 e7 04 8b 6a 6e bf 9b e9 40 51 c4"
        "db ac f8 c8 e2 89 9e ad 74 f3 40 0c 95 d1 fb fb"
        "bd f9 cc 80 38 b9 ee 02 36 be 54 86 77 6c e1 45"
        "e9 91 33 61 02 c7 d1 83 05 90 af 71 c0 33 1e bd"
        "17 70 6a c3 f7 78 a8 ec 93 89 bf d4 c9 d5 ca ec"
        "d1 6c 8e 7d d3 5b eb 4b da 9d 09 62 19 71 81 88"
        "c4 42 d0 f1 25 d5 63 5c 51 2a 27 83 45 52 4f ce"
        "de 45 ac 5c 79 33 7c 91 6f fa 90 d9 08 f3 b4 dd",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 1200]
        //     QUIC Short Header PKN=31
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..00 = Packet Number Length: 1 bytes (0)]
        //         [Packet Number: 31]
        //         Protected Payload […]: ...
        //     STREAM id=0 fin=0 off=16699 len=1176 dir=Bidirectional origin=Client-initiated
        //         Frame Type: STREAM (0x000000000000000c)
        //         Stream ID: 0
        //         Offset: 16699
        //         Stream Data […]: ...
        //         [Reassembled PDU in frame: 61]
        from_server,
        prot_quic,
        "WIRESHARK#59 QUIC STREAM",
        "45 79 6d e9 13 ce a6 e3 11 19 ce e7 6e 81 c9 fd"
        "9c 13 b2 27 6c 19 fb 24 ce bc 9e ed b4 67 b1 e3"
        "bf 1e 50 6a 12 56 68 fe c8 d5 64 b6 ca 5d 81 37"
        "63 51 25 aa c8 16 c5 a2 9e 04 d5 a1 83 f4 a8 61"
        "b2 a1 96 1a ef 52 c2 3a 73 39 75 fc 65 e8 98 42"
        "c9 ba 08 10 9d 83 a4 e5 ef c5 de c9 7b 4e 39 99"
        "1b c5 08 f5 cb 3c ab f4 aa 9e 50 ff 2e 4b 26 cf"
        "4d 05 0a 31 ff 69 65 70 02 77 88 e6 17 6c 8d 00"
        "a7 ec 9f 5d e9 2e e8 d2 0b b5 c8 db 3a 3d 9e 5c"
        "33 75 c5 ec fe db 85 29 93 e2 47 68 7b 6f 7a 31"
        "39 63 43 f7 61 d2 5c ac 68 fc 2c 38 b0 c5 b0 e6"
        "66 8b 8a 04 03 3c d2 5e 31 10 9c 90 05 98 28 3e"
        "92 06 1b 0c 06 1e 57 73 08 3d 69 19 63 ca 42 03"
        "ee 56 b0 9f 13 87 b0 08 3a 51 d2 96 30 d1 ce 5c"
        "de 38 00 bb e4 18 ac 50 7c 21 d6 65 d8 be ea 06"
        "32 84 37 e1 6b 1a 7c a3 4a 6d 7c 61 b6 ca c8 cd"
        "ae 55 e2 62 88 17 94 2d 0d db 81 f9 f8 68 16 29"
        "b0 2d 13 8d 39 10 0b 24 64 8c f4 1d 1d cd 3c 49"
        "4c 27 0f 73 79 f7 d0 bb 69 68 38 dd 3e 15 d0 cd"
        "25 77 72 62 96 96 d9 ce 9e a0 0b f8 ab 64 2a 8b"
        "43 82 48 67 aa bb c8 a2 e3 e1 06 7c f5 0e 48 94"
        "ef f8 af 50 5b 46 85 9c a2 de c6 d5 f5 cb a8 3f"
        "73 fc 8f b9 33 3b 87 18 e1 4c b7 81 17 d4 ac 49"
        "37 cd 24 3b e3 4b 17 7d 88 47 33 c5 b8 0c 46 89"
        "a2 e7 a2 33 f3 6c 69 c5 49 c4 9b 6d 4d 50 31 03"
        "f5 82 4d b1 3c a6 63 69 14 9a 3f 43 17 71 9b d1"
        "bf ca 69 fe fe 6c 45 9c 7d 34 3f 92 cb a6 06 a7"
        "52 da bd 68 62 29 58 4f 13 73 42 73 b7 01 8b f6"
        "55 05 f6 2b c6 a0 d7 a6 2e aa 35 77 e1 a6 5c 10"
        "2b bf 26 e6 5a c4 0b e9 c5 83 4d 29 40 d0 18 72"
        "4c 20 58 15 63 35 cd fd bf bf 73 7b 43 21 a0 dd"
        "61 66 30 2b f6 45 59 f2 82 ce 2c eb ce 6f a6 70"
        "b0 86 5f 1f ea cd 7b 79 f4 b5 60 fe 0e c0 bb 1a"
        "5c 32 de 44 af 10 46 02 2e 1b 80 d3 1c bd cf 20"
        "be 08 8b 8d b9 95 94 bf ec 7c bb 2a 42 e0 c7 18"
        "82 f8 09 5a f4 48 03 db 6a f3 c5 0c 68 26 e8 df"
        "7f e3 78 1a 34 77 0a 67 41 1e 52 74 78 bf bf 5d"
        "78 4e f2 e5 3c 1d ca e2 cc 64 60 0e f8 3a 8f dc"
        "d6 8b 6c e6 29 00 4b f5 c3 9c 46 af 2b 74 b5 ec"
        "a7 20 7e d7 55 1b 4e 02 27 dd af d2 39 2b 83 03"
        "22 e2 a4 2e f3 cc 05 32 a5 6a b9 7c 8d 1a 3a a6"
        "9e f0 39 19 ea 56 83 49 b7 ae e0 f5 f0 79 08 0b"
        "4f f7 29 17 06 db 28 1b 00 ec f7 02 66 b2 4f 70"
        "c6 44 67 ba ef b7 9e 38 89 06 64 2a 1f b3 dd 36"
        "a8 9b 6c 5a 01 37 77 d6 e5 b1 be b7 d9 4d f9 5c"
        "cb 43 58 b1 42 c9 73 c4 e2 37 17 59 83 12 c0 dc"
        "db 88 dc cc f2 d8 ca c7 a4 c1 0a a2 82 d8 c3 24"
        "70 f4 17 bb 74 6f 8e 8f c6 1f 00 c2 4c 02 aa 9c"
        "69 c1 63 76 77 df 37 8a f5 b9 79 7d 2f 27 e5 e2"
        "d5 45 88 c1 e4 51 43 6e e2 f8 97 ba bb 89 c4 30"
        "68 85 b6 0a 9e 30 cb d3 a1 e8 51 70 d7 8a f9 cc"
        "a4 3c 23 1a ea f3 ec 42 ee 13 e3 bc c7 8a a7 f6"
        "47 fe a0 bc 17 2c 98 88 2c a6 4e 82 ca eb 5f cd"
        "1b 34 ea b8 b3 ab 67 6f 40 31 d9 c8 72 27 e6 8d"
        "ef e1 c0 41 09 58 86 85 97 85 c2 a5 2d a4 99 1c"
        "e8 99 ea d4 53 cf d9 25 85 d6 ef 5a f7 76 59 5a"
        "12 49 db 5a fd 15 8d d1 34 1c 95 fd 42 63 fe 16"
        "c8 a7 f7 b1 e3 7b 80 43 36 a3 d8 7f a7 47 2c 9c"
        "6d 50 f1 d4 56 f6 0f 0b 12 ff b1 b0 6d 45 d6 15"
        "dd 9a 3a 1e 03 bb 69 24 8f f5 72 3b 40 03 d0 73"
        "5d 1d f0 00 9a c0 10 08 71 28 94 4a 75 63 f1 36"
        "04 54 61 97 cc 8f d5 6d 15 c4 30 44 f4 48 a3 72"
        "70 0f 8c b9 2b 06 5b da 79 89 9a 40 7c 87 ce 54"
        "8b bd b2 fe b3 6e 79 52 d3 a9 34 79 b5 eb ab d2"
        "d1 ff 6e 3c ea c5 52 a7 7c c6 e0 65 8e c3 22 e4"
        "40 f0 e3 91 72 34 74 e3 3f ca d0 d6 0b ed 3d 93"
        "e3 cc 0b ac a6 87 04 66 3b 7e de 1c 05 78 cc dc"
        "c0 f2 6e 23 9c 9f 72 34 c8 fc 02 65 01 90 73 e8"
        "e6 4b 2b 42 94 c2 85 35 4f 54 9f 6e f3 74 6f 98"
        "18 dc b3 2d 03 64 6a 0b 9f e9 03 93 40 cf 9e 7c"
        "f9 d0 30 f3 ff 71 76 e7 4c f1 c6 21 16 6e b7 9e"
        "72 64 57 cd e8 c7 60 39 e9 f2 2b d5 52 f7 fb 5c"
        "c8 29 7e 4b 02 19 d9 97 b1 bd 4b a6 ed 46 fe b7"
        "28 78 75 14 ee a7 e6 89 86 e6 c5 45 39 bc ee e8"
        "9a 0d 9a e4 73 09 24 a8 06 99 50 bb d4 61 b8 e9",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 1200]
        //     QUIC Short Header PKN=32
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..00 = Packet Number Length: 1 bytes (0)]
        //         [Packet Number: 32]
        //         Protected Payload […]: ...
        //     STREAM id=0 fin=0 off=17875 len=1176 dir=Bidirectional origin=Client-initiated
        //         Frame Type: STREAM (0x000000000000000c)
        //         Stream ID: 0
        //         Offset: 17875
        //         Stream Data […]: ...
        //         [Reassembled PDU in frame: 61]
        from_server,
        prot_quic,
        "WIRESHARK#60 QUIC STREAM",
        "4e 03 df 2e 1d 12 cb 2a 8d e8 1d 55 09 67 c6 31"
        "79 6c c5 bc f4 c1 1d d1 51 45 15 7a de db 47 ff"
        "d2 56 ba 63 bc 23 2a a0 d5 91 49 cf de b9 3c fd"
        "8a 58 ea bd b0 73 9d d6 b6 05 53 10 8b 94 d2 99"
        "14 3f 64 cb f0 86 54 cc 17 00 b4 05 3c 37 6d cb"
        "95 b3 b4 d6 cf 1f af 67 b5 6b 90 80 79 b5 d7 dc"
        "8a cf 88 90 f7 b7 30 6f fc 0a bb 83 03 85 2e e7"
        "7f 0b 6c 9d af 33 42 78 de 48 7b d7 2c 25 b2 73"
        "8c d4 d6 1a c4 c8 5d c0 cd 3d be 86 3d bc 28 38"
        "32 98 72 d5 7e 62 42 4e 6f 2c c9 e5 64 89 55 dd"
        "89 04 40 c7 df f2 54 ed e6 15 aa 7b 0d 94 95 a7"
        "a6 20 6b 2a fa 49 04 ec d6 7a 36 be d5 26 0d e4"
        "b9 8f fe 5c c7 9e 29 e4 4f dc aa cd 7f 30 cc 26"
        "ee df 36 40 29 aa 74 37 9f cf 1a 64 28 f1 b4 d1"
        "2d 24 09 4a 4c 40 6f 31 07 bf b9 09 23 93 16 84"
        "60 c7 62 ac 49 67 3a aa b2 75 1e af 42 36 1d 7a"
        "13 8a 62 22 f4 e4 06 ff 10 77 0f 5a cb 94 be fc"
        "53 10 5f ac c8 c6 91 c8 6d 28 44 5d 48 1c 1d f7"
        "99 1c 1e b2 e1 31 22 0f df c9 fe fa be 5e 0c bf"
        "37 f2 eb da 48 d5 a4 51 96 b6 e2 8e 7d 85 dc 76"
        "c5 0c 4b 90 34 b4 10 1e da 01 d8 3f 9f fe a9 1a"
        "2b 0d 35 e5 c2 de 51 45 ef 8a ba e9 be 14 03 31"
        "e5 54 2d 93 25 f9 9d 24 2a 30 12 71 f7 f5 4c cd"
        "12 67 60 c8 f8 1a 05 38 58 58 7f 6a 31 34 21 49"
        "72 2f 06 47 f3 7e d3 45 25 80 d6 b6 e9 43 42 15"
        "75 37 ea 8d 13 62 bf 2a 68 11 c1 42 40 a5 97 e3"
        "9c cb 9e 91 03 0f f5 50 fe 0c f8 98 e7 2d 7c e4"
        "63 b4 0c 1e 84 a3 ed 61 56 ce 8a 04 ab 50 f5 b1"
        "65 8f fa 10 6f 7a 61 a9 2d 40 b5 ae 2c 13 4c ad"
        "8f c4 d8 0b 0d 85 0f cb dc 18 84 5c ed bd 3a 86"
        "44 95 95 24 3c 8b 5d 89 ec b2 df 31 97 32 e6 45"
        "9c db f3 3c ed e2 fc 49 cb 1f 62 da 5e 8a 25 5b"
        "b0 58 00 e2 67 db e3 c4 f5 dd f5 54 f4 1b 7e 1c"
        "bb 72 22 54 3d c6 fb 15 b1 c5 b6 b5 8e 17 51 6d"
        "f4 b7 db d6 5d 4d 8a 89 8e e8 5a 10 4c be 57 98"
        "32 a8 45 0a f4 e7 6c 4d d9 0d 06 01 41 0f 5b f8"
        "4e 3d 43 cc 99 3f fe 34 02 d5 1a c1 a7 a2 01 19"
        "d3 a9 3a 1c 31 e2 9c 6b fb e1 9d 24 bc 93 53 82"
        "cc 9e bd 0b ff 41 80 dc 28 44 3f ed b1 09 c1 6b"
        "b2 0f 89 02 45 3d cb 16 31 2e 5d c1 ac dc 2e 17"
        "9c 54 2d 06 94 86 b3 08 f5 95 a2 82 44 ca 6e 7d"
        "a2 be 1d c5 22 40 10 ab 37 1d 8b 19 52 87 bd 4e"
        "68 e2 e4 65 e1 86 2c a5 5f c2 a5 a4 ae 0d f7 44"
        "f9 61 13 07 ee 27 86 23 a7 7e c5 ad f5 f4 45 73"
        "e1 ef 6f 41 28 f4 ca 43 ae 57 c3 ad f4 e8 ca 50"
        "84 3f 19 30 36 e1 d5 4e da 4c f7 ff e2 de 92 be"
        "c5 a0 5c da f8 b4 85 05 3d 6c b6 f8 74 9f 5f b3"
        "a1 1d b3 fb 45 a9 10 55 b6 37 d8 17 05 79 54 c1"
        "4a 48 8a 04 4f 54 06 18 d4 bd 70 c3 4f 8a 59 6e"
        "6a 37 5a f9 8a 43 b0 96 e6 65 71 91 70 3f 25 25"
        "db 81 bd 67 82 27 f7 8d 1b e5 12 0c ad de f3 af"
        "45 be e6 75 a5 bf 63 e5 b1 b2 e8 65 95 3d c3 26"
        "fb f5 5a 3b 05 0b 85 40 65 b7 47 3e ff 42 ee de"
        "04 c6 ba 3d 00 cd 84 1a 7d 9c ae b7 c0 d3 9c 26"
        "ec 0e 12 f4 c6 c5 20 d3 16 85 a2 47 7e b1 82 9d"
        "dc 99 3d dc 1a 43 e7 c8 d1 c2 8d 0b 25 3c e3 b9"
        "59 c4 27 50 ae df 5b ec c1 29 b8 c8 97 2a eb 13"
        "78 b9 21 fb e9 22 ca 83 5d ea 58 1e 70 f5 29 ad"
        "46 19 60 c3 56 c7 87 90 11 6e 0a 31 90 75 80 5e"
        "95 e6 6c 9b c1 db 05 d5 d6 25 aa e1 fe a4 e5 65"
        "2a 50 82 4c 49 8f 20 ba c4 45 ff 10 db 68 c1 18"
        "8c 09 36 ab 38 01 9b 34 c5 fa b3 9b eb 3a e9 b7"
        "f7 10 46 24 f9 e3 ab 84 6d 0b f1 bd 4a 25 2b ad"
        "8c 31 3f b1 b8 f7 25 51 23 8e 72 e2 22 32 42 d0"
        "69 b2 b9 22 11 4e 6f 58 87 2e 52 4f 2b 4e 68 e9"
        "07 2b 2a 59 90 a1 e5 34 58 92 b1 e3 74 f2 25 33"
        "85 fb f1 49 dd e8 93 eb 55 80 c0 bf 09 4b 18 c8"
        "63 b9 88 f1 f1 21 8c 8a 71 03 1d de d1 6b 32 30"
        "c1 76 d0 28 15 fb fb a2 1b 8e f2 e8 6f 07 82 59"
        "29 27 db 55 4b 41 7a 5f 04 90 9b 02 5f 2d 4c 9f"
        "d5 30 21 3e 97 12 17 2c 00 7c 8f ef 93 93 77 ea"
        "d9 ec 81 ba a8 b0 6a 14 c1 50 18 67 99 7c ed eb"
        "01 77 34 77 a4 47 04 6a 9b 45 ea b2 e4 a6 23 d6"
        "70 04 4f 8e 53 7e 6a a3 b9 3c 56 3c 3f 86 98 07"
        "b1 97 0a bb 12 26 da c9 13 50 c1 a6 85 df 8a 32",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 734]
        //     QUIC Short Header PKN=33
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..00 = Packet Number Length: 1 bytes (0)]
        //         [Packet Number: 33]
        //         Protected Payload […]: ...
        //     PADDING Length: 232
        //         Frame Type: PADDING (0x0000000000000000)
        //         [Padding Length: 232]
        //     STREAM id=0 fin=1 off=19051 len=478 dir=Bidirectional origin=Client-initiated
        //         Frame Type: STREAM (0x000000000000000d)
        //         Stream ID: 0
        //         Offset: 19051
        //         Stream Data […]: ...
        //         [10 Reassembled QUIC STREAM Data Fragments (11071 bytes): ...
        //             [Frame: 52, payload: 0-1172 (1173 bytes)]
        //             [Frame: 53, payload: 1173-2350 (1178 bytes)]
        //             [Frame: 54, payload: 2351-3528 (1178 bytes)]
        //             [Frame: 55, payload: 3529-4706 (1178 bytes)]
        //             [Frame: 56, payload: 4707-5884 (1178 bytes)]
        //             [Frame: 57, payload: 5885-7062 (1178 bytes)]
        //             [Frame: 58, payload: 7063-8240 (1178 bytes)]
        //             [Frame: 59, payload: 8241-9416 (1176 bytes)]
        //             [Frame: 60, payload: 9417-10592 (1176 bytes)]
        //             [Frame: 61, payload: 10593-11070 (478 bytes)]
        //             [Fragment count: 10]
        //             [Reassembled QUIC STREAM Data length: 11071]
        //             [Reassembled QUIC STREAM Data […]: ...
        from_server,
        prot_quic,
        "WIRESHARK#61 QUIC PADDING, STREAM",
        "53 37 35 8f 24 0b 79 03 40 c2 73 b2 74 9d b6 19"
        "76 60 d4 e2 87 9a 68 fe dd bb 3f f1 83 84 a8 eb"
        "a9 16 71 ee 90 02 97 bb 74 82 b1 db ff 0e 5e f3"
        "02 6d 6a 4f 2e f0 ce 3d f1 fb 0d a8 80 13 c9 58"
        "a8 64 a1 91 0d 95 5a d5 c0 d8 fb 79 ed 3c dc f0"
        "c4 b1 25 a8 1d 3d 97 c6 4c 97 47 4b 75 6e ae 5a"
        "23 23 43 dd 40 4c 80 68 00 6a 89 e9 27 42 29 8e"
        "45 8f 9e c4 43 13 e2 eb 7a 65 72 22 49 7f be 61"
        "30 6a d1 9c 0d fe 5e 02 24 bc db d6 c6 fb 5f e0"
        "4f ae 4f 29 4f e2 23 8a 32 67 c6 17 32 b0 69 0b"
        "04 5a f5 ef fc 47 45 56 73 bc 79 4f d4 4c 9d aa"
        "e4 96 27 14 9d a2 2b c7 7b ff 68 4c 47 38 e3 bd"
        "87 b1 55 43 1a 77 82 8b f3 a3 34 e0 55 1a 4b 83"
        "e4 39 82 69 34 e8 34 c1 c8 b7 06 f3 be 46 91 66"
        "93 95 f8 81 04 42 30 f2 84 1d 3c 87 3a 8b 76 0b"
        "cf e5 72 05 88 42 7b e5 40 a2 8d 3b 8c e0 58 96"
        "0c 80 a5 61 86 d0 38 a8 28 95 95 3f 2f bb b2 92"
        "4d 18 bb d7 51 e2 93 f4 c5 d8 24 f8 3d 85 9a 8c"
        "5d 61 40 09 d3 98 8e 21 18 76 d4 49 70 90 4e 72"
        "89 bb 37 7c d0 62 b8 72 a5 43 38 90 ed d3 73 f4"
        "42 4b 73 12 fa 36 88 91 0e 3a 3b bf 29 95 f0 ff"
        "23 ca 9a 0d 23 5e 16 e9 c6 24 2c 65 f4 f4 91 93"
        "c0 97 e2 47 dd b4 a5 b4 c8 71 31 3d 89 f3 e2 1d"
        "c4 ff 57 af d1 58 09 06 c1 b1 e0 bd e9 f9 bb 0f"
        "c5 65 4d d5 8c 64 17 ed 51 04 5f 83 7b d6 8d c1"
        "e7 7e a5 68 ae 3e 22 2c 8b cb 3f 51 4e e4 cd 29"
        "53 47 ce fa 34 3b 5a d6 43 17 e6 e3 cb 9a b1 b1"
        "b8 2f c3 e6 7d 9a 61 8f 23 c6 d4 1a f6 2d f9 76"
        "4f 48 15 57 74 4e 92 f4 f1 36 90 1b 63 ec 38 a4"
        "33 37 8d 97 27 b0 58 49 ec 1e 24 b1 c7 19 77 e8"
        "9c 07 75 fc 30 ab 78 13 94 3e fc 40 8d e3 6b 63"
        "10 ee 86 25 cf 6e 4c 60 bb 28 62 3b 83 cc 11 bb"
        "42 67 38 68 91 9c 7d ca 83 2e 4f 11 14 f2 33 17"
        "94 96 5a ad 00 d0 84 79 33 3a dc 2b 27 ce 9b 64"
        "f1 18 d3 26 fe 72 3b 0b 87 58 4c 07 fc 0b c6 34"
        "ac be 6b a0 47 46 d8 5f e4 8e a1 2b ed cc 92 e1"
        "5e 01 c7 c4 fe 6e c1 e4 d8 0f 7d ef 01 7f 49 e5"
        "23 10 27 23 95 18 6b 19 7f 32 d8 e8 f5 c3 a3 a7"
        "9c f6 80 87 80 d6 64 a0 cf 6a fe ef 78 fb 6e c6"
        "b4 df 2a 0a 36 7a 76 db ab 7a d6 64 ea ca 67 e4"
        "01 a4 db 61 de 61 a3 19 b7 df ab 22 16 66 cf 31"
        "da 4b 21 e8 a5 64 e8 bb 2d 0e b6 7f b2 2a 01 34"
        "86 a4 cc a3 82 9c d0 9d 7e fa 23 13 52 c2 a0 e5"
        "3c 64 e4 de 53 14 67 d7 4f cc 59 47 13 51 39 df"
        "3e 2d 75 c8 c5 68 e3 b9 f1 2f d4 c3 62 43 0b 85"
        "2f 3d b3 4a 2c f9 81 ed 82 14 b9 a6 02 97",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 36]
        //     QUIC Short Header DCID=fe21df6a65e76e9e PKN=14
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..11 = Packet Number Length: 4 bytes (3)]
        //         Destination Connection ID: fe21df6a65e76e9e
        //         [Packet Number: 14]
        //         Protected Payload: 10c51f3db6290324ad7d9c9d008e87fe08573f7b5d0d3f
        //     ACK
        //         Frame Type: ACK (0x0000000000000002)
        //         Largest Acknowledged: 24
        //         ACK Delay: 0
        //         ACK Range Count: 1
        //         First ACK Range: 10
        //         Gap: 0
        //         ACK Range: 5
        from_client,
        prot_quic,
        "WIRESHARK#62 ACK",
        "42 fe 21 df 6a 65 e7 6e 9e 86 10 55 47 10 c5 1f"
        "3d b6 29 03 24 ad 7d 9c 9d 00 8e 87 fe 08 57 3f"
        "7b 5d 0d 3f",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 36]
        //     QUIC Short Header DCID=fe21df6a65e76e9e PKN=15
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..11 = Packet Number Length: 4 bytes (3)]
        //         Destination Connection ID: fe21df6a65e76e9e
        //         [Packet Number: 15]
        //         Protected Payload: 32e59f1d2209e41ba4fee1568d974969374acd749f59b5
        //     ACK
        //         Frame Type: ACK (0x0000000000000002)
        //         Largest Acknowledged: 26
        //         ACK Delay: 0
        //         ACK Range Count: 1
        //         First ACK Range: 12
        //         Gap: 0
        //         ACK Range: 5
        from_client,
        prot_quic,
        "WIRESHARK#63 ACK",
        "47 fe 21 df 6a 65 e7 6e 9e f7 06 3c a9 32 e5 9f"
        "1d 22 09 e4 1b a4 fe e1 56 8d 97 49 69 37 4a cd"
        "74 9f 59 b5",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 36]
        //     QUIC Short Header DCID=fe21df6a65e76e9e PKN=16
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..11 = Packet Number Length: 4 bytes (3)]
        //         Destination Connection ID: fe21df6a65e76e9e
        //         [Packet Number: 16]
        //         Protected Payload: 1a82c57d068d05b648152f37434e23e24cbb4940ae3718
        //     ACK
        //         Frame Type: ACK (0x0000000000000002)
        //         Largest Acknowledged: 28
        //         ACK Delay: 0
        //         ACK Range Count: 1
        //         First ACK Range: 14
        //         Gap: 0
        //         ACK Range: 5
        from_client,
        prot_quic,
        "WIRESHARK#64 ACK",
        "42 fe 21 df 6a 65 e7 6e 9e 09 8b 1c 06 1a 82 c5"
        "7d 06 8d 05 b6 48 15 2f 37 43 4e 23 e2 4c bb 49"
        "40 ae 37 18",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 36]
        //     QUIC Short Header DCID=fe21df6a65e76e9e PKN=17
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..11 = Packet Number Length: 4 bytes (3)]
        //         Destination Connection ID: fe21df6a65e76e9e
        //         [Packet Number: 17]
        //         Protected Payload: e2370eaaf1a0c93abd2959eb5ce9d2ef4f4b6db53586fc
        //     ACK
        //         Frame Type: ACK (0x0000000000000002)
        //         Largest Acknowledged: 30
        //         ACK Delay: 0
        //         ACK Range Count: 1
        //         First ACK Range: 16
        //         Gap: 0
        //         ACK Range: 5
        from_client,
        prot_quic,
        "WIRESHARK#65 ACK",
        "44 fe 21 df 6a 65 e7 6e 9e 93 07 1f 6b e2 37 0e"
        "aa f1 a0 c9 3a bd 29 59 eb 5c e9 d2 ef 4f 4b 6d"
        "b5 35 86 fc",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 36]
        //     QUIC Short Header DCID=fe21df6a65e76e9e PKN=18
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..11 = Packet Number Length: 4 bytes (3)]
        //         Destination Connection ID: fe21df6a65e76e9e
        //         [Packet Number: 18]
        //         Protected Payload: 65bc80f9c6bea02677091826197a673cf1a0d68d32f17a
        //     ACK
        //         Frame Type: ACK (0x0000000000000002)
        //         Largest Acknowledged: 32
        //         ACK Delay: 0
        //         ACK Range Count: 1
        //         First ACK Range: 18
        //         Gap: 0
        //         ACK Range: 5
        from_client,
        prot_quic,
        "WIRESHARK#66 ACK",
        "5c fe 21 df 6a 65 e7 6e 9e 52 5f 22 19 65 bc 80"
        "f9 c6 be a0 26 77 09 18 26 19 7a 67 3c f1 a0 d6"
        "8d 32 f1 7a",
    },
    {
        // QUIC IETF
        //     QUIC Connection information
        //     [Packet Length: 32]
        //     QUIC Short Header DCID=fe21df6a65e76e9e PKN=19
        //         0... .... = Header Form: Short Header (0)
        //         .1.. .... = Fixed Bit: True
        //         ..0. .... = Spin Bit: False
        //         [...0 0... = Reserved: 0]
        //         [.... .0.. = Key Phase Bit: False]
        //         [.... ..11 = Packet Number Length: 4 bytes (3)]
        //         Destination Connection ID: fe21df6a65e76e9e
        //         [Packet Number: 19]
        //         Protected Payload: e72a7b018939c3ce5741a3407f8c60417e1f87
        //     CONNECTION_CLOSE (Application) Error code: 0
        //         Frame Type: CONNECTION_CLOSE (Application) (0x000000000000001d)
        //         Application Error code: 0
        //         Reason phrase Length: 0
        //         Reason phrase:
        from_client,
        prot_quic,
        "WIRESHARK#67 CONNECTION_CLOSE",
        "58 fe 21 df 6a 65 e7 6e 9e c5 e0 38 6d e7 2a 7b"
        "01 89 39 c3 ce 57 41 a3 40 7f 8c 60 41 7e 1f 87",
        1,
    },
};
const size_t sizeof_pcap_http3 = RTL_NUMBER_OF(pcap_http3);
