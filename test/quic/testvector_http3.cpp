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
        SOCK_DGRAM,
        "QUIC Initial",
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
        SOCK_DGRAM,
        "QUIC Initial",
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
        SOCK_DGRAM,
        "QUIC Initial",
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
};
const size_t sizeof_pcap_http3 = RTL_NUMBER_OF(pcap_http3);
