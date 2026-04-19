/* vim: set tabstop=4 shiftwidth=4 softtabstop=4 expandtab smarttab : */
/**
 * @file {file}
 * @author Soo Han, Kim (princeb612.kr@gmail.com)
 * @desc
 *
 * Revision History
 * Date         Name                Description
 */

#include <hotplace/test/base/sample.hpp>

void test_bn1() {
    _test_case.begin("bignumber");
    struct testvector {
        const char* hexvalue;
        std::string decvalue;
    } table[] = {
        {"0x123456789abcdef", "81985529216486895"},
        {"0x123456789", "4886718345"},
        {"0x8000", "32768"},
        // bignumber from numeric string (greater than int128)
        // uint128.max + 1
        {"0x100000000000000000000000000000000", "340282366920938463463374607431768211456"},
        // 2^256 - 1
        {"0xffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff",
         "115792089237316195423570985008687907853269984665640564039457584007913129639935"},
    };

    bignumber bn1;
    bignumber bn2;

    for (const auto& item : table) {
        bn1 = item.hexvalue;
        bn2 = item.decvalue;

        bn1.dump([&](const binary_t& bin) -> void { _logger->hdump("from hexvalue", bin, 16, 3); });
        bn2.dump([&](const binary_t& bin) -> void { _logger->hdump("from decvalue", bin, 16, 3); });

        _test_case.assert(bn1 == bn2, __FUNCTION__, "compare");
        _test_case.assert(bn1.str() == item.decvalue, __FUNCTION__, "base16 %s", item.decvalue.c_str());
    }
}

void test_bn2() {
    _test_case.begin("bignumber");
    struct {
        const char* text;
        int64 n1;
        int64 n2;
        std::string add;
        std::string sub;
        std::string mul;
        std::string div;
        std::string mod;
        std::string lshift1;
        std::string rshift1;
    } table[] = {
        {"case 0", 36028797018963967LL, 1, "36028797018963968", "36028797018963966", "36028797018963967", "36028797018963967", "0", "72057594037927934",
         "18014398509481983"},
        {"case 1", 123456789012345678LL, 9876543210LL, "123456798888888888", "123456779135802468", "1219326311248285312223746380", "12499999", "8763888888",
         "246913578024691356", "61728394506172839"},
        {"case 2", -123456789012345678LL, -9876543210LL, "-123456798888888888", "-123456779135802468", "1219326311248285312223746380", "12499999",
         "-8763888888", "-246913578024691356", "-61728394506172839"},
        {"case 3", 123456789012345678LL, -9876543210LL, "123456779135802468", "123456798888888888", "-1219326311248285312223746380", "-12499999", "8763888888",
         "246913578024691356", "61728394506172839"},
        {"case 4", -123456789012345678LL, 9876543210LL, "-123456779135802468", "-123456798888888888", "-1219326311248285312223746380", "-12499999",
         "-8763888888", "-246913578024691356", "-61728394506172839"},
        {"case 5", 9876543210LL, 123456789012345678LL, "123456798888888888", "-123456779135802468", "1219326311248285312223746380", "0", "9876543210",
         "19753086420", "4938271605"},
        {"case 6", -9876543210LL, -123456789012345678LL, "-123456798888888888", "123456779135802468", "1219326311248285312223746380", "0", "-9876543210",
         "-19753086420", "-4938271605"},
        {"case 7", -9876543210LL, 123456789012345678LL, "123456779135802468", "-123456798888888888", "-1219326311248285312223746380", "0", "-9876543210",
         "-19753086420", "-4938271605"},
        {"case 8", 9876543210LL, -123456789012345678LL, "-123456779135802468", "123456798888888888", "-1219326311248285312223746380", "0", "9876543210",
         "19753086420", "4938271605"},
    };

    // mod : verified only positive big numbers

    for (auto item : table) {
        bignumber n1(item.n1);
        bignumber n2(item.n2);

#ifdef __SIZEOF_INT128__
        // gcc verification
        int128 v1 = item.n1;
        int128 v2 = item.n2;
        int128 add128 = v1 + v2;
        _test_case.assert(add128 == t_atoi<int128>(item.add), __FUNCTION__, "%s add %I128i", item.text, add128);
        int128 sub128 = v1 - v2;
        _test_case.assert(sub128 == t_atoi<int128>(item.sub), __FUNCTION__, "%s sub %I128i", item.text, sub128);
        int128 mul128 = v1 * v2;
        _test_case.assert(mul128 == t_atoi<int128>(item.mul), __FUNCTION__, "%s mul %I128i", item.text, mul128);
        int128 div128 = v1 / v2;
        _test_case.assert(div128 == t_atoi<int128>(item.div), __FUNCTION__, "%s div %I128i", item.text, div128);
        int128 mod128 = v1 % v2;
        _test_case.assert(mod128 == t_atoi<int128>(item.mod), __FUNCTION__, "%s mod %I128i", item.text, mod128);
        int128 lshift128 = v1 << 1;
        _test_case.assert(lshift128 == t_atoi<int128>(item.lshift1), __FUNCTION__, "%s lshift1 %I128i", item.text, lshift128);
        int128 rshift128 = v1 >> 1;
        _test_case.assert(rshift128 == t_atoi<int128>(item.rshift1), __FUNCTION__, "%s rshift1 %I128i", item.text, rshift128);
#endif

        auto add = (n1 + n2).str();
        _test_case.assert(add == item.add, __FUNCTION__, "%s add %s", item.text, add.c_str());
        auto sub = (n1 - n2).str();
        _test_case.assert(sub == item.sub, __FUNCTION__, "%s sub %s", item.text, sub.c_str());
        auto mul = (n1 * n2).str();
        _test_case.assert(mul == item.mul, __FUNCTION__, "%s mul %s", item.text, mul.c_str());
        auto div = (n1 / n2).str();
        _test_case.assert(div == item.div, __FUNCTION__, "%s div %s", item.text, div.c_str());
        auto mod = (n1 % n2).str();
        _test_case.assert(mod == item.mod, __FUNCTION__, "%s mod %s", item.text, mod.c_str());
        auto lshift1 = (n1 << 1).str();
        _test_case.assert(lshift1 == item.lshift1, __FUNCTION__, "%s lshift1 %s", item.text, lshift1.c_str());
        auto rshift1 = (n1 >> 1).str();
        _test_case.assert(rshift1 == item.rshift1, __FUNCTION__, "%s rshift1 %s", item.text, rshift1.c_str());
    }

#ifdef __SIZEOF_INT128__
    openssl_prng prng;
    int loop = 10;
    while (loop--) {
        int128 i1 = prng.rand64();
        int128 i2 = prng.rand64();
        int128 i = 0;
        bignumber b1 = i1;
        bignumber b2 = i2;
        bignumber bn;
        basic_stream bs;
        binary_t bin;
        std::string b16str;

        bs.clear();
        i = i1 + i2;
        bn = b1 + b2;
        bs.printf("%I128i", i);
        _test_case.assert(bs == bn.str(), __FUNCTION__, "%I128i + %I128i = %s (expect %I128i)", i1, i2, bn.str().c_str(), i);

        bs.clear();
        i = i1 - i2;
        bn = b1 - b2;
        bs.printf("%I128i", i);
        _test_case.assert(bs == bn.str(), __FUNCTION__, "%I128i - %I128i = %s (expect %I128i)", i1, i2, bn.str().c_str(), i);

        bs.clear();
        i = i1 * i2;
        bn = b1 * b2;
        bs.printf("%I128i", i);
        _test_case.assert(bs == bn.str(), __FUNCTION__, "%I128i * %I128i = %s (expect %I128i)", i1, i2, bn.str().c_str(), i);

        bs.clear();
        i = i1 / i2;
        bn = b1 / b2;
        bs.printf("%I128i", i);
        _test_case.assert(bs == bn.str(), __FUNCTION__, "%I128i / %I128i = %s (expect %I128i)", i1, i2, bn.str().c_str(), i);

        bs.clear();
        i = i1 % i2;
        bn = b1 % b2;
        bs.printf("%I128i", i);
        _test_case.assert(bs == bn.str(), __FUNCTION__, "%I128i %% %I128i = %s (expect %I128i)", i1, i2, bn.str().c_str(), i);
    }
#endif

    {
        bignumber a(int64(9223372036854775807));
        bignumber b(int64(2147483647));
        bignumber c;
        _logger->writeln("bignumber a = %s", a.str().c_str());
        _logger->writeln("bignumber b = %s", b.str().c_str());

        c = a + b;
        _test_case.assert(c.str() == "9223372039002259454", __FUNCTION__, "bignumber a + b = %s", c.str().c_str());
        c = a - b;
        _test_case.assert(c.str() == "9223372034707292160", __FUNCTION__, "bignumber a - b = %s", c.str().c_str());
        c = a * b;
        _test_case.assert(c.str() == "19807040619342712359383728129", __FUNCTION__, "bignumber a * b = %s", c.str().c_str());
        c = a / b;
        _test_case.assert(c.str() == "4294967298", __FUNCTION__, "bignumber a / b = %s", c.str().c_str());
    }

    // modular
    {
        // -7 % 3 = -1, 7 % -3 = 1
        auto a = bignumber(-7) % bignumber(3);
        _logger->writeln("a = %s", a.str().c_str());
        _test_case.assert(a.str() == "-1", __FUNCTION__, "-7 %% 3");

        auto b = bignumber(7) % bignumber(-3);
        _logger->writeln("b = %s", b.str().c_str());
        _test_case.assert(b.str() == "1", __FUNCTION__, "7 %% -3");
    }
}

void test_bn3() {
    _test_case.begin("bignumber");
    struct testvector {
        int bits;
        const char* minvalue;
        const char* maxvalue;
        const char* umaxvalue;  // 0 ~ umaxvalue
    } table[] = {
        {8, "-128", "127", "255"},
        {16, "-32768", "32767", "65535"},
        {32, "-2147483648", "2147483647", "4294967295"},
        {64, "-9223372036854775808", "9223372036854775807", "18446744073709551615"},
        {128, "-170141183460469231731687303715884105728", "170141183460469231731687303715884105727", "340282366920938463463374607431768211455"},
        {256, "-57896044618658097711785492504343953926634992332820282019728792003956564819968",
         "57896044618658097711785492504343953926634992332820282019728792003956564819967",
         "115792089237316195423570985008687907853269984665640564039457584007913129639935"},
        {512,
         "-670390396497129854978701249910292306373968291029619668886178072186088201503677348840093714908345171384501592909324302542687694140597328497321682"
         "4503042048",
         "6703903964971298549787012499102923063739682910296196688861780721860882015036773488400937149083451713845015929093243025426876941405973284973216824"
         "503042047",
         "1340780792994259709957402499820584612747936582059239337772356144372176403007354697680187429816690342769003185818648605085375388281194656994643364"
         "9006084095"},
        {1024,
         "-898846567431157953864652595394512366808988489471153286367150405788663379027504815663542386612037680105600569399356966788293948844072083112464237"
         "1531973706218888394671243274263815110980062304705972654147604250288441907534117123144073695655527041361858167525534229314911997362296923985815241"
         "7678164812112068608",
         "8988465674311579538646525953945123668089884894711532863671504057886633790275048156635423866120376801056005693993569667882939488440720831124642371"
         "5319737062188883946712432742638151109800623047059726541476042502884419075341171231440736956555270413618581675255342293149119973622969239858152417"
         "678164812112068607",
         "1797693134862315907729305190789024733617976978942306572734300811577326758055009631327084773224075360211201138798713933576587897688144166224928474"
         "3063947412437776789342486548527630221960124609411945308295208500576883815068234246288147391311054082723716335051068458629823994724593847971630483"
         "5356329624224137215"},
        {2048,
         "-161585030356555036503574383443349759802220513348577420160651727137623275694339454465986007057614567318443589804609490097470597795752454605475440"
         "7619322414156031543868365049804587509887519482605339802881919203378413839610932130987808091904716923808523529082292601815252144378794577053290430"
         "3776199561965192760957166694834171210342487393282284747428088017663161029038902829665513096354230157075129296432088558362971801859230928678799175"
         "5761508229522018488066166436156135628423554101048625785508634656617348392712903283489675229986341764993191077625831947186677718010677166148023226"
         "59239302476074096777926805529798115328",
         "1615850303565550365035743834433497598022205133485774201606517271376232756943394544659860070576145673184435898046094900974705977957524546054754407"
         "6193224141560315438683650498045875098875194826053398028819192033784138396109321309878080919047169238085235290822926018152521443787945770532904303"
         "7761995619651927609571666948341712103424873932822847474280880176631610290389028296655130963542301570751292964320885583629718018592309286787991755"
         "7615082295220184880661664361561356284235541010486257855086346566173483927129032834896752299863417649931910776258319471866777180106771661480232265"
         "9239302476074096777926805529798115327",
         "3231700607131100730071487668866995196044410266971548403213034542752465513886789089319720141152291346368871796092189801949411955915049092109508815"
         "2386448283120630877367300996091750197750389652106796057638384067568276792218642619756161838094338476170470581645852036305042887575891541065808607"
         "5523991239303855219143333896683424206849747865645694948561760353263220580778056593310261927084603141502585928641771167259436037184618573575983511"
         "5230164590440369761323328723122712568471082020972515710172693132346967854258065669793504599726835299863821552516638943733554360213543322960464531"
         "8478604952148193555853611059596230655"},
        {4096,
         "-522194440706576253345876355358312191289982124523691890192116741641976953985778728424413405967498779170445053357219631418993786719092896803631618"
         "0439256826389729784882718549991701807950671918591572140350059279731131881594196988563728361673421722933087484039543529018520356420243700593045572"
         "3398889179901450334346948844089389297345281509513047029978972671641173465151334822152951250798619993385710777084691777994264574315911895721724836"
         "7043905936319748237550094520674504208530837546834166925275516486044134775384991808184705966507606898412918594045916828375610659246423184062775112"
         "9991502061723924312978372460973085119032529566228054128659176900438043110514171350988491011565845088390033375977425399608182096851426875623920074"
         "5357956772999139525669980577589713555341556704529213644213989577742489147716176725853261163453069745299384650106148169784389143947422030800370647"
         "2837459911525285821188577408160690315522951458068463354171428220365223949985950890732881736611925133626529949897998045399734600887312408859224933"
         "7278296250891645352365597165827754037841109232858731866484424564097601587285012204633084554370741925392059649022614909286694888240515630429515006"
         "51206733594863336608245755565801460390869016718045121902354170201577095168",
         "5221944407065762533458763553583121912899821245236918901921167416419769539857787284244134059674987791704450533572196314189937867190928968036316180"
         "4392568263897297848827185499917018079506719185915721403500592797311318815941969885637283616734217229330874840395435290185203564202437005930455723"
         "3988891799014503343469488440893892973452815095130470299789726716411734651513348221529512507986199933857107770846917779942645743159118957217248367"
         "0439059363197482375500945206745042085308375468341669252755164860441347753849918081847059665076068984129185940459168283756106592464231840627751129"
         "9915020617239243129783724609730851190325295662280541286591769004380431105141713509884910115658450883900333759774253996081820968514268756239200745"
         "3579567729991395256699805775897135553415567045292136442139895777424891477161767258532611634530697452993846501061481697843891439474220308003706472"
         "8374599115252858211885774081606903155229514580684633541714282203652239499859508907328817366119251336265299498979980453997346008873124088592249337"
         "2782962508916453523655971658277540378411092328587318664844245640976015872850122046330845543707419253920596490226149092866948882405156304295150065"
         "1206733594863336608245755565801460390869016718045121902354170201577095167",
         "1044388881413152506691752710716624382579964249047383780384233483283953907971557456848826811934997558340890106714439262837987573438185793607263236"
         "0878513652779459569765437099983403615901343837183144280700118559462263763188393977127456723346843445866174968079087058037040712840487401186091144"
         "6797778359802900668693897688178778594690563019026094059957945343282346930302669644305902501597239986771421554169383555988529148631823791443449673"
         "4087811872639496475100189041349008417061675093668333850551032972088269550769983616369411933015213796825837188091833656751221318492846368125550225"
         "9983004123447848625956744921946170238065059132456108257318353800876086221028342701976982023131690176780066751954850799216364193702853751247840149"
         "0715913545998279051339961155179427110683113409058427288427979155484978295432353451706522326906139490598769300212296339568778287894844061600741294"
         "5674919823050571642377154816321380631045902916136926708342856440730447899971901781465763473223850267253059899795996090799469201774624817718449867"
         "4556592501783290704731194331655508075682218465717463732968849128195203174570024409266169108741483850784119298045229818573389776481031260859030013"
         "02413467189726673216491511131602920781738033436090243804708340403154190335"},
    };

    for (auto item : table) {
        bignumber intmin = -(bignumber(1) << (item.bits - 1));
        bignumber intmax = (bignumber(1) << (item.bits - 1)) - bignumber(1);
        bignumber uintmax = (bignumber(1) << item.bits) - bignumber(1);

        _logger->writeln([&](basic_stream& bs) -> void { bs << "int" << item.bits << ".min -2^" << (item.bits - 1); });
        _logger->writeln([&](basic_stream& bs) -> void { bs << "int" << item.bits << ".min 0x" << intmin.hex(); });
        _logger->writeln([&](basic_stream& bs) -> void { bs << "int" << item.bits << ".min " << intmin.str(); });

        _logger->writeln([&](basic_stream& bs) -> void { bs << "int" << item.bits << ".max 2^" << (item.bits - 1) << "-1"; });
        _logger->writeln([&](basic_stream& bs) -> void { bs << "int" << item.bits << ".max 0x" << intmax.hex(); });
        _logger->writeln([&](basic_stream& bs) -> void { bs << "int" << item.bits << ".max " << intmax.str(); });
        auto test = (intmin.str() == std::string(item.minvalue)) && (intmax.str() == std::string(item.maxvalue));
        _test_case.assert(test, __FUNCTION__, "check int%i.min ~ int%i.max", item.bits, item.bits);

        _logger->writeln([&](basic_stream& bs) -> void { bs << "uint" << item.bits << ".max 2^" << item.bits << "-1"; });
        _logger->writeln([&](basic_stream& bs) -> void { bs << "uint" << item.bits << ".max 0x" << uintmax.hex(); });
        _logger->writeln([&](basic_stream& bs) -> void { bs << "uint" << item.bits << ".max " << uintmax.str(); });
        auto utest = (uintmax.str() == std::string(item.umaxvalue));
        _test_case.assert(utest, __FUNCTION__, "check uint%i.max", item.bits);
    }

    {
        bignumber a(bignumber(1) << 128);  // 340282366920938463463374607431768211456
        bignumber b(bignumber(1) << 64);   // 18446744073709551616
        bignumber c;
        _logger->writeln("bignumber a = %s", a.str().c_str());
        _logger->writeln("bignumber b = %s", b.str().c_str());

        c = a + b;
        _test_case.assert(c.str() == "340282366920938463481821351505477763072", __FUNCTION__, "bignumber a + b = %s", c.str().c_str());
        c = a - b;
        _test_case.assert(c.str() == "340282366920938463444927863358058659840", __FUNCTION__, "bignumber a - b = %s", c.str().c_str());
        c = a * b;
        _test_case.assert(c.str() == "6277101735386680763835789423207666416102355444464034512896", __FUNCTION__, "bignumber a * b = %s", c.str().c_str());
        c = a / b;
        _test_case.assert(c.str() == "18446744073709551616", __FUNCTION__, "bignumber a / b = %s", c.str().c_str());

        openssl_prng prng;
        int loop = 10;
        while (loop--) {
            bignumber b1 = prng.rand64();
            bignumber b2 = prng.rand64();
            bignumber i = uint64(0);
            bignumber v = uint64(0);
            i = b1 + b2;
            _logger->writeln("%s + %s = %s", b1.str().c_str(), b2.str().c_str(), i.str().c_str());
            i = b1 - b2;
            _logger->writeln("%s - %s = %s", b1.str().c_str(), b2.str().c_str(), i.str().c_str());
            i = b1 * b2;
            _logger->writeln("%s * %s = %s", b1.str().c_str(), b2.str().c_str(), i.str().c_str());
            i = b1 / b2;
            _logger->writeln("%s / %s = %s", b1.str().c_str(), b2.str().c_str(), i.str().c_str());
            i = b1 % b2;
            _logger->writeln("%s %% %s = %s", b1.str().c_str(), b2.str().c_str(), i.str().c_str());
        }
    }
}

void test_bn4() {
    _test_case.begin("bignumber");
    struct testvector {
        uint64 i1;
        uint64 i2;
    } table[]{
        {0xc4fe9903b76d6c72ULL, 0x8e6781062bd05a82ULL}, {0xe8556865b15e621ULL, 0x894da65e198e0e8bULL}, {0x5dd523de7ca877ecULL, 0xe2c900ef8c975e5cULL},
        {0x1a72c958dda70797ULL, 0xbbaf38760fb4ff55ULL}, {0xb6a22bb40f07c9a0ULL, 0xd2c5ab685c2dcb4ULL}, {0xdc5c66b4bfb3312fULL, 0xb3c5b881db04af9bULL},
        {0x8ee394be324ce02fULL, 0x93d8c0e7925e2833ULL},
    };
    openssl_prng prng;
    for (const auto& item : table) {
        bignumber b1;
        bignumber b2;

        b1 = item.i1;
        b2 = item.i2;

        auto bit_and = item.i1 & item.i2;
        auto bit_or = item.i1 | item.i2;
        auto bit_xor = item.i1 ^ item.i2;

        auto bn_and = b1 & b2;
        auto bn_or = b1 | b2;
        auto bn_xor = b1 ^ b2;

        _test_case.assert(bignumber(bit_and) == bn_and, __FUNCTION__, "%I64x AND %I64x = %I64x (%s)", item.i1, item.i2, bit_and, bn_and.hex().c_str());
        _test_case.assert(bignumber(bit_or) == bn_or, __FUNCTION__, "%I64x OR %I64x = %I64x (%s)", item.i1, item.i2, bit_or, bn_or.hex().c_str());
        _test_case.assert(bignumber(bit_xor) == bn_xor, __FUNCTION__, "%I64x XOR %I64x = %I64x (%s)", item.i1, item.i2, bit_xor, bn_xor.hex().c_str());
    }

    {
        uint64 i1 = 0;
        uint64 i2 = 0;
        uint64 ir = 0;
        bignumber b1;
        bignumber b2;
        bignumber br;
        int loop = 10;

        while (loop--) {
            i1 = prng.rand64();
            i2 = prng.rand64();
            b1 = i1;
            b2 = i2;

            _logger->writeln("sample %I64x %I64x", i1, i2);

            ir = i1 & i2;
            br = b1 & b2;
            _logger->writeln("%I64x & %I64x = %s (expected %I64x)", i1, i2, br.hex().c_str(), ir);
            _test_case.assert(bignumber(ir) == br, __FUNCTION__, "%I64x & %I64x = %I64x (%s)", i1, i2, ir, br.hex().c_str());

            ir = i1 | i2;
            br = b1 | b2;
            _logger->writeln("%I64x | %I64x = %s (expected %I64x)", i1, i2, br.hex().c_str(), ir);
            _test_case.assert(bignumber(ir) == br, __FUNCTION__, "%I64x | %I64x = %I64x (%s)", i1, i2, ir, br.hex().c_str());

            ir = i1 ^ i2;
            br = b1 ^ b2;
            _logger->writeln("%I64x ^ %I64x = %s (expected %I64x)", i1, i2, br.hex().c_str(), ir);
            _test_case.assert(bignumber(ir) == br, __FUNCTION__, "%I64x ^ %I64x = %I64x (%s)", i1, i2, ir, br.hex().c_str());
        }
    }
}

void test_bn5() {
    _test_case.begin("bignumber");
    std::string sample = std::string("0x0123456789abcdef0123456789abcdef");
#ifdef __SIZEOF_INT128__
    int128 signed_sample = t_htoi<int128>(sample.c_str());
    uint128 unsigned_sample = t_htoi<uint128>(sample.c_str());
#else
    int64 signed_sample = t_htoi<int64>(sample.c_str());
    uint64 unsigned_sample = t_htoi<uint64>(sample.c_str());
#endif
    bignumber bn(sample);

    auto i8 = bn.t_bntoi<int8>();
    _logger->writeln("int8 %i", i8);
    _test_case.assert(i8 == int8(signed_sample), __FUNCTION__, "to.int8 %i", int8(signed_sample));

    auto ui8 = bn.t_bntoi<uint8>();
    _logger->writeln("uint8 %u", ui8);
    _test_case.assert(ui8 == uint8(unsigned_sample), __FUNCTION__, "to.uint8 %u", uint8(unsigned_sample));

    auto i16 = bn.t_bntoi<int16>();
    _logger->writeln("int16 %i", i16);
    _test_case.assert(i16 == int16(signed_sample), __FUNCTION__, "to.int16 %i", int16(signed_sample));

    auto ui16 = bn.t_bntoi<uint16>();
    _logger->writeln("uint16 %u", ui16);
    _test_case.assert(ui16 == uint16(unsigned_sample), __FUNCTION__, "to.uint16 %u", uint16(unsigned_sample));

    auto i32 = bn.t_bntoi<int32>();
    _logger->writeln("int32 %i", i32);
    _test_case.assert(i32 == int32(signed_sample), __FUNCTION__, "to.int32 %i", int32(signed_sample));

    auto ui32 = bn.t_bntoi<uint32>();
    _logger->writeln("uint32 %u", ui32);
    _test_case.assert(ui32 == uint32(unsigned_sample), __FUNCTION__, "to.uint32 %u", uint32(unsigned_sample));

    auto i64 = bn.t_bntoi<int64>();
    _logger->writeln("int64 %I64i", i64);
    _test_case.assert(i64 == int64(signed_sample), __FUNCTION__, "to.int64 %I64i", int64(signed_sample));

    auto ui64 = bn.t_bntoi<uint64>();
    _logger->writeln("uint64 %I64u", ui64);
    _test_case.assert(ui64 == uint64(unsigned_sample), __FUNCTION__, "to.uint64 %I64u", uint64(unsigned_sample));

#ifdef __SIZEOF_INT128__
    auto i128 = bn.t_bntoi<int128>();
    _logger->writeln("int128 %I128i", i128);
    _test_case.assert(i128 == int128(signed_sample), __FUNCTION__, "to.int128 %I64i", signed_sample);

    auto ui128 = bn.t_bntoi<uint128>();
    _logger->writeln("uint128 %I128u", ui128);
    _test_case.assert(ui128 == uint128(unsigned_sample), __FUNCTION__, "to.uint128 %I64u", signed_sample);
#endif
}

void test_bn6() {
    _test_case.begin("bignumber");
    bignumber bn(1);
    bignumber bn2;
    bn = -bn;
    _logger->writeln("bignumber = %s", bn.str().c_str());
    _test_case.assert(bn == -1, __FUNCTION__, "bignumber = -1");

    bn = "0xffffffffffffffff";  // uint64.max
    bn = -bn;
    bn2 = "-18446744073709551615";
    _logger->writeln("bignumber = %s", bn.str().c_str());
    _test_case.assert(bn == bn2, __FUNCTION__, "bignumber = -uint64.max");

    bn = "0xffffffffffffffffffffffffffffffff";  // uint128.max
    bn = -bn;
    bn2 = "-340282366920938463463374607431768211455";
    _logger->writeln("bignumber = %s", bn.str().c_str());
    _test_case.assert(bn == bn2, __FUNCTION__, "bignumber = -uint128.max");
}

void test_bn7() {
    _test_case.begin("bignumber");
    openssl_prng prng;
    int loop = 10;
    while (--loop) {
        uint64 i = prng.rand64();
        _logger->writeln("i = %I64u", i);
        bignumber bn(i);
        bn *= bn;
        _logger->writeln("i^i %s", bn.str().c_str());
        bn.sqrt();
        _logger->writeln("sqrt %s", bn.str().c_str());
        _test_case.assert(bn == i, __FUNCTION__, "square, sqrt %I64u", i);
    }
    {
        // https://en.wikipedia.org/wiki/Modular_exponentiation
        // c ≡ 4^13 (mod 497)
        // c is determined to be 445
        struct testvector {
            uint64 base;
            uint64 exp;
            uint64 m;
            uint64 expect;
        } table[] = {
            {4, 1, 497, 4},   {4, 2, 497, 16},  {4, 3, 497, 64},   {4, 4, 497, 256},  {4, 5, 497, 30},   {4, 6, 497, 120},  {4, 7, 497, 480},
            {4, 8, 497, 429}, {4, 9, 497, 225}, {4, 10, 497, 403}, {4, 11, 497, 121}, {4, 12, 497, 484}, {4, 13, 497, 445},
        };
        for (const auto& item : table) {
            auto bn = bignumber::modpow(item.base, item.exp, item.m);
            _test_case.assert(bn == item.expect, __FUNCTION__, "%I64u ^ %I64u %% %I64u = %s", item.base, item.exp, item.m, bn.str().c_str());
        }
    }
    {
        auto bn = bignumber::modinv(42, 2017);
        _test_case.assert(bn == 1969, __FUNCTION__, "modinv");
    }
}

void testcase_bignumber() {
    test_bn1();  // numeric, hexdecimal string
    test_bn2();  // + - * /
    test_bn3();  // shift
    test_bn4();  // AND OR XOR
    test_bn5();  // bn to integer
    test_bn6();  // neg
    test_bn7();  // sqaure, sqrt, modpow
}
