#include "sample.hpp"

// refer ChatGPT
#include <iomanip>
#include <sstream>

/*
 * int128(MSVC), int256, iont512, ...
 * refer ChatGPT
 */
class bignumber {
   public:
    bignumber(int64 value = 0) { set(value); }
    bignumber(const bignumber &other) {
        d = other.d;
        sign = other.sign;
    }
    bignumber(bignumber &&other) {
        d = std::move(other.d);
        sign = other.sign;
        other.sign = 1;
    }

    bignumber &operator=(const bignumber &other) {
        d = other.d;
        sign = other.sign;
        return *this;
    }

    bignumber &operator=(int64 value) {
        set(value);
        return *this;
    }

    bignumber add(const bignumber &lhs, const bignumber &rhs) const {
        bignumber res;
        if (lhs.sign == rhs.sign) {
            res = absadd(lhs, rhs);
            res.sign = lhs.sign;
        } else {
            if (abscmp(lhs, rhs) >= 0) {
                res = abssub(lhs, rhs);
                res.sign = lhs.sign;
            } else {
                res = abssub(rhs, lhs);
                res.sign = rhs.sign;
            }
        }
        return res;
    }
    bignumber subtract(const bignumber &lhs, const bignumber &rhs) const {
        bignumber res;
        if (lhs.sign != rhs.sign) {
            res = absadd(lhs, rhs);
            res.sign = lhs.sign;
        } else {
            int cmp = abscmp(lhs, rhs);
            if (cmp == 0) {
                res = 0;
            } else {
                if (cmp > 0) {
                    res = abssub(lhs, rhs);
                    res.sign = lhs.sign;
                } else {
                    res = abssub(rhs, lhs);
                    res.sign = -lhs.sign;
                }
            }
        }
        return res;
    }
    bignumber multiply(const bignumber &lhs, const bignumber &rhs) const {
        bignumber res;
        res.sign = lhs.sign * rhs.sign;
        res.d.assign(lhs.d.size() + rhs.d.size(), 0);

        for (size_t i = 0; i < lhs.d.size(); i++) {
            uint64 carry = 0;
            for (size_t j = 0; j < rhs.d.size() || carry; j++) {
                uint64 cur = res.d[i + j] + (uint64)lhs.d[i] * (j < rhs.d.size() ? rhs.d[j] : 0) + carry;

                res.d[i + j] = cur % BASE;
                carry = cur / BASE;
            }
        }
        res.trim();
        return res;
    }
    bignumber divide(const bignumber &lhs, const bignumber &rhs) const {
        // O(n^2)
        bignumber a = lhs;
        bignumber b = rhs;
        bignumber res;
        bignumber cur;

        res.sign = lhs.sign * rhs.sign;
        a.sign = b.sign = 1;

        res.d.resize(a.d.size());

        for (int i = (int)a.d.size() - 1; i >= 0; i--) {
            cur.d.insert(cur.d.begin(), a.d[i]);
            cur.trim();

            uint32_t x = 0;
            uint32_t l = 0;
            uint32_t r = BASE - 1;
            while (l <= r) {
                uint32_t m = (l + r) / 2;
                bignumber t = b * m;
                if (abscmp(t, cur) <= 0) {
                    x = m;
                    l = m + 1;
                } else {
                    r = m - 1;
                }
            }

            res.d[i] = x;
            cur = cur - b * x;
        }

        res.trim();
        return res;
    }

    bignumber mod(const bignumber &lhs, const bignumber &rhs) const { return lhs - (lhs / rhs) * rhs; }

    int compare(const bignumber &lhs, const bignumber &rhs) const {
        if (lhs.sign != rhs.sign) return lhs.sign < rhs.sign ? -1 : 1;

        if (lhs.d.size() != rhs.d.size()) {
            if (lhs.sign == 1)
                return lhs.d.size() < rhs.d.size() ? -1 : 1;
            else
                return lhs.d.size() < rhs.d.size() ? 1 : -1;
        }

        for (int i = (int)lhs.d.size() - 1; i >= 0; i--) {
            if (lhs.d[i] != rhs.d[i]) {
                if (lhs.sign == 1)
                    return lhs.d[i] < rhs.d[i] ? -1 : 1;
                else
                    return lhs.d[i] < rhs.d[i] ? 1 : -1;
            }
        }
        return 0;
    }

    bignumber operator+(const bignumber &other) const { return add(*this, other); }

    bignumber operator-(const bignumber &other) const { return subtract(*this, other); }

    bignumber operator*(const bignumber &other) const { return multiply(*this, other); }

    bignumber operator/(const bignumber &other) const { return divide(*this, other); }

    bignumber operator%(const bignumber &other) const { return mod(*this, other); }

    bool operator<(const bignumber &other) const { return compare(*this, other) < 0; }

    bool operator<=(const bignumber &other) const { return compare(*this, other) <= 0; }

    bool operator>(const bignumber &other) const { return compare(*this, other) > 0; }

    bool operator>=(const bignumber &other) const { return compare(*this, other) >= 0; }

    bignumber operator<<(unsigned int k) const { return leftshift(k); }

    bignumber operator>>(unsigned int k) const { return rightshift(k); }

    std::string str() const {
        std::stringstream ss;
        if (d.empty()) {
            ss << '0';
        } else {
            if (sign == -1) {
                ss << '-';
            }
            ss << d.back();
            for (int i = (int)d.size() - 2; i >= 0; i--) {
                ss << std::setw(9) << std::setfill('0') << d[i];
            }
        }
        return ss.str();
    }

   protected:
    bignumber &set(int64 value) {
        if (value > 0) {
            sign = 1;
        } else {
            sign = -1;
            value = -value;
        }
        d.clear();
        while (value) {
            d.push_back(value % BASE);
            value /= BASE;
        }
        if (d.empty()) {
            sign = 1;
        }
        return *this;
    }

    bignumber leftshift(unsigned int k) const {
        bignumber res = *this;
        bignumber two(2);
        while(k--) {
            res = res * two;
        }
        return res;
    }

    bignumber rightshift(unsigned int k) const {
        bignumber res = *this;
        bignumber two(2);
        while(k--) {
            res = res / two;
        }
        return res;
    }

    void trim() {
        while ((false == d.empty()) && (0 == d.back())) {
            d.pop_back();
        }
        if (d.empty()) {
            sign = 1;
        }
    }

    static int abscmp(const bignumber &a, const bignumber &b) {
        int ret = 0;
        if (a.d.size() != b.d.size()) {
            ret = a.d.size() < b.d.size() ? -1 : 1;
        } else {
            for (int i = (int)a.d.size() - 1; i >= 0; --i) {
                if (a.d[i] != b.d[i]) {
                    ret = a.d[i] < b.d[i] ? -1 : 1;
                    break;
                }
            }
        }
        return ret;
    }

    static bignumber absadd(const bignumber &a, const bignumber &b) {
        // O(n)
        bignumber res;
        uint64 carry = 0;
        size_t n = std::max(a.d.size(), b.d.size());
        res.d.resize(n);

        for (size_t i = 0; i < n; i++) {
            uint64 sum = carry;
            if (i < a.d.size()) {
                sum += a.d[i];
            }
            if (i < b.d.size()) {
                sum += b.d[i];
            }
            res.d[i] = sum % BASE;
            carry = sum / BASE;
        }
        if (carry) {
            res.d.push_back(carry);
        }
        return res;
    }

    static bignumber abssub(const bignumber &a, const bignumber &b) {
        // |a| >= |b|
        // O(n)
        bignumber res;
        res.d.resize(a.d.size());
        int64 carry = 0;

        for (size_t i = 0; i < a.d.size(); i++) {
            int64 cur = (int64)a.d[i] - carry;
            if (i < b.d.size()) {
                cur -= b.d[i];
            }
            if (cur < 0) {
                cur += BASE;
                carry = 1;
            } else {
                carry = 0;
            }
            res.d[i] = cur;
        }
        res.trim();
        return res;
    }

   private:
    static const uint32 BASE = 1000000000;  // 1e9
    std::vector<uint32> d;                  // digit(4bytes)
    int sign;
};

// #ifdef _MSC_VER
// int128
// #endif

class int256 {
   public:
    int256() {}
    int256(const int256 &other) { v = other.v; }
    int256(int256 &&other) { v = std::move(other.v); }
    int256(const bignumber &other) { v = other; }
    int256(bignumber &&other) { v = std::move(other); }

    int256& operator=(const int256 &other) {
        v = other.v;
        normalize();
        return *this;
    }
    int256 operator+(const int256 &other) const {
        int256 i(v + other.v);
        i.normalize();
        return i;
    }
    int256 operator-(const int256 &other) const {
        int256 i(v - other.v);
        i.normalize();
        return i;
    }
    int256 operator*(const int256 &other) const {
        int256 i(v * other.v);
        i.normalize();
        return i;
    }
    int256 operator/(const int256 &other) const {
        int256 i(v / other.v);
        i.normalize();
        return i;
    }
    int256 operator%(const int256 &other) const {
        int256 i(v % other.v);
        i.normalize();
        return i;
    }

    std::string str() { return v.str(); }

   protected:
    static const bignumber &MOD() {
        static bignumber m = bignumber(1) << 256;
        return m;
    }
    static const bignumber &HALF() {
        static bignumber m = bignumber(1) << 255;
        return m;
    }
    void normalize() {
        v = v.mod(v, MOD());
        // int256
        if (v < 0) {
            v = v + MOD();
        }
        // signed
        if (v >= HALF()) {
            v = v - MOD();
        }
    }
   private:
    bignumber v;
};

void test_bignumber() {
    _test_case.begin("bignumber");
    struct {
        const char *text;
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
        {"case 1", 123456789012345678LL, 9876543210LL,  //
         "123456798888888888", "123456779135802468", "1219326311248285312223746380", "12499999", "8763888888", "246913578024691356", "61728394506172839"},
        {"case 2", -123456789012345678LL, -9876543210LL,  //
         "-123456798888888888", "-123456779135802468", "1219326311248285312223746380", "12499999", "-8763888888", "-246913578024691356", "-61728394506172839"},
        {"case 3", 123456789012345678LL, -9876543210LL,  //
         "123456779135802468", "123456798888888888", "-1219326311248285312223746380", "-12499999", "8763888888", "246913578024691356", "61728394506172839"},
        {"case 4", -123456789012345678LL, 9876543210LL,  //
         "-123456779135802468", "-123456798888888888", "-1219326311248285312223746380", "-12499999", "-8763888888", "-246913578024691356",
         "-61728394506172839"},
        {"case 5", 9876543210LL, 123456789012345678LL,  //
         "123456798888888888", "-123456779135802468", "1219326311248285312223746380", "0", "9876543210", "19753086420", "4938271605"},
        {"case 6", -9876543210LL, -123456789012345678LL,  //
         "-123456798888888888", "123456779135802468", "1219326311248285312223746380", "0", "-9876543210", "-19753086420", "-4938271605"},
        {"case 7", -9876543210LL, 123456789012345678LL,  //
         "123456779135802468", "-123456798888888888", "-1219326311248285312223746380", "0", "-9876543210", "-19753086420", "-4938271605"},
        {"case 8", 9876543210LL, -123456789012345678LL,  //
         "-123456779135802468", "123456798888888888", "-1219326311248285312223746380", "0", "9876543210", "19753086420", "4938271605"},
        {"case 9", 36028797018963967LL, 1,  //
         "36028797018963968", "36028797018963966", "36028797018963967", "36028797018963967", "0", "72057594037927934", "18014398509481983"},
    };

    for (auto item : table) {
        bignumber n1 = item.n1;
        bignumber n2 = item.n2;

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

    {
        int256 a(bignumber(1) << 128);
        int256 b(bignumber(1) << 64);
        int256 c;
        _logger->writeln("a = %s", a.str().c_str());
        _logger->writeln("b = %s", b.str().c_str());

        // https://www.calculator.net/big-number-calculator.html

        c = a + b;
        _test_case.assert(c.str() == "340282366920938463481821351505477763072", __FUNCTION__, "int256 a + b = %s", c.str().c_str());
        c = a - b;
        _test_case.assert(c.str() == "340282366920938463444927863358058659840", __FUNCTION__, "int256 a - b = %s", c.str().c_str());
        c = a * b;
        _test_case.assert(c.str() == "6277101735386680763835789423207666416102355444464034512896", __FUNCTION__, "int256 a * b = %s", c.str().c_str());
        c = a / b;
        _test_case.assert(c.str() == "18446744073709551616", __FUNCTION__, "int256 a / b = %s", c.str().c_str());
    }
}
