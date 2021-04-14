#ifndef SHA256_384_512_SHA256_H
#define SHA256_384_512_SHA256_H

#include <string>
#include <vector>
#include <array>
#include <cstdint>
#include <algorithm>

class sha256 {

    using i8  = int8_t;
    using i16 = int16_t;
    using i32 = int32_t;
    using i64 = int64_t;
    using u8  = uint8_t;
    using u16 = uint16_t;
    using u32 = uint32_t;
    using u64 = uint64_t;
    using f32 = float_t;
    using f64 = double_t;

public:
    static std::string hash(const std::string &message) {
        message_ = pad(message);
        for(int i = 0 ; i < message_.size() / 64; ++i)
            hash_block();
        return hash_to_string(hash_);
    }

    sha256() = delete;
    ~sha256() = delete;
    sha256(const sha256&) = delete;
    sha256& operator = (const sha256&) = delete;
    sha256(const sha256&&) = delete;
    sha256& operator = (sha256&&) = delete;

private:

    static inline std::array<u32, 8> hash_ = {
            0x6a09e667,
            0xbb67ae85,
            0x3c6ef372,
            0xa54ff53a,
            0x510e527f,
            0x9b05688c,
            0x1f83d9ab,
            0x5be0cd19
    };

    constexpr static inline u32 k[64] {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    static inline std::string message_;
    static inline u32 a, b, c, d, e, f, g, h;

    static std::string hash_to_string(std::array<u32, 8> hash) {
        std::string hash_str;
        hash_str.reserve(257);
        for(auto i : hash) {
            hash_str += value_to_bytes(i);
        }
        return hash_str;
    }

    template <typename T>
    inline static std::string value_to_bytes(T value) {
        std::string result;
        for(int i = sizeof(value) - 1; i >= 0; --i)
            result.push_back(static_cast<u8>(value >> (i * 8)));
        return result;
    }

    inline static std::string pad(const std::string& message) {
        std::string result = message;
        const auto msg_len = message.size();
        const auto num_zero_bytes = (56 - (msg_len + 1)) % 56;
        result.append(1, '\x80');
        result.append(num_zero_bytes, 0);
        result.append(value_to_bytes(msg_len * 8));
        return result;
    }

    inline static u32 R(const u32 x, const u32 n) {
        return x >> n;
    }

    inline static u32 S(const u32 x, const u32 n) {
        return (x >> n) | (x << (sizeof(u32) - n));
    }

    inline static u32 ch(u32 x, u32 y, u32 z) {
        return (x & y) ^ (~x & z);
    }

    inline static u32 maj(const u32 x, const u32 y, const u32 z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    inline static u32 usig0(const u32 x) {
        return S(x, 2) ^ S(x, 13) ^ S(x, 22);
    }

    inline static u32 usig1(const u32 x) {
        return S(x, 6) ^ S(x, 11) ^ S(x, 25);
    }

    inline static u32 lsig0(const u32 x) {
        return S(x, 7) ^ S(x, 18) ^ R(x, 3);
    }

    inline static u32 lsig1(const u32 x) {
        return S(x, 17) ^ S(x, 19) ^ R(x, 10);
    }

    static void hash_block() {
        std::cout << "yo\n";
        a = hash_[0];
        b = hash_[1];
        c = hash_[2];
        d = hash_[3];
        e = hash_[4];
        f = hash_[5];
        g = hash_[6];
        h = hash_[7];

        u32 w[64];
        for(auto i = 0; i < 16; ++i)
            w[i] = static_cast<u8>(message_[i] << 24) | static_cast<u8>(message_[i + 1] << 16) |
                    static_cast<u8>(message_[i + 2] << 8) | static_cast<u8>(message_[i + 3]);

        for(auto j = 16; j < 64; ++j) {
            w[j] = lsig1(w[j - 2]) + w[j - 7] + lsig0(w[j - 15]) + w[j - 16];

            u32 t1 = h + usig1(e) + ch(e, f, g) + k[j] + w[j];
            u32 t2 = usig0(a) + maj(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + t1;
            d = c;
            c = b;
            b = a;
            a = t1 + t2;
        }
        hash_[0] += a;
        hash_[1] += b;
        hash_[2] += c;
        hash_[3] += d;
        hash_[4] += e;
        hash_[5] += f;
        hash_[6] += g;
        hash_[7] += h;
    }

};


#endif //SHA256_384_512_SHA256_H
