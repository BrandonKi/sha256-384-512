#ifndef SHA256_384_512_SHA256_H
#define SHA256_384_512_SHA256_H

#include <string>
#include <vector>
#include <cstdint>

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
        auto message_digest = pad(message);
        for(int i = 0 ; i < message_digest.size() / 64; ++i)
            hash_block();
        return message_digest;
    }

    sha256() = delete;
    ~sha256() = delete;
    sha256(const sha256&) = delete;
    sha256& operator = (const sha256&) = delete;
    sha256(const sha256&&) = delete;
    sha256& operator = (sha256&&) = delete;

private:

    static inline u32 last_hash[8] = {
            0x6a09e667,
            0xbb67ae85,
            0x3c6ef372,
            0xa54ff53a,
            0x510e527f,
            0x9b05688c,
            0x1f83d9ab,
            0x5be0cd19
    };

    static u32 a, b, c, d, e, f, g, h;


    template <typename T>
    inline static std::string value_to_bytes(T value) {
        std::string result;
        for(int i = sizeof(value) - 1; i >= 0; --i)
            result.push_back(static_cast<u8>(value >> (i * 8)));
        return result;
    }

    inline static std::string pad(const std::string& message) {
        std::string result = message;
        auto msg_len = message.size();
        auto num_zero_bytes = (56 - (msg_len + 1)) % 56;
        result.append(1, static_cast<u8>(0x80));
        result.append(num_zero_bytes, 0);
        result.append(value_to_bytes(msg_len * 8));
        return result;
    }

    inline static u32 R(u32 x, u32 n) {
        return x >> n;
    }

    inline static u32 S(u32 x, u32 n) {
        return (x >> n) | (x << (sizeof(u32) - n));
    }

    inline static u32 ch(u32 x, u32 y, u32 z) {
        return (x & y) ^ (~x & z);
    }

    inline static u32 maj(u32 x, u32 y, u32 z) {
        return (x & y) ^ (x & z) ^ (y & z);
    }

    inline static u32 usig0(u32 x) {
        return S(x, 2) ^ S(x, 13) ^ S(x, 22);
    }

    inline static u32 usig1(u32 x) {
        return S(x, 6) ^ S(x, 11) ^ S(x, 25);
    }

    inline static u32 lsig0(u32 x) {
        return S(x, 7) ^ S(x, 18) ^ R(x, 3);
    }

    inline static u32 lsig1(u32 x) {
        return S(x, 17) ^ S(x, 19) ^ R(x, 10);
    }

    static void hash_block() {
        std::cout << "yo\n";
        a = last_hash[0];
        b = last_hash[1];
        c = last_hash[2];
        d = last_hash[3];
        e = last_hash[4];
        f = last_hash[5];
        g = last_hash[6];
        h = last_hash[7];
    }

};


#endif //SHA256_384_512_SHA256_H
