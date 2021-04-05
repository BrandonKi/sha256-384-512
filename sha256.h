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
        return message_digest;
    }

    sha256() = delete;
    ~sha256() = delete;

private:

    unsigned int initial_hash[8] = {
            0x6a09e667,
            0xbb67ae85,
            0x3c6ef372,
            0xa54ff53a,
            0x510e527f,
            0x9b05688c,
            0x1f83d9ab,
            0x5be0cd19
    };

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

};


#endif //SHA256_384_512_SHA256_H
