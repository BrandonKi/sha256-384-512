#ifndef SHA256_384_512_SHA512_H
#define SHA256_384_512_SHA512_H

class sha512 {

    using u8 = uint8_t;
    using u32 = uint32_t;
    using u64 = uint64_t;

public:

    /**
     * performs a sha512 hash on the input message
     *
     * @param message input message
     * @return sha512 hash of input message
     */
    static std::string hash(const std::string& message) {
        std::string message_ = pad(message);

        u64 hash_[8] = {
                0x6a09e667f3bcc908,
                0xbb67ae8584caa73b,
                0x3c6ef372fe94f82b,
                0xa54ff53a5f1d36f1,
                0x510e527fade682d1,
                0x9b05688c2b3e6c1f,
                0x1f83d9abfb41bd6b,
                0x5be0cd19137e2179
        };
        return message_;
    }
    sha512() = delete;

    ~sha512() = delete;

    sha512(const sha512&) = delete;

    sha512& operator=(const sha512&) = delete;

    sha512(const sha512&&) = delete;

    sha512& operator=(sha512&&) = delete;

private:

    static std::string pad(const std::string& message) {
        return "";
    }
};

#endif //SHA256_384_512_SHA512_H
