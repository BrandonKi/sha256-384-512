#ifndef SHA256_384_512_SHA384_H
#define SHA256_384_512_SHA384_H

class sha384 {

    using u8 = uint8_t;
    using u32 = uint32_t;
    using u64 = uint64_t;

public:

    /**
     * performs a sha384 hash on the input message
     *
     * @param message input message
     * @return sha384 hash of input message
     */
    static std::string hash(const std::string& message) {
        std::string message_ = pad(message);

        u64 hash_[8] = {
                0xcbbb9d5dc1059ed8,
                0x629a292a367cd507,
                0x9159015a3070dd17,
                0x152fecd8f70e5939,
                0x67332667ffc00b31,
                0x8eb44a8768581511,
                0xdb0c2e0d64f98fa7,
                0x47b5481dbefa4fa4
        };

        return message_;
    }

    sha384() = delete;

    ~sha384() = delete;

    sha384(const sha384&) = delete;

    sha384& operator=(const sha384&) = delete;

    sha384(const sha384&&) = delete;

    sha384& operator=(sha384&&) = delete;

private:
    static std::string pad(const std::string& message) {
        return "";
    }


};

#endif //SHA256_384_512_SHA384_H
