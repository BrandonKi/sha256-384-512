/**
 * @file sha256.h
 * @author Brandon Kirincich
 * @version 1.0
 * @date 2021-05-22
 * 
 * @example 
 *  // hash a message and print the resulting hash in hex
 *  std::cout << sha256::to_hex(sha256::hash("abc")) << '\n';
 * 
 * @copyright 
 *  MIT License
 *
 *  Copyright (c) 2021 Brandon Kirincich
 *
 *  Permission is hereby granted, free of charge, to any person obtaining a copy
 *  of this software and associated documentation files (the "Software"), to deal
 *  in the Software without restriction, including without limitation the rights
 *  to use, copy, modify, merge, publish, distribute, sublicense, and/or sell
 *  copies of the Software, and to permit persons to whom the Software is
 *  furnished to do so, subject to the following conditions:
 *
 *  The above copyright notice and this permission notice shall be included in all
 *  copies or substantial portions of the Software.
 *
 *  THE SOFTWARE IS PROVIDED "AS IS", WITHOUT WARRANTY OF ANY KIND, EXPRESS OR
 *  IMPLIED, INCLUDING BUT NOT LIMITED TO THE WARRANTIES OF MERCHANTABILITY,
 *  FITNESS FOR A PARTICULAR PURPOSE AND NONINFRINGEMENT. IN NO EVENT SHALL THE
 *  AUTHORS OR COPYRIGHT HOLDERS BE LIABLE FOR ANY CLAIM, DAMAGES OR OTHER
 *  LIABILITY, WHETHER IN AN ACTION OF CONTRACT, TORT OR OTHERWISE, ARISING FROM,
 *  OUT OF OR IN CONNECTION WITH THE SOFTWARE OR THE USE OR OTHER DEALINGS IN THE
 *  SOFTWARE.
 * 
 */
#ifndef SHA256_384_512_SHA256_H
#define SHA256_384_512_SHA256_H

#include <string>
#include <vector>
#include <array>
#include <cstdint>
#include <algorithm>

#include <sstream>
#include <iomanip>

class sha256 {

    using u8 = uint8_t;
    using u32 = uint32_t;
    using u64 = uint64_t;

    constexpr static auto BLOCK_SIZE = 64;

public:

    /**
     * performs a sha256 hash on the input message
     *
     * @param message input message
     * @return sha256 hash of input message
     */
    static std::string hash(const std::string& message) {
        std::string message_ = pad(message);

        std::array<u32, 8> hash_ = {
                0x6a09e667,
                0xbb67ae85,
                0x3c6ef372,
                0xa54ff53a,
                0x510e527f,
                0x9b05688c,
                0x1f83d9ab,
                0x5be0cd19
        };

        for (int i = 0; i < message_.size() / BLOCK_SIZE; ++i)
            hash_block(message_, hash_, i);
        return to_hex(hash_to_string(hash_));
    }

    sha256() = delete;

    ~sha256() = delete;

    sha256(const sha256&) = delete;

    sha256& operator=(const sha256&) = delete;

    sha256(const sha256&&) = delete;

    sha256& operator=(sha256&&) = delete;

private:

    constexpr static inline std::array<u32, BLOCK_SIZE> k {
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

    /**
     * convert the result of sha256::hash to hex
     *
     * @param in input string
     * @return string converted to hex
     */
    static std::string to_hex(const std::string& in) {
        std::stringstream ss;

        ss << std::hex << std::setfill('0');
        for (auto c : in)
            ss << std::setw(2) << static_cast<unsigned int>(static_cast<unsigned char>(c));

        return ss.str();
    }

    static std::string hash_to_string(const std::array<u32, 8>& hash) {
        std::string hash_str;
        hash_str.reserve(257);
        for (auto i : hash)
            hash_str += value_to_bytes(i);
        return hash_str;
    }

    template<typename T>
    inline static std::string value_to_bytes(const T value) {
        std::string result;
        for (int i = sizeof(value) - 1; i >= 0; --i)
            result.push_back(static_cast<u8>(value >> (i * 8)));
        return result;
    }

    inline static std::string pad(const std::string& message) {
        std::string result = message;
        const u64 msg_len = message.size();
        auto num_zero_bytes = 56 - ((msg_len + 1) % BLOCK_SIZE);
        result.append(1, '\x80');
        result.append(num_zero_bytes, 0);
        result.append(value_to_bytes(msg_len * 8));
        return result;
    }

    inline static u32 R(const u32 x, const u32 n) {
        return x >> n;
    }

    inline static u32 S(const u32 x, const u32 n) {
        return (x >> n) | (x << (32 - n));
    }

    inline static u32 ch(const u32 x, const u32 y, const u32 z) {
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

    static void hash_block(const std::string& message_, std::array<u32, 8>& hash_, u32 block_num) {
        auto block_start = block_num * BLOCK_SIZE;
        u32 w[BLOCK_SIZE];
        for (auto i = 0; i < BLOCK_SIZE; i += 4)
            w[i / 4] = (static_cast<u8>(message_[block_start + i])) << 24 |
                       (static_cast<u8>(message_[block_start + i + 1]) << 16) |
                       (static_cast<u8>(message_[block_start + i + 2]) << 8) |
                       static_cast<u8>((message_[block_start + i + 3]));

        for (auto t = 16; t < BLOCK_SIZE; ++t)
            w[t] = lsig1(w[t - 2]) + w[t - 7] + lsig0(w[t - 15]) + w[t - 16];

        u32 a = hash_[0];
        u32 b = hash_[1];
        u32 c = hash_[2];
        u32 d = hash_[3];
        u32 e = hash_[4];
        u32 f = hash_[5];
        u32 g = hash_[6];
        u32 h = hash_[7];

        for (auto j = 0; j < BLOCK_SIZE; ++j) {
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