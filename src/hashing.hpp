#ifndef C3F8C015_E7B0_4543_AB0C_6D83AD5DF3C2
#define C3F8C015_E7B0_4543_AB0C_6D83AD5DF3C2

#include <array>
#include <bit>
#include <cstdint>
#include <iostream>
#include <vector>

namespace steve::defs
{
    using std::array;
    using std::byte;

    /* sha-244 & 256 */
    constexpr size_t BLOCK_SIZE_BYTES = 64;
    constexpr size_t BLOCK_SIZE = BLOCK_SIZE_BYTES * 8;
    constexpr size_t BLOCK_ROLLOVER_BYTES = 56;
    constexpr size_t BLOCK_ROLLOVER = BLOCK_ROLLOVER_BYTES * 8;
    constexpr size_t WORDS_PER_BLOCK = 16;
    using block_t = array<uint32_t, WORDS_PER_BLOCK>;
    using byte_block_t = array<byte, BLOCK_SIZE_BYTES>;
}

template <std::integral Integer = int> Integer const constexpr SHA256_DIGEST_LEN = 32;
template <std::integral Integer = int> Integer const constexpr SHA384_DIGEST_LEN = 48;
template <std::integral Integer = int> Integer const constexpr SHA512_DIGEST_LEN = 64;

namespace steve::algorithms
{
    namespace sha256
    {
        template <typename I = unsigned> auto const constexpr DIGEST_LENGTH = SHA256_DIGEST_LEN<I>;
        using digest_t = std::array<std::byte, DIGEST_LENGTH<>>;
    } // namespace sha256
    namespace sha384
    {
        template <typename I = unsigned> I const constexpr DIGEST_LENGTH = SHA384_DIGEST_LEN<I>;
        using digest_t = std::array<std::byte, DIGEST_LENGTH<>>;
    } // namespace sha384
    namespace sha512
    {
        template <typename I = unsigned> auto const constexpr DIGEST_LENGTH = SHA512_DIGEST_LEN<I>;
        using digest_t = std::array<std::byte, DIGEST_LENGTH<>>;
    } // namespace sha512

} // namespace steve::algorithms

namespace steve::algorithms::sha256_old
{
    using namespace steve::defs;

    using std::byte;
    using std::cbegin;
    using std::cend;
    using std::copy;
    using std::cout;
    using std::endl;
    using std::min;
    using std::rotr;

    struct Sha256Progress;

    struct Scramble /* functions used by SHA-224 and SHA-256  */
    {
        static constexpr uint32_t CH(uint32_t x, uint32_t y, uint32_t z)
        {
            return (x & y) ^ ((~x) & z);
        }
        static constexpr uint32_t MAJ(uint32_t x, uint32_t y, uint32_t z)
        {
            return (x & y) ^ (x & z) ^ (y & z);
        }
        static constexpr uint32_t BSIG0(uint32_t x)
        {
            return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
        }
        static constexpr uint32_t BSIG1(uint32_t x)
        {
            return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
        }
        static constexpr uint32_t SSIG0(uint32_t x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
        static constexpr uint32_t SSIG1(uint32_t x)
        {
            return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
        }

        static std::array<uint32_t, 64> const constexpr K_WORDS = std::array<uint32_t, 64>{
            0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5, 0x3956c25b, 0x59f111f1, 0x923f82a4,
            0xab1c5ed5, 0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3, 0x72be5d74, 0x80deb1fe,
            0x9bdc06a7, 0xc19bf174, 0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc, 0x2de92c6f,
            0x4a7484aa, 0x5cb0a9dc, 0x76f988da, 0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
            0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967, 0x27b70a85, 0x2e1b2138, 0x4d2c6dfc,
            0x53380d13, 0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85, 0xa2bfe8a1, 0xa81a664b,
            0xc24b8b70, 0xc76c51a3, 0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070, 0x19a4c116,
            0x1e376c08, 0x2748774c, 0x34b0bcb5, 0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
            0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208, 0x90befffa, 0xa4506ceb, 0xbef9a3f7,
            0xc67178f2};

        // initial state for SHA-224
        static array<uint32_t, 8> const constexpr H_init_244 = {0xc1059ed8, 0x367cd507, 0x3070dd17,
                                                                0xf70e5939, 0xffc00b31, 0x68581511,
                                                                0x64f98fa7, 0xbefa4fa4};

        // initial state for SHA-256
        static array<uint32_t, 8> const constexpr H_init_256 = {0x6a09e667, 0xbb67ae85, 0x3c6ef372,
                                                                0xa54ff53a, 0x510e527f, 0x9b05688c,
                                                                0x1f83d9ab, 0x5be0cd19};

        static auto init_W(block_t message_block)
        {
            array<uint32_t, 64> W_WORDS;
            copy(cbegin(message_block), cbegin(message_block) + 16, begin(W_WORDS));
            for (size_t t = 16; t < 64; ++t)
            {
                W_WORDS[t] = SSIG1(W_WORDS[t - 2]) + W_WORDS[t - 7] + SSIG0(W_WORDS[t - 15]) +
                             W_WORDS[t - 16];
            }
            return W_WORDS;
        }

        static auto block_work(const Sha256Progress &prog);
        static auto block_work_functional(const Sha256Progress &prog);
    };

    struct Sha256Progress
    {
        array<uint32_t, 64> W{};
        array<uint32_t, 8> H = Scramble::H_init_256;
        void accumulate(decltype(H) working)
        {
            for (size_t i = 0; i < H.size(); i++)
            {
                H[i] += working[i];
            }
        }
        auto digest();
    };

    constexpr size_t block_count(size_t message_length_bits)
    {
        size_t div = (message_length_bits + 1) / BLOCK_SIZE;
        size_t mod = (message_length_bits + 1) % BLOCK_SIZE;
        return div + 1 + (mod > BLOCK_ROLLOVER);
    }

    byte_block_t pad_block(std::vector<byte>::const_iterator msg_beg,
                           std::vector<byte>::const_iterator msg_end, size_t msg_length);

    block_t get_message_block(const std::vector<byte> &message, int block_index);

    sha256::digest_t hash_sha256(std::vector<byte> message);
}

#endif /* C3F8C015_E7B0_4543_AB0C_6D83AD5DF3C2 */
