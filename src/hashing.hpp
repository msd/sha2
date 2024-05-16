#ifndef C3F8C015_E7B0_4543_AB0C_6D83AD5DF3C2
#define C3F8C015_E7B0_4543_AB0C_6D83AD5DF3C2

#include "extended_int.hpp"
#include <bit>
#include <climits>
#include <concepts>
#include <cstdint>
#include <iterator>
#include <ranges>
#include <span>

#include <msd_utils/endian_containers.hpp>

template <std::integral Integer = int> Integer const constexpr SHA256_DIGEST_LEN = 32;
template <std::integral Integer = int> Integer const constexpr SHA384_DIGEST_LEN = 48;
template <std::integral Integer = int> Integer const constexpr SHA512_DIGEST_LEN = 64;

namespace steve::algorithms
{
    namespace sha2_details
    {
        namespace impl
        {
            template <typename Details>
            concept basic_sha_details_impl = requires {
                // the number of bytes that the resulting digest is
                { Details::digest_length } -> std::convertible_to<size_t>;
                // the number of iterations the compression function is ran for
                { Details::compress_iterations } -> std::convertible_to<size_t>;
                // the unit data type that the algorithm is run on
                typename Details::unit;
                typename Details::padding_tail_type;
                { Details::state_size } -> std::convertible_to<size_t>;
            };

            // TODO sha224 SHA512/224 SHA512/256

            struct basic_sha256
            {
                static size_t const constexpr digest_length = 32;
                static size_t const constexpr state_size = 32;
                static size_t const constexpr compress_iterations = 64;
                using unit = uint32_t;
                using padding_tail_type = uint64_t;
            };

            struct basic_sha384
            {
                static size_t const constexpr digest_length = 48;
                static size_t const constexpr state_size = 64;
                static size_t const constexpr compress_iterations = 80;
                using unit = uint64_t;
                using padding_tail_type = integer::uint128_t;
                static std::tuple<size_t, size_t> const constexpr skip{0, 16};
            };

            struct basic_sha512
            {
                static size_t const constexpr digest_length = 64;
                static size_t const constexpr state_size = 64;
                static size_t const constexpr compress_iterations = 80;
                using unit = uint64_t;
                using padding_tail_type = integer::uint128_t;
            };

            template <basic_sha_details_impl ShaDetails> struct ShaDetailsComplete_aux
            {
                static auto const constexpr digest_length = ShaDetails::digest_length;
                static auto const constexpr compress_iterations = ShaDetails::compress_iterations;
                // cipher state size, intermediate hash value. In bytes
                static auto const constexpr state_size = ShaDetails::state_size;
                using unit = ShaDetails::unit;
                using padding_tail_type = ShaDetails::padding_tail_type;

                using compression_constants = std::array<unit, compress_iterations>;

                using digest_t = std::array<std::byte, digest_length>;

                // size of each message block in bytes
                static size_t const constexpr BLOCK_SIZE = state_size * 2;

                // how many units fit in a message block
                static size_t const constexpr UNITS_PER_BLOCK = BLOCK_SIZE / sizeof(unit);
                // the message block made of units
                using block_t = std::array<unit, UNITS_PER_BLOCK>;
                // the message block made of bytes
                using byte_block_t = std::array<std::byte, BLOCK_SIZE>;

                static size_t const constexpr STATE_UNIT_SIZE = state_size / sizeof(unit);

                using state_t = std::array<unit, STATE_UNIT_SIZE>;
            };

            template <basic_sha_details_impl ShaDetails> struct ShaDetailsComplete;
            template <basic_sha_details_impl ShaDetails>
            struct ShaDetailsComplete : ShaDetailsComplete_aux<ShaDetails>
            {
                static_assert(ShaDetails::state_size == ShaDetails::digest_length,
                              "you must define skip tuple in details struct to specify which bytes "
                              "need to be skipped, because state size and tuple length differ");
                static std::tuple<size_t, size_t> const constexpr skip{0, 0};
            };

            template <basic_sha_details_impl ShaDetails>
                requires requires {
                    { ShaDetails::skip } -> std::convertible_to<std::tuple<size_t, size_t>>;
                }
            struct ShaDetailsComplete<ShaDetails> : ShaDetailsComplete_aux<ShaDetails>
            {
                static auto const constexpr skip = ShaDetails::skip;
                static_assert(std::get<0>(skip) + std::get<1>(skip) + ShaDetails::digest_length ==
                              ShaDetails::state_size);
            };

            using sha256_details = ShaDetailsComplete<basic_sha256>;
            using sha384_details = ShaDetailsComplete<basic_sha384>;
            using sha512_details = ShaDetailsComplete<basic_sha512>;
        } // namespace impl

        using sha256_details = impl::sha256_details;
        using sha384_details = impl::sha384_details;
        using sha512_details = impl::sha512_details;

    } // namespace sha2_details

    namespace sha256
    {
        using details = sha2_details::sha256_details;
        using digest_t = details::digest_t;

        // initial state for SHA-224
        details::state_t const constexpr H_init_244{
            0xc1059ed8, 0x367cd507, 0x3070dd17, 0xf70e5939,
            0xffc00b31, 0x68581511, 0x64f98fa7, 0xbefa4fa4,
        };

        // initial state for SHA-256
        // (which are obtained by taking the fractional parts of the square roots of the first eight
        // primes)
        details::state_t const constexpr H_init_256{
            0x6a09e667, 0xbb67ae85, 0x3c6ef372, 0xa54ff53a,
            0x510e527f, 0x9b05688c, 0x1f83d9ab, 0x5be0cd19,
        };

        namespace aux
        {
            using std::rotr;
            using unit = details::unit;
            unit constexpr CH(unit x, unit y, unit z) { return (x & y) ^ ((~x) & z); }
            unit constexpr MAJ(unit x, unit y, unit z) { return (x & y) ^ (x & z) ^ (y & z); }
            unit constexpr BSIG0(unit x) { return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22); }
            unit constexpr BSIG1(unit x) { return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25); }
            unit constexpr SSIG0(unit x) { return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3); }
            unit constexpr SSIG1(unit x) { return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10); }
        } // namespace aux

        /**
         * @brief Return expanded message block based on the message block
         * The first 16 units are copied directly from the message using big endian encoding
         * and the remaining 48 units are derived from the former.
         * @param byte_block the message block bytes
         * @return the extended message block
         */
        [[nodiscard]] auto constexpr expanded_message_block(details::byte_block_t byte_block)
        {
            details::compression_constants W{};

            // copy the first 16 units from the message block
            msd::utils::endian::ranges::many_from_big_endian<details::unit>(byte_block, W.begin());

            // derive the 48 remaining units
            using namespace aux;
            for (auto t : std::ranges::views::iota(16ull, W.size()))
            {
                W[t] = SSIG1(W[t - 2]) + W[t - 7] + SSIG0(W[t - 15]) + W[t - 16];
            }

            return W;
        }

        /*
         * (These are the first thirty-two bits of the fractional parts of the cube roots of the
         * first sixty-four primes)
         */
        details::compression_constants const constexpr K_WORDS{

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

            0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2,
        };

        // process a block of bytes and returns the next intermediate hash value (H).
        // This is the compress function combined with the accumulation.
        [[nodiscard]] auto next_state(details::state_t const &state,
                                      details::byte_block_t const &byte_block)
        {
            auto const W = expanded_message_block(byte_block);

            using namespace aux;
            auto next_hash_value = state;
            auto &[a, b, c, d, e, f, g, h] = next_hash_value;

            auto const w_end = std::end(W);
            auto const k_end = std::end(K_WORDS);

            for (auto w = W.cbegin(), k = K_WORDS.cbegin(); w != w_end && k != k_end; ++k, ++w)
            {
                unit const T1 = h + BSIG1(e) + CH(e, f, g) + *k + *w;
                unit const T2 = BSIG0(a) + MAJ(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + T1;
                d = c;
                c = b;
                b = a;
                a = T1 + T2;
            }

            for (size_t i :
                 std::ranges::views::iota(0ull, std::min(state.size(), next_hash_value.size())))
            {
                next_hash_value[i] += state[i];
            }
            return next_hash_value;
        }
    } // namespace sha256

    namespace sha512
    {
        using details = sha2_details::sha512_details;
        using digest_t = details::digest_t;

        details::state_t const constexpr H_init_512{
            0x6a09e667f3bcc908, 0xbb67ae8584caa73b, 0x3c6ef372fe94f82b, 0xa54ff53a5f1d36f1,
            0x510e527fade682d1, 0x9b05688c2b3e6c1f, 0x1f83d9abfb41bd6b, 0x5be0cd19137e2179,
        };

        details::compression_constants const constexpr K_WORDS = {
            0x428a2f98d728ae22, 0x7137449123ef65cd, 0xb5c0fbcfec4d3b2f, 0xe9b5dba58189dbbc,
            0x3956c25bf348b538, 0x59f111f1b605d019, 0x923f82a4af194f9b, 0xab1c5ed5da6d8118,
            0xd807aa98a3030242, 0x12835b0145706fbe, 0x243185be4ee4b28c, 0x550c7dc3d5ffb4e2,
            0x72be5d74f27b896f, 0x80deb1fe3b1696b1, 0x9bdc06a725c71235, 0xc19bf174cf692694,
            0xe49b69c19ef14ad2, 0xefbe4786384f25e3, 0x0fc19dc68b8cd5b5, 0x240ca1cc77ac9c65,
            0x2de92c6f592b0275, 0x4a7484aa6ea6e483, 0x5cb0a9dcbd41fbd4, 0x76f988da831153b5,
            0x983e5152ee66dfab, 0xa831c66d2db43210, 0xb00327c898fb213f, 0xbf597fc7beef0ee4,
            0xc6e00bf33da88fc2, 0xd5a79147930aa725, 0x06ca6351e003826f, 0x142929670a0e6e70,
            0x27b70a8546d22ffc, 0x2e1b21385c26c926, 0x4d2c6dfc5ac42aed, 0x53380d139d95b3df,
            0x650a73548baf63de, 0x766a0abb3c77b2a8, 0x81c2c92e47edaee6, 0x92722c851482353b,
            0xa2bfe8a14cf10364, 0xa81a664bbc423001, 0xc24b8b70d0f89791, 0xc76c51a30654be30,
            0xd192e819d6ef5218, 0xd69906245565a910, 0xf40e35855771202a, 0x106aa07032bbd1b8,
            0x19a4c116b8d2d0c8, 0x1e376c085141ab53, 0x2748774cdf8eeb99, 0x34b0bcb5e19b48a8,
            0x391c0cb3c5c95a63, 0x4ed8aa4ae3418acb, 0x5b9cca4f7763e373, 0x682e6ff3d6b2b8a3,
            0x748f82ee5defb2fc, 0x78a5636f43172f60, 0x84c87814a1f0ab72, 0x8cc702081a6439ec,
            0x90befffa23631e28, 0xa4506cebde82bde9, 0xbef9a3f7b2c67915, 0xc67178f2e372532b,
            0xca273eceea26619c, 0xd186b8c721c0c207, 0xeada7dd6cde0eb1e, 0xf57d4f7fee6ed178,
            0x06f067aa72176fba, 0x0a637dc5a2c898a6, 0x113f9804bef90dae, 0x1b710b35131c471b,
            0x28db77f523047d84, 0x32caab7b40c72493, 0x3c9ebe0a15c9bebc, 0x431d67c49c100d4c,
            0x4cc5d4becb3e42b6, 0x597f299cfc657e2a, 0x5fcb6fab3ad6faec, 0x6c44198c4a475817,
        };

        namespace aux
        {
            using std::rotr;
            using unit = details::unit;
            unit constexpr CH(unit x, unit y, unit z) { return (x & y) ^ (~x & z); }
            unit constexpr MAJ(unit x, unit y, unit z) { return (x & y) ^ (x & z) ^ (y & z); }
            unit constexpr BSIG0(unit x) { return rotr(x, 28) ^ rotr(x, 34) ^ rotr(x, 39); }
            unit constexpr BSIG1(unit x) { return rotr(x, 14) ^ rotr(x, 18) ^ rotr(x, 41); }
            unit constexpr SSIG0(unit x) { return rotr(x, 1) ^ rotr(x, 8) ^ (x >> 7); }
            unit constexpr SSIG1(unit x) { return rotr(x, 19) ^ rotr(x, 61) ^ (x >> 6); }
        } // namespace aux

        [[nodiscard]] auto constexpr expanded_message_block(details::byte_block_t const &byte_block)
        {
            using namespace aux;

            details::compression_constants W{};

            msd::utils::endian::ranges::many_from_big_endian<unit>(byte_block, W.begin());

            for (auto j : std::ranges::views::iota(16ull, W.size()))
            {
                W[j] = SSIG1(W[j - 2]) + W[j - 7] + SSIG0(W[j - 15]) + W[j - 16];
            }

            return W;
        }

        // process a block of bytes and returns the next intermediate hash value (H).
        // This is the compress function combined with the accumulation.
        [[nodiscard]] auto next_state(details::state_t const &state,
                                      details::byte_block_t const &byte_block)
        {
            auto const W = expanded_message_block(byte_block);

            using namespace aux;
            auto next_hash_value = state;
            auto &[a, b, c, d, e, f, g, h] = next_hash_value;

            auto const w_end = std::end(W);
            auto const k_end = std::end(K_WORDS);

            for (auto w = W.cbegin(), k = K_WORDS.cbegin(); w != w_end && k != k_end; ++k, ++w)
            {
                unit const T1 = h + BSIG1(e) + CH(e, f, g) + *k + *w;
                unit const T2 = BSIG0(a) + MAJ(a, b, c);
                h = g;
                g = f;
                f = e;
                e = d + T1;
                d = c;
                c = b;
                b = a;
                a = T1 + T2;
            }

            for (size_t i :
                 std::ranges::views::iota(0ull, std::min(state.size(), next_hash_value.size())))
            {
                next_hash_value[i] += state[i];
            }
            return next_hash_value;
        }
    } // namespace sha512

    namespace sha384
    {
        using details = sha2_details::sha384_details;
        details::state_t const constexpr H_init = {
            0xcbbb9d5dc1059ed8, 0x629a292a367cd507, 0x9159015a3070dd17, 0x152fecd8f70e5939,
            0x67332667ffc00b31, 0x8eb44a8768581511, 0xdb0c2e0d64f98fa7, 0x47b5481dbefa4fa4,
        };
        using digest_t = details::digest_t;

        auto const constexpr x = details::state_t{};
    } // namespace sha384

    namespace sha2_algo
    {
        namespace impl
        {
            template <typename Details>
            concept details_complete = requires {
                typename Details::unit;
                typename Details::state_t;
                Details::compress_iterations;
                { Details::skip } -> std::convertible_to<std::tuple<size_t, size_t>>;
            };

            template <typename Algorithm>
            concept algorithm_specification = requires {
                typename Algorithm::details;
                requires details_complete<typename Algorithm::details>;
                {
                    Algorithm::initial_state
                } -> std::convertible_to<typename Algorithm::details::state_t>;
                { Algorithm::next_state };
                requires requires(typename Algorithm::details::state_t const &state,
                                  typename Algorithm::details::byte_block_t const &byte_block) {
                    {
                        Algorithm::next_state(state, byte_block)
                    } -> std::same_as<typename Algorithm::details::state_t>;
                };
            };

            struct sha256_spec
            {
                using details = sha256::details;
                static auto const constexpr initial_state = sha256::H_init_256;
                static auto const constexpr next_state = sha256::next_state;
            };

            struct sha384_spec
            {
                using details = sha384::details;
                static auto const constexpr initial_state = sha384::H_init;
                static auto const constexpr next_state = sha512::next_state;
            };

            struct sha512_spec
            {
                using details = sha512::details;
                static auto const constexpr initial_state = sha512::H_init_512;
                static auto const constexpr next_state = sha512::next_state;
            };

            template <algorithm_specification AlgoSpec> struct Algorithm
            {
                using byte_block_t = AlgoSpec::details::byte_block_t;
                using state_t = AlgoSpec::details::state_t;
                using padding_tail_type = AlgoSpec::details::padding_tail_type;
                using digest_t = AlgoSpec::details::digest_t;
                static auto const constexpr next_state = AlgoSpec::next_state;
                byte_block_t buffer{};
                byte_block_t::iterator buffer_pos{buffer.begin()};
                state_t state{AlgoSpec::initial_state};
                padding_tail_type message_size{0}; // in bytes
                [[nodiscard]] auto buffer_remaining() const
                {
                    return std::distance(static_cast<byte_block_t::const_iterator>(buffer_pos),
                                         buffer.cend());
                }

                void update(std::span<std::byte const> const &data)
                {
                    auto data_pos = data.cbegin();
                    auto const data_end = data.cend();
                    message_size += data.size();

                    auto const data_remaining = [&]() { return std::distance(data_pos, data_end); };

                    while (data_remaining() > 0)
                    {
                        auto const data_fits = std::min(buffer_remaining(), data_remaining());
                        if (data_fits != 0)
                        {
                            auto data_pos_next = std::next(data_pos, data_fits);
                            std::copy(data_pos, data_pos_next, buffer_pos);
                            std::advance(buffer_pos, data_fits);
                            data_pos = data_pos_next;
                        }
                        if (buffer_remaining() == 0)
                        {
                            process_block();
                        }
                    }
                }

                /**
                 * @brief
                 * handle a full buffer, any padding must be done before
                 * calling this function. Changes the current state (intermediate hash value)
                 * and reset the buffer_pos to the start of the buffer. the contents of the buffer
                 * remain unchanged.
                 */
                void process_block()
                {
                    state = next_state(state, buffer);
                    buffer_pos = buffer.begin();
                }

                [[nodiscard]] auto digest_aux() const
                {
                    // message size in bits, same as multiplication by CHAR_BIT (8)
                    auto const message_size_bits = message_size << 3;
                    if (buffer_remaining() >= static_cast<ssize_t>(sizeof(padding_tail_type) + 1))
                    {
                        auto tmp_buffer = buffer;
                        auto tmp_pos = std::next(
                            tmp_buffer.begin(),
                            std::distance(buffer.cbegin(),
                                          static_cast<byte_block_t::const_iterator>(buffer_pos)));

                        // begin padding
                        *(tmp_pos++) = std::byte{0x80};
                        // pad remaining zeros
                        auto padding_tail_begin =
                            std::prev(tmp_buffer.end(), sizeof(padding_tail_type));
                        if (std::distance(tmp_pos, padding_tail_begin) > 0)
                        {
                            std::fill(tmp_pos, padding_tail_begin, std::byte{0});
                        }
                        // add padding tail (size of message mod 2^64)

                        msd::utils::endian::to_big_endian(message_size_bits, padding_tail_begin);

                        return next_state(state, tmp_buffer);
                    }

                    auto tmp_buffer = buffer;
                    auto tmp_pos = std::next(
                        tmp_buffer.begin(),
                        std::distance(buffer.cbegin(),
                                      static_cast<byte_block_t::const_iterator>(buffer_pos)));

                    // begin padding
                    *(tmp_pos++) = std::byte{0x80};
                    // pad the rest of the block with zeros
                    std::fill(tmp_pos, tmp_buffer.end(), std::byte{0});
                    auto const tmp_state = next_state(state, tmp_buffer);

                    byte_block_t final_block{};
                    auto padding_tail_begin =
                        std::prev(final_block.end(), sizeof(padding_tail_type));
                    // todo is this necessary?
                    std::fill(final_block.begin(), padding_tail_begin, std::byte{0});
                    // add padding tail (size of message mod 2^64)
                    msd::utils::endian::to_big_endian(message_size_bits, padding_tail_begin);

                    return next_state(tmp_state, final_block);
                }

                [[nodiscard]] auto digest() const
                {
                    auto const final_state = digest_aux();
                    std::array<std::byte, AlgoSpec::details::state_size> state_bytes;
                    msd::utils::endian::ranges::many_to_big_endian(final_state,
                                                                   state_bytes.begin());

                    auto digest_beg = std::cbegin(state_bytes);
                    if constexpr (std::get<0>(AlgoSpec::details::skip) != 0)
                    {
                        std::advance(digest_beg, std::get<0>(AlgoSpec::details::skip));
                    }
                    auto digest_end = std::cend(state_bytes);
                    if constexpr (std::get<1>(AlgoSpec::details::skip) != 0)
                    {
                        std::advance(digest_end, -std::get<1>(AlgoSpec::details::skip));
                    }

                    digest_t digest_value{};
                    std::copy(digest_beg, digest_end, digest_value.begin());
                    return digest_value;
                }
            };

            using sha256_algo = Algorithm<sha256_spec>;
            using sha384_algo = Algorithm<sha384_spec>;
            using sha512_algo = Algorithm<sha512_spec>;
        } // namespace impl

        using sha256_algo = impl::sha256_algo;
        using sha384_algo = impl::sha384_algo;
        using sha512_algo = impl::sha512_algo;
    } // namespace sha2_algo

    namespace sha256
    {
        using hash = sha2_algo::sha256_algo;
    } // namespace sha256

    namespace sha384
    {
        using hash = sha2_algo::sha384_algo;
    } // namespace sha384

    namespace sha512
    {
        using hash = sha2_algo::sha512_algo;
    } // namespace sha512

} // namespace steve::algorithms

#endif /* C3F8C015_E7B0_4543_AB0C_6D83AD5DF3C2 */
