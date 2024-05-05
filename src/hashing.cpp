#include "hashing.hpp"

#include <ranges>
#include <stdexcept>

#include <msd_utils/endian.hpp>

#include "utils.hpp"

using std::to_string;

namespace steve::algorithms::sha256_old
{
    using namespace steve::bits;
    using std::byte;

    auto Scramble::block_work_functional(const Sha256Progress &prog)
    {
        // static auto const_loop = [&prog](const auto &loop_control)
        // {
        //     auto working = loop_control.first;
        //     auto &[a, b, c, d, e, f, g, h] = working;
        //     auto t = loop_control.second;
        //     uint32_t T1 = h + BSIG1(e) + CH(e, f, g) + K_WORDS[t] + prog.W[t];
        //     uint32_t T2 = BSIG0(a) + MAJ(a, b, c);
        //     h = g;
        //     g = f;
        //     f = e;
        //     e = d + T1;
        //     d = c;
        //     c = b;
        //     b = a;
        //     a = T1 + T2;
        //     return make_pair(working, t + 1);
        // };
        static auto loop = [&prog](auto loop_control)
        {
            auto &working = loop_control.first;
            auto &[a, b, c, d, e, f, g, h] = working;
            auto &t = loop_control.second;
            uint32_t T1 = h + BSIG1(e) + CH(e, f, g) + K_WORDS[t] + prog.W[t];
            uint32_t T2 = BSIG0(a) + MAJ(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
            ++t;
            return loop_control;
        };
        return iterate(loop, make_pair(prog.H, 0), 64);
    }

    auto Scramble::block_work(const Sha256Progress &prog)
    {
        auto working = prog.H;
        auto &[a, b, c, d, e, f, g, h] = working;
        for (size_t t = 0; t < 64; ++t)
        {
            uint32_t T1 = h + BSIG1(e) + CH(e, f, g) + K_WORDS[t] + prog.W[t];
            uint32_t T2 = BSIG0(a) + MAJ(a, b, c);
            h = g;
            g = f;
            f = e;
            e = d + T1;
            d = c;
            c = b;
            b = a;
            a = T1 + T2;
        }
        return working;
    }

    auto Sha256Progress::digest()
    {
        array<byte, array_byte_size_v<decltype(H)>> a;
        auto ins = a.begin();
        for (uint32_t h : H)
        {
            to_big_endian(h, ins);
            ins += sizeof h;
        }
        if (ins != a.end())
        {
            throw std::runtime_error("ASSERT-3: did not write everything when writing digest");
        }
        return a;
    }

    /*

        BYTE TO HEX

        ss.setf(stringstream::hex, stringstream::basefield);
        ss.fill('0');
        for (auto word : message_block)
        {
            for (auto b : to_big_endian_array(word))
            {
                ss.width(2);
                */

    byte_block_t pad_block(std::vector<byte>::const_iterator msg_beg,
                           std::vector<byte>::const_iterator msg_end, size_t msg_length)
    {
        auto const msg_bytes = std::distance(msg_beg, msg_end);
        byte_block_t padded_block;
        copy(msg_beg, msg_end, padded_block.data());
        if (msg_bytes < static_cast<ssize_t>(BLOCK_SIZE_BYTES)) // padding needed
        {
            padded_block[msg_bytes] = byte{0x80};
            ssize_t padded_length = msg_bytes + 1;
            ssize_t limit = padded_length > static_cast<ssize_t>(BLOCK_ROLLOVER_BYTES)
                                ? BLOCK_SIZE_BYTES
                                : BLOCK_ROLLOVER_BYTES;
            while (padded_length < limit)
            {
                padded_block[padded_length++] = byte{0};
            }
            if (padded_length == BLOCK_ROLLOVER_BYTES)
            {
                for (byte b : to_big_endian_array(msg_length))
                {
                    padded_block[padded_length++] = b;
                }
            }
            if (padded_length != BLOCK_SIZE_BYTES)
            {
                throw std::runtime_error("wtf why no bytes at end " + to_string(padded_length));
            }
        }
        return padded_block;
    }

    block_t get_message_block(const std::vector<byte> &message, int block_index)
    {
        if (static_cast<size_t>(block_index) >= block_count(message.size() * 8))
        {
            throw std::runtime_error("ASSERT-4: got block index bigger than block count");
        }

        const auto start = block_index * BLOCK_SIZE_BYTES;
        const auto bytes_after_start = message.size() - start;
        const auto block_size = min(bytes_after_start, BLOCK_SIZE_BYTES);

        auto block_beg = std::next(cbegin(message), static_cast<ssize_t>(start));
        auto block_end = std::next(block_beg, static_cast<ssize_t>(block_size));

        auto padded = pad_block(block_beg, block_end, message.size());
        if (padded.size() != 64)
        {
            throw std::runtime_error("ASSERT-2: block size should be 64 bytes");
        }

        block_t to_be_returned_block;
        many_from_big_endian<uint32_t>(cbegin(padded), cend(padded), to_be_returned_block.data());
        return to_be_returned_block;
    }

    sha256::digest_t hash_sha256(std::vector<byte> message)
    {
        Sha256Progress work;
        // Scramble::pad_block(cbegin(message));

        cout << "Block count: " << block_count(message.size() * 8) << endl;

        cout << "=== BEGIN MESSAGE ===\n";
        for (auto line : bytes_to_lines(std::ranges::views::all(message)))
        {
            cout << line << '\n';
        }
        cout << "=== END   MESSAGE ===" << endl;

        static auto const constexpr print_block = [](size_t number, block_t const &block)
        {
            cout << "=== BEGIN PADDED MESSAGE BLOCK " << to_string(number) << " ===" << endl;
            static int const constexpr per_line = 2;
            static_assert(per_line > 0);
            int i = 0;
            for (auto x : block)
            {
                ++i;
                std::cout << to_hex(x) << (i % per_line == 0 ? '\n' : ' ');
            }
            cout << "=== END PADDED MESSAGE ===" << endl;
        };

        for (size_t i = 0; i < block_count(message.size() * 8); ++i)
        {
            cout << "=== BEGIN ITERMEDIATE DIGEST ===" << endl;
            for (auto line : bytes_to_lines(work.digest()))
            {
                cout << line << endl;
            }
            cout << "=== END ITERMEDIATE DIGEST ===" << endl;
            block_t message_block = get_message_block(message, static_cast<int>(i));

            print_block(i, message_block);

            work.W = Scramble::init_W(message_block);
            auto block_result = Scramble::block_work(work);
            work.accumulate(block_result);
        }

        return work.digest();
    }

} // namespace steve::algorithms
