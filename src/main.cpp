#include <exception>
#include <filesystem>
#include <ios>
#include <iostream>
#include <ranges>
#include <stdexcept>
#include <string_view>

#include <msd_utils/endian.hpp>

#include "hashing.hpp"
#include "utils.hpp"

namespace fs = std::filesystem;

/*
 * SHA224("")
 * 0x d14a028c2a3a2bc9476102bb288234c415a2b01f828ea62ac5b3e42f
 * SHA256("")
 * 0x e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855
 * SHA384("")
 * 0x
 * 38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da274edebfe76f65fbd51ad2f14898b95b
 * SHA512("")
 * 0x
 * cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce47d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e
 * SHA512/224("")
 * 0x 6ed0dd02806fa89e25de060c19d3ac86cabb87d6a0ddd05c333b84f4
 * SHA512/256("")
 * 0x c672b8d1ef56ed28ab87c3622c5114069bdd3ad7b8f9737498d0c01ecef0967a
 */

struct multi_hash_result
{
    std::vector<std::byte> data{};
    steve::algorithms::sha256::digest_t sha_256{};

    [[nodiscard]] std::string sha_256_string(unsigned split = 0) const
    {
        return steve::bits::many_bytes_to_hex(sha_256, split);
    }

    [[nodiscard]] std::string sha_512_string(unsigned split = 0) const
    {
        // FIXME
        throw std::runtime_error("not implemented sha512_string");
        return steve::bits::many_bytes_to_hex(std::ranges::views::empty<std::byte>, split);
    }
};

multi_hash_result multi_hash(std::vector<std::byte> data)
{
    multi_hash_result results;

    results.sha_256 = steve::algorithms::sha256_old::hash_sha256(data);
    // TODO add the rest of the results

    return results;
}

void test_suite()
{
    auto empty = multi_hash({});

    std::cout << std::boolalpha;

    // data = "" (empty)
    std::cout << (steve::bits::many_bytes_to_hex(empty.sha_256) == "");
    std::cout << std::noboolalpha;
}

int main_throw(std::vector<std::string_view> args)
{
    using namespace steve::bits;
    using namespace steve::algorithms;

    if (args.size() < 2)
    {
        std::cerr << "Error: No file given" << std::endl;
        return 1;
    }
    std::string_view file_path{args[1]};
    if (!fs::exists(file_path))
    {
        std::cerr << "Error: File does not exist" << std::endl;
        return 1;
    }
    std::cout << "File Size: " << fs::file_size(file_path) << std::endl;
    auto message = read_file_bytes(std::string{file_path});

    std::cout << many_bytes_to_hex(sha256_old::hash_sha256(message), 4) << std::endl;

    return 0;
}

static auto parse_args(int argc, char **argv)
{
    if (argv == nullptr || argc < 0)
    {
        return std::vector<std::string_view>{};
    }

    std::vector<std::string_view> args{};

    for (int i = 0; i < argc; ++i)
    {
        char *str = argv[i]; /* NOLINT(*pointer*) */
        if (str != nullptr)
        {
            args.emplace_back(str);
        }
    }

    return args;
}

int main(int argc, char **argv)
{
    try
    {
        return main_throw(parse_args(argc, argv));
    }
    catch (std::exception const &ex)
    {
        std::cout << "ERROR: " << ex.what() << std::endl;
    }
    return -1;
}
