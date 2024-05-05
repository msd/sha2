#include <exception>
#include <filesystem>
#include <ios>
#include <iostream>
#include <span>
#include <string_view>
#include <type_traits>

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
    steve::algorithms::sha384::digest_t sha_384{};
    steve::algorithms::sha512::digest_t sha_512{};

    [[nodiscard]] std::string sha_256_string(unsigned split = 0) const
    {
        return steve::bits::many_bytes_to_hex(sha_256, split);
    }

    [[nodiscard]] std::string sha_384_string(unsigned split = 0) const
    {
        return steve::bits::many_bytes_to_hex(sha_384, split);
    }

    [[nodiscard]] std::string sha_512_string(unsigned split = 0) const
    {
        return steve::bits::many_bytes_to_hex(sha_512, split);
    }
};

template <typename... Args> auto constexpr make_array(Args... args)
{
    return std::array<std::common_type_t<Args...>, sizeof...(Args)>{args...};
}

multi_hash_result multi_hash(std::vector<std::byte> data)
{
    return multi_hash_result{.sha_256 = steve::algorithms::sha256_old::hash_sha256(data)};
}

struct expected_data
{
    std::string_view data, sha_256, sha_384, sha_512;
};

void test_suite()
{
    std::cout << "=== BEGIN TEST SUITE ===\n";

    std::cout << "\tsha256\tsha348\tsha512\n";

    static auto const constexpr expected = make_array(
        expected_data{.data = "",
                      .sha_256 = "e3b0c44298fc1c149afbf4c8996fb92427ae41e4649b934ca495991b7852b855",
                      .sha_384 = "38b060a751ac96384cd9327eb1b1e36a21fdb71114be07434c0cc7bf63f6e1da2"
                                 "74edebfe76f65fbd51ad2f14898b95b",
                      .sha_512 = "cf83e1357eefb8bdf1542850d66d8007d620e4050b5715dc83f4a921d36ce9ce4"
                                 "7d0d13c5d85f2b0ff8318d2877eec2f63b931bd47417a81a538327af927da3e"},
        expected_data{.data = "hello world",
                      .sha_256 = "b94d27b9934d3e08a52e52d7da7dabfac484efe37a5380ee9088f7ace2efcde9",
                      .sha_384 = "fdbd8e75a67f29f701a4e040385e2e23986303ea10239211af907fcbb83578b3e"
                                 "417cb71ce646efd0819dd8c088de1bd",
                      .sha_512 = "309ecc489c12d6eb4cc40f50c902f2b4d0ed77ee511a7c7a9bcd3ca86d4cd86f9"
                                 "89dd35bc5ff499670da34255b45b0cfd830e81f605dcf7dc5542e93ae9cd76f"},
        expected_data{.data = "abc",
                      .sha_256 = "ba7816bf8f01cfea414140de5dae2223b00361a396177a9cb410ff61f20015ad",
                      .sha_384 = "cb00753f45a35e8bb5a03d699ac65007272c32ab0eded1631a8b605a43ff5bed8"
                                 "086072ba1e7cc2358baeca134c825a7",
                      .sha_512 =
                          "ddaf35a193617abacc417349ae20413112e6fa4e89a97ea20a9eeee64b55d39a2192992a"
                          "274fc1a836ba3c23a3feebbd454d4423643ce80e2a9ac94fa54ca49f"});

    for (auto exp : expected)
    {
        auto exp_data_span = std::as_bytes(std::span<const char>{exp.data.data(), exp.data.size()});
        std::vector<std::byte> exp_data_vec_bytes{exp_data_span.cbegin(), exp_data_span.cend()};
        auto const got = multi_hash(exp_data_vec_bytes);

        std::cout

            << "\"" << exp.data << "\""

            << std::boolalpha

            << '\t' << (got.sha_256_string() == exp.sha_256)

            << '\t' << (got.sha_384_string() == exp.sha_384)

            << '\t' << (got.sha_512_string() == exp.sha_512)

            << '\n'

            << std::noboolalpha;
    }
    std::cout << "=== END TEST SUITE ===\n";
}

int main_throw(std::vector<std::string_view> args)
{
    test_suite();

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
