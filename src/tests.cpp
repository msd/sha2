#include <catch2/catch_test_macros.hpp>

#include "utils.hpp"

TEST_CASE ( "block count is correct", "[block_count]" )
{
    REQUIRE ( block_count(447) == 1 );
    REQUIRE ( block_count(448) == 2 );
    REQUIRE ( block_count(511) == 2 );
    REQUIRE ( block_count(512) == 2 );
    REQUIRE ( block_count(513) == 2 );
    REQUIRE ( block_count(512 + 447) == 2 );
    REQUIRE ( block_count(512 + 448) == 3 );
    REQUIRE ( block_count(2 * 512) == 3 );
}

TEST_CASE ( "conversion of integer types to big endian", "[to_big_endian_array][big_endian][endian]" )
{
    SECTION ( "convert 2 byte int", "converting 0x3412 to big endian")
    {
        uint16_t x = 0x1234u;
        array<byte,2> expected = {byte{0x12}, byte{0x34}};
        array<byte,2> got = to_big_endian_array(x);
        REQUIRE ( expected == got );
    }

    SECTION ( "convert 4 byte int", "converting 0x78563412 to big endian")
    {
        uint32_t x = 0x12345678;
        array<byte,4> expected = {byte{0x12}, byte{0x34}, byte{0x56}, byte{0x78}};
        array<byte,4> got = to_big_endian_array(x);
        REQUIRE ( expected == got );
    }

    SECTION ( "convert 8 byte int", "converting 0xf0debc9a78563412 to big endian")
    {
        uint64_t x = 0x123456789abcdef0ull;
        array<byte,8> expected = {
            byte{0x12}, byte{0x34}, byte{0x56}, byte{0x78},
            byte{0x9a}, byte{0xbc}, byte{0xde}, byte{0xf0}
        };
        array<byte,8> got = to_big_endian_array(x);
        REQUIRE ( expected == got );
    }
}
TEST_CASE ( "conversion of integer types to little endian", "[to_little_endian_array][little_endian][endian]")
{
    SECTION ("convert 2 byte integer" "converting 0x3412 to little endian" )
    {
        uint16_t x = 0x3412u;
        array<byte,2> expected = {byte{0x12}, byte{0x34}};
        array<byte,2> got = to_little_endian_array(x);
        REQUIRE (expected == got);
    }

    SECTION ("convert 4 byte integer" "converting 0x78563412 to little endian" )
    {
        
        uint32_t x = 0x78563412;
        array<byte,4> expected = {byte{0x12}, byte{0x34}, byte{0x56}, byte{0x78}};
        array<byte,4> got = to_little_endian_array(x);
        REQUIRE (expected == got);
    }

    SECTION ("convert 8 byte integer" "converting 0xf0debc9a78563412 to little endian" )
    {
        uint64_t x = 0xf0debc9a78563412ull;
        array<byte,8> expected = {
            byte{0x12}, byte{0x34}, byte{0x56}, byte{0x78},
            byte{0x9a}, byte{0xbc}, byte{0xde}, byte{0xf0}
        };
        array<byte,8> got = to_little_endian_array(x);
        REQUIRE (expected == got);
    }
}

TEST_CASE ( "conversion of little endian bytes to integer types", "[from_little_endian_array][little_endian][endian]")
{
    SECTION ( "convert  little endian bytes to integer type", "converting bytes from little endian to 0x3412")
    {
        array<byte,2> x = {byte{0x12}, byte{0x34}};
        uint16_t expected = 0x3412u;
        auto got = from_little_endian_array<uint16_t>(x);
        REQUIRE (expected == got);
    }

    SECTION ( "convert  little endian bytes to integer type", "converting bytes from little endian to 0x78563412")
    {
        array<byte,4> x = {byte{0x12}, byte{0x34}, byte{0x56}, byte{0x78}};
        uint32_t expected = 0x78563412;
        auto got = from_little_endian_array<uint32_t>(x);
        REQUIRE (expected == got);
    }

    SECTION ( "convert  little endian bytes to integer type", "converting bytes from little endian to 0xf0debc9a78563412")
    {
        array<byte,8> x = {
            byte{0x12}, byte{0x34}, byte{0x56}, byte{0x78},
            byte{0x9a}, byte{0xbc}, byte{0xde}, byte{0xf0}
        };
        uint64_t expected = 0xf0debc9a78563412ull;
        auto got = from_little_endian_array<uint64_t>(x);
        REQUIRE (expected == got);
    }
}

TEST_CASE ( "conversion of big endian bytes to integer types", "[from_big_endian_array][big_endian][endian]")
{
    SECTION ( "convert  big endian bytes to integer type", "converting bytes from little endian to 0x3412")
    {
        array<byte,2> x = {byte{0x12}, byte{0x34}};
        uint16_t expected = 0x1234u;
        auto got = from_big_endian_array<uint16_t>(x);
        REQUIRE (expected == got);
    }

    SECTION ( "convert  big endian bytes to integer type", "converting bytes from little endian to 0x78563412")
    {
        array<byte,4> x = {byte{0x12}, byte{0x34}, byte{0x56}, byte{0x78}};
        uint32_t expected = 0x12345678;
        auto got = from_big_endian_array<uint32_t>(x);
        REQUIRE (expected == got);
    }

    SECTION ( "convert  big endian bytes to integer type", "converting bytes from little endian to 0xf0debc9a78563412")
    {
        array<byte,8> x = {
            byte{0x12}, byte{0x34}, byte{0x56}, byte{0x78},
            byte{0x9a}, byte{0xbc}, byte{0xde}, byte{0xf0}
        };
        uint64_t expected = 0x123456789abcdef0ull;
        auto got = from_big_endian_array<uint64_t>(x);
        REQUIRE (expected == got);
    }
}

TEST_CASE ( "many from big endian" )
{
    array<byte, 8> x{byte{0x12}, byte{0x34}, byte{0x56}, byte{0x78}, byte{0x9a}, byte{0xbc}, byte{0xde}, byte{0xf0}};
    SECTION ( "4 16-bit integers" )
    {
        array<uint16_t, 4> expected = { 0x1234u, 0x5678u, 0x9abcu, 0xdef0u};
        array<uint16_t, 4> got;
        many_from_big_endian<uint16_t>(begin(x), end(x), got.data());
        REQUIRE ( expected == got );
    }
    SECTION ( "2 32-bit integers" )
    {
        array<uint32_t, 2> expected = { 0x12345678u, 0x9abcdef0u};
        array<uint32_t, 2> got;
        many_from_big_endian<uint32_t>(begin(x), end(x), got.data());
        REQUIRE ( expected == got );
    }
}

TEST_CASE ( "many from little endian" )
{
    array<byte, 8> x{byte{0x12}, byte{0x34}, byte{0x56}, byte{0x78}, byte{0x9a}, byte{0xbc}, byte{0xde}, byte{0xf0}};
    SECTION ( "4 16-bit integers" )
    {
        array<uint16_t, 4> expected = { 0x3412u, 0x7856u, 0xbc9au, 0xf0deu};
        array<uint16_t, 4> got;
        many_from_little_endian<uint16_t>(begin(x), end(x), got.data());
        REQUIRE ( expected == got );
    }
    SECTION ( "2 32-bit integers" )
    {
        array<uint32_t, 2> expected = { 0x78563412u, 0xf0debc9au};
        array<uint32_t, 2> got;
        many_from_little_endian<uint32_t>(begin(x), end(x), got.data());
        REQUIRE ( expected == got );
    }
}
