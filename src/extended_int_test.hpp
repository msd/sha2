#ifndef DE44FEB3_4784_4EF2_B895_029069CB574D
#define DE44FEB3_4784_4EF2_B895_029069CB574D

#include <stdexcept>
#include <string_view>

#include "extended_int.hpp"

struct assertion_failed : std::runtime_error
{
    explicit assertion_failed(std::string_view msg) : std::runtime_error{std::string{msg}} {}
};

namespace asrtion
{
    using namespace steve::integer;

    void assert_addition(uint128_t const &x, uint128_t const &y, uint128_t const &expected)
    {
        if ((x + y) <=> expected != 0)
        {
            throw assertion_failed{x.to_hex() + " + " + y.to_hex() + " does not equal to " +
                                   expected.to_hex()};
        }
    }

    void commutative(uint128_t const &x, uint128_t const &y, uint128_t const &expected)
    {
        try
        {
            assert_addition(x, y, expected);
            assert_addition(y, x, expected);
        }
        catch (assertion_failed const &)
        {
            throw assertion_failed{"Addition of x:" + x.to_hex() + " and y:" + y.to_hex() +
                                   " is not commutative (x + y is " + (x + y).to_hex() +
                                   ", y + x is " + (y + x).to_hex() + ", expected result is " +
                                   expected.to_hex() + ")"};
        }
    }
} // namespace asrtion

void test_addition_commutativity() { asrtion::commutative(0x10ull, 0x20, 0x30); }

#endif /* DE44FEB3_4784_4EF2_B895_029069CB574D */
