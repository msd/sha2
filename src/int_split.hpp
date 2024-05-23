#ifndef B762950C_62D3_4019_BF02_F68C09913190
#define B762950C_62D3_4019_BF02_F68C09913190

#include <climits>
#include <concepts>
#include <cstddef>
#include <ranges>

template <size_t UnitIndex, std::integral Unit = std::byte, std::integral Value>
    requires(sizeof(Unit) <= sizeof(Value) && sizeof(Value) % sizeof(Unit) == 0 &&
             UnitIndex < (sizeof(Value) / sizeof(Unit)))
auto constexpr split_int(Value x)
{
    static auto const constexpr bit_count = sizeof(Unit) * CHAR_BIT;
    static Value const constexpr single_unit_mask = (static_cast<Value>(1) << bit_count) - 1;
    static size_t const constexpr shift = UnitIndex * bit_count;
    Value const single_unit = (x >> shift) & single_unit_mask;
    return static_cast<Unit>(single_unit);
}

template <std::integral Unit = std::byte, std::integral Value>
    requires(sizeof(Unit) <= sizeof(Value) && sizeof(Value) % sizeof(Unit) == 0)
auto constexpr split_int_rt(Value x, size_t i)
{
    static auto const constexpr bit_count = sizeof(Unit) * CHAR_BIT;
    static Value const constexpr single_unit_mask = (static_cast<Value>(1) << bit_count) - 1;
    size_t const shift = i * bit_count;
    auto const single_unit = (x >> shift) & single_unit_mask;
    return static_cast<Unit>(single_unit);
}

namespace views
{
    template <typename Unit, typename Value>
        requires(sizeof(Unit) <= sizeof(Value) && sizeof(Value) % sizeof(Unit) == 0)
    auto constexpr low_first(Value val)
    {
        static auto const constexpr count = sizeof(Value) / sizeof(Unit);
        using namespace std::ranges::views;
        return iota(0ull, count) |
               transform([val](size_t i) { return split_int_rt<Unit>(val, i); });
    }

    template <typename Unit, typename Value>
        requires(sizeof(Unit) <= sizeof(Value) && sizeof(Value) % sizeof(Unit) == 0)
    auto constexpr high_first(Value val)
    {
        static auto const constexpr count = sizeof(Value) / sizeof(Unit);
        using namespace std::ranges::views;
        return iota(0ull, count) |
               transform([val](size_t i) { return split_int_rt<Unit>(val, count - 1 - i); });
    }
} // namespace views

#endif /* B762950C_62D3_4019_BF02_F68C09913190 */
