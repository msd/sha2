#ifndef AE26D0F3_C377_468F_BAAB_B7EAC672FAB4
#define AE26D0F3_C377_468F_BAAB_B7EAC672FAB4

#include <bit>
#include <cmath>
#include <cstdint>
#include <ranges>

#include <msd_utils/endian_containers.hpp>

#include "utils.hpp"

namespace msd::integer
{
    namespace impl
    {
        template <typename T> static auto constexpr bottom_half(T x)
        {
            static size_t const constexpr half_count = sizeof(T) * CHAR_BIT / 2;
            static T const constexpr half_mask = (static_cast<T>(1) << half_count) - 1;
            return x & half_mask;
        }

        template <typename T> static auto constexpr top_half(T x)
        {
            static size_t const constexpr half_count = sizeof(T) * CHAR_BIT / 2;
            return x >> half_count;
        }
        template <std::unsigned_integral I> struct next_up_unsigned
        {
        };

        template <> struct next_up_unsigned<uint8_t>
        {
            using type = uint16_t;
        };

        template <> struct next_up_unsigned<uint16_t>
        {
            using type = uint32_t;
        };

        template <> struct next_up_unsigned<uint32_t>
        {
            using type = uint64_t;
        };

        template <std::unsigned_integral I>
        using next_up_unsigned_t = typename next_up_unsigned<I>::type;
    } // namespace impl

    namespace unsigned_checked_operations
    {
        template <std::unsigned_integral UnsignedInt>
        [[nodiscard]] static inline UnsignedInt addition_would_overflow(UnsignedInt x,
                                                                        UnsignedInt y)
        {
            auto const constexpr max = std::numeric_limits<UnsignedInt>::max();
            if (x == 0 || y == 0)
            {
                return false;
            }

            return x > max - y;
        }

        template <std::unsigned_integral I> struct mult_result
        {
            I product, carry;
        };

        /**
         * @brief Multiplies two integers with carry
         *
         * The result of two multiplied integers of size n bytes can take as much
         * as 2n bytes to store so here is carry
         *
         * for example
         * 0xff * 0xff = 0xfe01
         * @tparam Int
         * @param x
         * @param y
         * @return auto
         */
        template <std::unsigned_integral Int>
        static auto constexpr multi_by_parts(Int x, Int y) // NOLINT(*swappable*)
        {
            /*
             * n = bit size Int
             *
             * x = a << (n/2) + b
             * y = c << (n/2) + d
             * (a,b,c,d n/2 bits long)
             *
             * x * y = (a * c) << n                       ----> CARRY
             *       + (b * c + a * d) << n / 2    \____PRODUCT
             *       + b * d                       /
             */
            Int const constexpr n = sizeof(Int) * CHAR_BIT;
            Int const constexpr h = n / 2;
            Int const a = top_half(x);
            Int const b = bottom_half(x);
            Int const c = top_half(y);
            Int const d = bottom_half(y);

            Int carry = a * c;
            Int const product_low{b * d};
            Int const product_high_left{b * c};
            Int const product_high_right{a * d};
            Int const product_high = product_high_left + product_high_right;
            using namespace unsigned_checked_operations;
            carry += addition_would_overflow(product_high_left, product_high_right);
            Int const product_high_split_1 = bottom_half(product_high)
                                             << (sizeof(Int) * CHAR_BIT / 2);
            carry += addition_would_overflow(product_high_split_1, product_low);
            carry += top_half(product_high);
            Int const product = product_high_split_1 + product_low;
            return mult_result<Int>(product, carry);
        }

        template <std::unsigned_integral Int>
            requires(!std::same_as<Int, uintmax_t>)
        static auto constexpr multi_double_precision(Int x, Int y) // NOLINT(*swappable*)
        {
            using namespace impl;
            using IntBigger = impl::next_up_unsigned_t<Int>;
            IntBigger result{static_cast<IntBigger>(x) * static_cast<IntBigger>(y)};
            Int product = static_cast<Int>(bottom_half(result));
            Int carry = static_cast<Int>(top_half(result));
            return mult_result<Int>(product, carry);
        }

        template <std::unsigned_integral Int>
        static auto constexpr multi(Int x, Int y) // NOLINT(*swappable*)
        {
            using namespace unsigned_checked_operations;
            if constexpr (std::same_as<Int, uintmax_t>)
            {
                return multi_by_parts(x, y);
            }
            return multi_double_precision(x, y);
        }

        /* x - y */
        template <std::unsigned_integral UnsignedInt>
        bool sub_would_underflow(UnsignedInt x, UnsignedInt y)
        {
            return x < y;
        }

    } // namespace unsigned_checked_operations

    namespace impl
    {
#pragma pack(push, 1)
        template <std::integral UnitT, size_t Count, std::endian endianess>
        struct extended_int_units;

        template <typename UnitT, size_t UnitCount>
        struct extended_int_units<UnitT, UnitCount, std::endian::big>
        {
            using self_t = extended_int_units<UnitT, UnitCount, std::endian::big>;
            using unit_t = UnitT;
            static size_t const constexpr unit_count = UnitCount;
            std::array<unit_t, unit_count> data{};

            [[nodiscard]] auto constexpr little()
            {
                return std::ranges::subrange{std::rbegin(data), std::rend(data)};
            }
            [[nodiscard]] auto constexpr little_const() const
            {
                return std::ranges::subrange{std::crbegin(data), std::crend(data)};
            }

            [[nodiscard]] auto constexpr big()
            {
                return std::ranges::subrange{std::begin(data), std::end(data)};
            }
            [[nodiscard]] auto constexpr big_const() const
            {
                return std::ranges::subrange{std::cbegin(data), std::cend(data)};
            }

            [[nodiscard]] auto constexpr native()
            {
                return std::ranges::subrange{std::begin(data), std::end(data)};
            }
            [[nodiscard]] auto constexpr native_const() const
            {
                return std::ranges::subrange{std::cbegin(data), std::cend(data)};
            }

            [[nodiscard]] std::strong_ordering constexpr
            operator<=>(extended_int_units<UnitT, UnitCount, std::endian::big> const &other) const
            {
                auto other_unit = other.big_const().cbegin();
                for (auto const &u : big_const())
                {
                    if (u != *other_unit)
                    {
                        return u <=> *other_unit;
                    }
                    ++other_unit;
                }
                return std::strong_ordering::equivalent;
            }

            [[nodiscard]] bool constexpr
            operator==(extended_int_units<UnitT, UnitCount, std::endian::little> const &other) const
            {
                return (*this <=> other) == 0;
            }
        };

        template <typename UnitT, size_t UnitCount>
        struct extended_int_units<UnitT, UnitCount, std::endian::little>
        {
            using unit_t = UnitT;
            static size_t const constexpr unit_count = UnitCount;
            std::array<unit_t, unit_count> data{};

            [[nodiscard]] auto constexpr little()
            {
                return std::ranges::subrange{std::begin(data), std::end(data)};
            }
            [[nodiscard]] auto constexpr little_const() const
            {
                return std::ranges::subrange{std::cbegin(data), std::cend(data)};
            }

            [[nodiscard]] auto constexpr big()
            {
                return std::ranges::subrange{std::rbegin(data), std::rend(data)};
            }
            [[nodiscard]] auto constexpr big_const() const
            {
                return std::ranges::subrange{std::crbegin(data), std::crend(data)};
            }

            [[nodiscard]] auto constexpr native()
            {
                return std::ranges::subrange{std::begin(data), std::end(data)};
            }
            [[nodiscard]] auto constexpr native_const() const
            {
                return std::ranges::subrange{std::cbegin(data), std::cend(data)};
            }

            [[nodiscard]] std::strong_ordering constexpr operator<=>(
                extended_int_units<UnitT, UnitCount, std::endian::little> const &other) const
            {
                auto other_unit = other.big_const().cbegin();
                for (auto const &u : big_const())
                {
                    if (u != *other_unit)
                    {
                        return u <=> *other_unit;
                    }
                    ++other_unit;
                }
                return std::strong_ordering::equivalent;
            }

            [[nodiscard]] bool constexpr
            operator==(extended_int_units<UnitT, UnitCount, std::endian::little> const &other) const
            {
                return (*this <=> other) == 0;
            }
        };

#pragma pack(pop)
        template <std::unsigned_integral UnitT, size_t Count>
        struct extended_int_units_2 : public extended_int_units<UnitT, Count, std::endian::native>
        {
            void F() { this->data; }
        };
    } // namespace impl

#pragma pack(push, 1)
    template <std::integral Unit, size_t Count>
        requires std::is_unsigned_v<Unit>
    struct extended_integer
    {
        using unit_t = Unit;
        static auto const constexpr unit_count = Count;
        using self_t = extended_integer<unit_t, unit_count>;
        impl::extended_int_units<unit_t, unit_count, std::endian::native> units{};

        template <typename... LittleValues>
            requires(sizeof...(LittleValues) > 0 && sizeof...(LittleValues) <= Count &&
                     std::convertible_to<std::common_type_t<LittleValues...>, unit_t>)
        constexpr extended_integer(LittleValues... values)
        {
            auto const values_array = bits::make_array(values...);
            std::ranges::copy(values_array, units.little().begin());
        }

        constexpr extended_integer() = default;

        static auto constexpr max()
        {
            self_t value{};
            for (auto &u : value.units.native())
            {
                u = std::numeric_limits<unit_t>::max();
            }
            return value;
        }

        static auto constexpr min() { return self_t{}; }

        auto constexpr &operator+=(self_t const &other)
        {
            using namespace unsigned_checked_operations;
            auto other_it = other.units.little_const().cbegin();

            unit_t carry_bit{0};

            for (auto &u : units.little())
            {
                unit_t const component_1 = u;
                unit_t const component_2 = *other_it;
                unit_t const prev_carry_bit = carry_bit;
                carry_bit = addition_would_overflow(component_1, component_2);
                unit_t const sum = component_1 + component_2;
                carry_bit += addition_would_overflow(sum, prev_carry_bit);
                u = sum + prev_carry_bit;
                ++other_it;
            }

            return *this;
        }
        [[nodiscard]] auto constexpr operator+(self_t other) const { return other += *this; }

        [[nodiscard]] auto constexpr &mult_by_unit(unit_t unit)
        {
            unit_t carry = 0;
            for (auto &u : units.little())
            {
                auto [product, new_carry] = unsigned_checked_operations::multi(u, unit);
                u = product + carry;
                carry = new_carry +
                        unsigned_checked_operations::addition_would_overflow(product, carry);
            }
            return *this;
        }

        [[nodiscard]] auto constexpr mult_by_unit_const(unit_t unit) const
        {
            return self_t{*this}.mult_by_unit(unit);
        }

        [[nodiscard]] auto constexpr operator*(self_t const &other) const
        {
            if (*this == 1)
            {
                return other;
            }
            if (other == 1)
            {
                return *this;
            }
            self_t result{};
            for (auto const &other_unit : other.units.little_const())
            {
                result += mult_by_unit_const(other_unit);
            }
            return result;
        }
        auto constexpr &operator*=(self_t const &other) { return *this = *this * other; }

        auto constexpr &operator-=(self_t const &other)
        {
            auto other_it = other.units.little_const().cbegin();
            Unit carry{0};
            for (auto &u : units.little())
            {
                Unit const a = u;
                Unit const b = carry;
                Unit const c = *other_it;
                Unit const diff_tmp = a - b;
                Unit const diff = diff_tmp - c;
                Unit new_carry{static_cast<Unit>(0)};
                new_carry += unsigned_checked_operations::sub_would_underflow(a, b);
                new_carry += unsigned_checked_operations::sub_would_underflow(diff_tmp, c);
                u = diff;
                carry = new_carry;
                ++other_it;
            }
            return *this;
        }
        [[nodiscard]] auto constexpr operator-(self_t const &other) const
        {
            return self_t{*this} -= other;
        }

        auto constexpr &operator>>=(int n)
        {
            auto const constexpr unit_size_bits = sizeof(Unit) * CHAR_BIT;

            if (n == 0) // TODO BENCHMARK WITH AND WITHOUT THIS IF-stmt
            {
                return *this;
            }
            if (n < 0)
            {
                return *this <<= -n;
            }

            auto const whole_unit_shift = n / unit_size_bits;
            auto const inner_unit_shift = n - whole_unit_shift * unit_size_bits;

            if (whole_unit_shift > Count)
            {
                std::ranges::fill(units.native(), static_cast<Unit>(0));
                return *this;
            }

            if (whole_unit_shift > 0)
            {
                auto whole_shifted_units =
                    units.little() | std::ranges::views::drop(whole_unit_shift);
                auto shifted_pos_it = units.little().begin();
                for (auto u : whole_shifted_units)
                {
                    *shifted_pos_it = u;
                    ++shifted_pos_it;
                }
            }

            if (inner_unit_shift > 0)
            {
                // the bytes that were righted "out" of the unit and are supposed to land into
                // the next unit
                Unit prev_carry{0};
                Unit const carry_mask = (1 << inner_unit_shift) - 1;

                for (auto &u : units.big() | std::ranges::views::drop(whole_unit_shift))
                {
                    auto const carry = u & carry_mask;
                    u = (u >> inner_unit_shift) | prev_carry;
                    // move the carry bits from one LSB side of the unit boundary to the MSB
                    // side, so it is ready to be combined with the unit in the next iteration
                    prev_carry = carry << (unit_size_bits - inner_unit_shift);
                }
            }

            return *this;
        }
        [[nodiscard]] auto constexpr operator>>(int n) const { return self_t{*this} >>= n; }

        auto constexpr &operator<<=(int n)
        {
            auto const constexpr unit_size_bits = sizeof(Unit) * CHAR_BIT;

            if (n == 0) // TODO BENCHMARK WITH AND WITHOUT THIS IF-stmt
            {
                return *this;
            }
            if (n < 0)
            {
                return *this >>= -n;
            }

            auto const whole_unit_shift = n / unit_size_bits;
            auto const inner_unit_shift = n % unit_size_bits;

            if (whole_unit_shift > Count)
            {
                std::ranges::fill(units.native(), static_cast<unit_t>(0));
                return *this;
            }

            if (whole_unit_shift > 0)
            {
                auto whole_shifted_units = units.big() | std::ranges::views::drop(whole_unit_shift);
                auto shifted_pos_it = units.big().begin();
                for (auto const &u : whole_shifted_units)
                {
                    *shifted_pos_it = u;
                    ++shifted_pos_it;
                }
            }

            if (inner_unit_shift > 0)
            {
                // the bytes that were righted "out" of the unit and are supposed to land into
                // the next unit
                Unit prev_carry{0};
                Unit const carry_mask = ((1 << inner_unit_shift) - 1)
                                        << (unit_size_bits - inner_unit_shift);

                for (auto &u : units.big() | std::ranges::views::drop(whole_unit_shift))
                {
                    auto const carry = u & carry_mask;
                    u = (u << inner_unit_shift) | prev_carry;
                    // move the carry bits from the MSB side of the unit boundary to the LSB
                    // side, so it is ready to be combined with the unit in the next iteration
                    prev_carry = carry >> (unit_size_bits - inner_unit_shift);
                }
            }

            return *this;
        }
        [[nodiscard]] auto constexpr operator<<(int n) const { return self_t{*this} <<= n; }

        [[nodiscard]] auto constexpr operator~() const
        {
            self_t new_value{*this};
            for (auto &u : new_value.units.native())
            {
                u = ~u;
            }
            return new_value;
        }

        auto constexpr &operator|=(self_t const &other)
        {
            auto it = other.units.native().cbegin();
            for (auto &u : units.native())
            {
                u |= *it;
                ++it;
            }
            return *this;
        }
        [[nodiscard]] auto constexpr operator|(self_t other) const { return other |= *this; }

        auto constexpr &operator&=(self_t const &other)
        {
            auto it = other.units.native().cbegin();
            for (auto &u : units.native())
            {
                u &= *it;
                ++it;
            }
            return *this;
        }
        [[nodiscard]] auto constexpr operator&(self_t other) { return other |= *this; }

        auto constexpr &operator^=(self_t const &other)
        {
            auto it = other.units.native().cbegin();
            for (auto &u : units.native())
            {
                u ^= *it;
                ++it;
            }
            return *this;
        }
        [[nodiscard]] auto constexpr operator^(self_t other) const { return other |= *this; }

        [[nodiscard]] static auto constexpr zero() { return self_t{}; }

        struct divmod_result
        {
            self_t quotient{};
            self_t remainder{};
        };
        [[nodiscard]] auto slow_divmod(self_t const &divisor) const
        {
            divmod_result result{.quotient = {0}, .remainder = {*this}};
            while (result.remainder >= divisor)
            {
                result.remainder -= divisor;
                ++result.quotient;
            }
            return result;
        }
        [[nodiscard]] auto slow_quo(self_t const &other) const
        {
            return slow_divmod(other).quotient;
        }
        [[nodiscard]] auto slow_rem(self_t const &other) const
        {
            return slow_divmod(other).remainder;
        }

        auto constexpr divmod(self_t const &other) { return slow_divmod(other); }
        [[nodiscard]] auto operator%(self_t const &other) const { return slow_rem(other); }
        auto &operator%=(self_t const &other) { return *this = *this % slow_rem(other); }

        [[nodiscard]] auto operator/(self_t const &other) const { return slow_quo(other); }
        auto &operator/=(self_t const &other) { return *this = *this / other; }

        extended_integer<Unit, Count> constexpr &operator--() { return *this -= {1}; }

        extended_integer<Unit, Count> constexpr &operator++()
        {
            unit_t carry{1};
            for (auto &u : units.little())
            {
                unit_t new_carry = unsigned_checked_operations::addition_would_overflow(u, carry);
                u += carry;
                carry = new_carry;
            }
            return *this;
        }

        [[nodiscard]] self_t constexpr pow(size_t n) const
        {
            /*
             * x^0 = 1
             * x^(2k) = (x^k)^2
             * x^(2k+1) = x * (x^k)^2
             */
            if (n == 0)
            {
                return 1;
            }
            auto const k = pow(n / 2);
            auto const k_sq = k * k;
            return n % 2 == 0 ? k_sq : *this * k_sq;
        }

        /* Convert to decimal */
        [[nodiscard]] std::string constexpr to_string() const
        {

            static auto const constexpr digit_to_char = [](unsigned digit) -> std::optional<char>
            {
                auto const constexpr z = static_cast<unsigned>('0');
                if (digit > 9)
                {
                    return {};
                }
                return z + digit;
            };

            self_t const constexpr base = 10;
            if (*this == 0)
            {
                return "0";
            }
            self_t val{*this};
            std::vector<char> digits_reverse{};
            while (val > 0)
            {
                auto const result = val.divmod(base);
                auto const digit =
                    static_cast<unsigned>(*result.remainder.units.little_const().cbegin());
                auto const digit_char_opt = digit_to_char(digit);
                if (!digit_char_opt)
                {
                    return "<error extended_int::to_string digit>";
                }
                digits_reverse.push_back(*digit_char_opt);
                val = result.quotient;
            }
            if (digits_reverse.empty())
            {
                return "0";
            }
            return std::string{digits_reverse.crbegin(), digits_reverse.crend()};
        }

        template <typename Int>
            requires(sizeof(Int) % sizeof(unit_t) == 0)
        struct constituent_units
        {
            static auto const constexpr byte_count = sizeof(Int);
            static auto const constexpr unit_count = byte_count / sizeof(unit_t);
            template <size_t... Counts> [[nodiscard]] static auto constexpr get_impl(Unit x)
            {
                return std::make_tuple(get_impl(x, Counts)...);
            }

            /*
            template <typename... Xs> struct type_list;
            template <typename Head, typename... Tail> struct type_list<Head, Tail...>
            {
                using type = Head;
                using next = type_list<Tail...>;
            };
            template <class Last> struct type_list<Last>
            {
                using type = Last;
                using next = void;
            };
             */

            template <size_t... ValueListCount> struct value_list;
            template <size_t ValueListHead, size_t... ValueListTail>
            struct value_list<ValueListHead, ValueListTail...>
            {
                static auto const constexpr value = ValueListHead;
                using next = value_list<ValueListTail...>;
            };
            template <size_t ValueListLast> struct value_list<ValueListLast>
            {
                static auto const constexpr value = ValueListLast;
                using next = void;
            };

            template <size_t NewHead, class ValueList> struct value_list_cons
            {
                static auto const constexpr value = NewHead;
                using next = ValueList;
            };

            template <typename ValueList>
            static auto const constexpr value_list_head = ValueList::value;

            template <typename ValueList> using value_list_tail = typename ValueList::next;

            template <typename ValueList>
            static bool const constexpr value_list_has_next =
                !std::same_as<value_list_tail<ValueList>, void>;

            template <class ValueList> struct value_list_length;
            template <typename ValueList>
            static auto const constexpr value_list_length_actual =
                value_list_length<ValueList>::value;
            template <class ValueList>
                requires(std::is_void_v<value_list_tail<ValueList>>)
            struct value_list_length<ValueList>
            {
                static size_t const constexpr value = 1;
            };
            template <class ValueList>
                requires(!std::is_void_v<value_list_tail<ValueList>>)
            struct value_list_length<ValueList>
            {
                static size_t const constexpr value =
                    value_list_length_actual<value_list_tail<ValueList>> + 1;
            };

            template <typename ValueList, size_t Value> struct value_list_append_impl;
            template <typename ValueList, size_t Value>
                requires(value_list_has_next<ValueList>)
            struct value_list_append_impl<ValueList, Value>
            {
                using type = value_list<value_list_head<ValueList>, Value>;
            };
            template <typename ValueList, size_t Value>
                requires(!value_list_has_next<ValueList>)
            struct value_list_append_impl<ValueList, Value>
            {
                using type = value_list_append_impl<value_list_tail<ValueList>, Value>;
            };
            template <typename ValueList, size_t Value>
            using value_list_append = value_list_append_impl<ValueList, Value>::type;

            template <typename ValueListCurrent, size_t Iteration, size_t Max> struct up_to_impl
            {
                using type =
                    up_to_impl<value_list_cons<Iteration, ValueListCurrent>, Iteration + 1, Max>;
            };
            template <typename ValueListCurrent, size_t Iteration, size_t Max>
                requires(Iteration == Max)
            struct up_to_impl<ValueListCurrent, Iteration, Max>
            {
                using type = ValueListCurrent;
            };
            template <size_t UpToCount>
            using up_to = typename up_to_impl<value_list<>, 0, UpToCount>::type;

            static auto get(Int x) {}
        };

        template <std::unsigned_integral FromInt> self_t from(FromInt value) {}

        template <std::floating_point Floating> Floating to_floating() const
        {
            static auto const constexpr bit_count =
                static_cast<Floating>(sizeof(unit_t) * CHAR_BIT);
            size_t exponent = 0;
            auto sum = static_cast<Floating>(0);
            for (auto u : units.little_const())
            {
                sum += static_cast<Floating>(u) * std::pow(bit_count, exponent);
                ++exponent;
            }
            return sum;
        }

        explicit constexpr operator float() const { return to_floating<float>(); }
        explicit constexpr operator double() const { return to_floating<double>(); }
        explicit constexpr operator long double() const { return to_floating<long double>(); }

        auto constexpr operator<=>(extended_integer<Unit, Count> const &) const = default;

        [[nodiscard]] auto constexpr to_hex(unsigned split = 0) const
        {
            return bits::many_bytes_to_hex(
                msd::utils::endian::containers::to_big_endian_array(*this), split);
        }
    };
#pragma pack(pop)
    using uint128_t = extended_integer<uint64_t, 2>;
} // namespace msd::integer

#endif /* AE26D0F3_C377_468F_BAAB_B7EAC672FAB4 */
