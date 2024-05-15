#ifndef AE26D0F3_C377_468F_BAAB_B7EAC672FAB4
#define AE26D0F3_C377_468F_BAAB_B7EAC672FAB4

#include <algorithm>
#include <bit>
#include <cstdint>
#include <iterator>
#include <span>
#include <tuple>

#include "utils.hpp"
#include <msd_utils/endian_containers.hpp>

namespace steve::integer
{
    using data_unit = uint64_t;

    template <std::endian endianess> struct uint128_t_helper;
    template <> struct uint128_t_helper<std::endian::little>
    {
        uint64_t low, high;
    };
    template <> struct uint128_t_helper<std::endian::big>
    {
        uint64_t high, low;
    };

    struct uint128_t
    {
        static auto constexpr data_unit_count() { return sizeof(uint128_t) / sizeof(data_unit); }

        uint128_t_helper<std::endian::native> data_data{};

        // NOLINTBEGIN(*union*access*)
        [[nodiscard]] auto constexpr &low() { return data_data.low; }

        [[nodiscard]] auto constexpr low() const { return data_data.low; }

        [[nodiscard]] auto constexpr &high() { return data_data.high; }

        [[nodiscard]] auto constexpr high() const { return data_data.high; }
        // NOLINTEND(*union*access*)

        constexpr uint128_t(uint64_t low_ = 0, uint64_t high_ = 0) // NOLINT(*easily*swap*)
        {
            static_assert(std::endian::native == std::endian::little ||
                              std::endian::native == std::endian::big,
                          "could not determine endianess of system");
            low() = low_;
            high() = high_;
        }

        template <std::input_iterator BytesInputIterator>
        static auto from_little_endian(BytesInputIterator it)
        {
            uint128_t value;

            value.low() = msd::utils::endian::from_little_endian<decltype(value.low())>(it);
            it += sizeof value.low();

            value.high() = msd::utils::endian::from_little_endian<decltype(value.high())>(it);
            it += sizeof value.high();

            return value;
        }

        template <std::input_iterator BytesInputIterator>
        static auto from_big_endian(BytesInputIterator it)
        {
            uint128_t value;

            value.high() = msd::utils::endian::from_big_endian<decltype(value.high())>(it);
            it += sizeof value.high();

            value.low() = msd::utils::endian::from_big_endian<decltype(value.low())>(it);
            it += sizeof value.low();

            return value;
        }

        template <std::output_iterator<std::byte> ByteOutputIterator>
        auto to_big_endian(ByteOutputIterator bytes_out) const
        {
            msd::utils::endian::to_big_endian(high(), bytes_out);
            bytes_out += sizeof high();

            msd::utils::endian::to_big_endian(low(), bytes_out);
            bytes_out += sizeof low();

            return bytes_out;
        }

        template <std::output_iterator<std::byte> ByteOutputIterator>
        auto to_little_endian(ByteOutputIterator bytes_out) const
        {
            msd::utils::endian::to_little_endian(low(), bytes_out);
            bytes_out += sizeof low();

            msd::utils::endian::to_little_endian(high(), bytes_out);
            bytes_out += sizeof high();

            return bytes_out;
        }

        [[nodiscard]] auto as_bytes() const
        {
            return std::as_bytes(std::span<uint128_t const, 1>{this, 1});
        }

        [[nodiscard]] auto to_big_endian_array() const
        {
            return msd::utils::endian::containers::to_big_endian_array(*this);
        }

        [[nodiscard]] auto to_little_endian_array() const
        {
            return msd::utils::endian::containers::to_little_endian_array(*this);
        }

        auto constexpr &operator-=(uint128_t const &other)
        {
            auto const old_low = low();
            low() -= other.low();
            if (old_low < low())
            {
                --high();
            }
            high() -= other.high();
            return *this;
        }

        [[nodiscard]] auto constexpr operator-(uint128_t const &other) const
        {
            uint128_t new_value{*this};
            new_value -= other;
            return new_value;
        }

        [[nodiscard]] auto constexpr operator-(uint128_t &&other) const
        {
            other -= *this;
            return other;
        }

        auto constexpr &operator+=(uint128_t const &other)
        {
            auto const old_low = low();
            low() += other.low();
            if (old_low > low())
            {
                ++high();
            }
            high() += other.high();
            return *this;
        }

        [[nodiscard]] auto constexpr operator+(uint128_t const &other) const
        {
            uint128_t new_value{other};
            new_value += *this;
            return new_value;
        }

        [[nodiscard]] auto constexpr operator+(uint128_t &&other) const
        {
            other += *this;
            return other;
        }

        [[nodiscard]] auto as_units() const
        {
            // NOLINTNEXTLINE(*reinterpret*cast*)
            auto const data_begin = reinterpret_cast<data_unit const *>(this);
            return std::span<data_unit const, data_unit_count()>{data_begin, data_unit_count()};
        }

        [[nodiscard]] auto as_writable_units()
        {
            // NOLINTNEXTLINE(*reinterpret*cast*)
            auto const data_begin = reinterpret_cast<data_unit *>(this);
            return std::span<data_unit, data_unit_count()>{data_begin, data_unit_count()};
        }

        // returns the least significant unit, or if index (i) is non-zero then
        // returns the i-th next unit after the most significant unit
        [[nodiscard]] auto constexpr low2(size_t index = 0) const
        {
            if constexpr (std::endian::native == std::endian::little)
            {
                return as_units()[index];
            }
            return as_units()[data_unit_count() - index - 1];
        }

        auto constexpr &low2(size_t index = 0)
        {
            if constexpr (std::endian::native == std::endian::little)
            {
                return as_writable_units()[index];
            }
            return as_writable_units()[data_unit_count() - index - 1];
        }

        // returns the most significant unit, or if the index (i) is non-zero
        // then returns the i-th next unit after the most significant unit
        [[nodiscard]] auto constexpr high2(size_t index = 0) const
        {
            return low2(data_unit_count() - index - 1);
        }

        auto constexpr &high2(size_t index = 0) { return low2(data_unit_count() - index - 1); }

        // the most significant unit first
        [[nodiscard]] auto big_units_array() const
        {
            std::array<data_unit, data_unit_count()> data{};
            if constexpr (std::endian::native == std::endian::little)
            {
                std::ranges::reverse_copy(as_units(), data.begin());
            }
            else if constexpr (std::endian::native == std::endian::big)
            {
                std::ranges::copy(as_units(), data.begin());
            }
            return data;
        }

        // the least significant unit first
        [[nodiscard]] auto little_units_array() const
        {
            std::array<data_unit, data_unit_count()> data{};
            if constexpr (std::endian::native == std::endian::little)
            {
                std::ranges::copy(as_units(), data.begin());
            }
            else if constexpr (std::endian::native == std::endian::big)
            {
                std::ranges::reverse_copy(as_units(), data.begin());
            }
            return data;
        }

        [[nodiscard]] auto to_hex(unsigned split = 0) const
        {
            auto const data_bytes = to_big_endian_array();
            return bits::many_bytes_to_hex(data_bytes, split);
        }

        [[nodiscard]] auto constexpr operator<=>(uint128_t const &other) const
        {
            return std::make_tuple(high(), low()) <=> std::make_tuple(other.high(), other.low());
        }
    };
} // namespace steve::integer

// [[nodiscard]] auto operator<=>(steve::integer::uint128_t const &a,
//                                steve::integer::uint128_t const &b)
// {
//     return std::make_tuple(a.high(), a.low()) <=> std::make_tuple(b.high(), b.low());
// }

#endif /* AE26D0F3_C377_468F_BAAB_B7EAC672FAB4 */
