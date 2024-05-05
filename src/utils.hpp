#ifndef B9B475FE_C6E6_4A9F_98B5_A506D530305D
#define B9B475FE_C6E6_4A9F_98B5_A506D530305D

#include <ranges>
#include <sstream>
#include <string>
#include <vector>

namespace steve::bits
{

    std::string read_file(std::string file_path);

    std::vector<std::byte> read_file_bytes(std::string file_path);

    template <typename F, typename X> X iterate(F f, X x, size_t count)
    {
        for (size_t i = 0; i != count; i++)
        {
            x = f(x);
        }
        return x;
    }

    struct hex_bytes_params
    {
        unsigned split = 0;
    };

    // byte count of array
    template <typename Array> struct array_byte_size
    {
        static size_t const constexpr value =
            std::tuple_size<Array>() * sizeof(typename Array::value_type);
    };

    template <typename Array>
    auto const constexpr array_byte_size_v = array_byte_size<Array>::value;

    template <typename Integer> std::string to_hex(Integer x)
    {
        static auto const new_stream = []
        {
            std::stringstream the_new_stream;
            the_new_stream.setf(std::stringstream::hex, std::stringstream::basefield);
            the_new_stream.fill('0');
            return the_new_stream;
        };

        auto stream = new_stream();
        stream.width(sizeof(Integer) * 2);
        stream << static_cast<size_t>(x);
        return stream.str();
    }

    template <typename Container>
        requires(
            std::same_as<std::byte, std::remove_cvref_t<std::ranges::range_value_t<Container>>>)
    std::string many_bytes_to_hex(Container container, unsigned split = 0)
    {
        namespace views = std::ranges::views;
        auto const hexes = container | views::transform(to_hex<std::byte>);
        std::stringstream stream;
        if (split == 0)
        {
            for (auto hex : hexes)
            {
                stream << hex;
            }
            return stream.str();
        }

        for (auto group : hexes | views::chunk(split))
        {
            for (auto hex : group)
            {
                stream << hex;
            }
            stream << ' ';
        }
        auto x = stream.str();
        // todo remove last character from stream instead of taking substr
        return x.substr(0, x.size() - 1);
    }

    template <typename Container> std::vector<std::string> bytes_to_lines(Container v)
    {
        static auto const new_stream = []
        {
            std::stringstream the_new_stream;
            the_new_stream.setf(std::stringstream::hex, std::stringstream::basefield);
            the_new_stream.fill('0');
            return the_new_stream;
        };
        std::vector<std::string> lines;
        std::stringstream stream = new_stream();
        constexpr int MAX_BYTES_PER_LINE = 16;
        constexpr int SEP_BYTES_COUNT = 4;
        int count_in_line = 0;
        for (std::byte b : v)
        {
            ++count_in_line;
            stream.width(2);
            stream << static_cast<int>(b);
            if (count_in_line == MAX_BYTES_PER_LINE)
            {
                lines.push_back(stream.str());
                stream = new_stream();
                count_in_line = 0;
            }
            else if (count_in_line % SEP_BYTES_COUNT == 0)
            {
                stream << ' ';
            }
        }

        std::string last_line = stream.str();
        if (last_line.size())
        {
            lines.push_back(last_line);
        }

        return lines;
    }

} // namespace steve::bits

#endif /* B9B475FE_C6E6_4A9F_98B5_A506D530305D */
