#include "utils.hpp"

#include <filesystem>
#include <fstream>
#include <string>
#include <vector>

namespace msd::bits
{
    std::string read_file(std::string file_path)
    {
        if (!std::filesystem::exists(file_path))
        {
            throw std::runtime_error("file does not exist");
        }
        std::ifstream ifs{file_path};
        return {std::istreambuf_iterator<char>{ifs}, {}};
    }

    std::vector<std::byte> read_file_bytes(std::string file_path)
    {
        if (!std::filesystem::exists(file_path))
        {
            throw std::runtime_error("file does not exist");
        }
        std::vector<std::byte> bytes_read;

        // The following do not work, no idea why
        // ifstream ifs{ file_path , std::ios::in | std::ios::binary};
        // DOES NOT WORK
        // bytes_read.assign(file_size(file_path), byte{0});
        // ifs.read(bytes_read.data(), bytes_read.size());
        // DOES NOT WORK EITHER
        // bytes_read = { std::istreambuf_iterator<byte>(ifs), {} };

        std::ifstream ifs_regular{file_path};
        bytes_read.assign(std::filesystem::file_size(file_path), std::byte{0});

        auto begin = reinterpret_cast<char *>(bytes_read.data()); // NOLINT(*reinterpret*)
        auto count = static_cast<ssize_t>(bytes_read.size());
        ifs_regular.read(begin, count);

        return bytes_read;
    }
} // namespace msd::bits
