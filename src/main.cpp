#include "utils.hpp"

using std::cerr;

int main(int argc, char** argv)
{
    if (argc < 2)
    {
        cerr << "Error: No file given" << endl;
        return 1;
    }
    string file_path{ argv[1] };
    if (!exists(file_path))
    {
        cerr << "Error: File does not exist" << endl;
        return 1;
    }
    cout << "File Size: " << file_size(file_path) << endl;
    auto message = read_file_bytes(file_path);
    // vector<byte> message;
    
    for (string line : bytes_to_lines(hash_sha256(message)))
    {
        cout << line << endl;
    }

    return 0;
}
