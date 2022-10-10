#include <string>
#include <iostream>
#include <fstream>
#include <filesystem>
#include <exception>
#include <vector>
#include <bit>
#include <array>
#include <algorithm>

using std::array;
using std::pair;
using std::byte;
using std::cbegin;
using std::cend;
using std::copy;
using std::cout;
using std::endian;
using std::endl;
using std::filesystem::exists;
using std::filesystem::file_size;
using std::ifstream;
using std::min;
using std::reverse_copy;
using std::rotr;
using std::runtime_error;
using std::string;
using std::stringstream;
using std::vector;
using std::to_string;

string read_file(string file_path)
{
    if (!exists(file_path))
    {
        throw runtime_error("file does not exist");
    }
    ifstream ifs{ file_path };
    return {std::istreambuf_iterator<char>{ifs}, {}};
}

vector<byte> read_file_bytes(string file_path)
{
    if (!exists(file_path))
    {
        throw runtime_error("file does not exist");
    }
    vector<byte> bytes_read;

    // The following do not work, no idea why
    // ifstream ifs{ file_path , std::ios::in | std::ios::binary};
    // DOES NOT WORK
    // bytes_read.assign(file_size(file_path), byte{0});
    // ifs.read(bytes_read.data(), bytes_read.size());
    // DOES NOT WORK EITHER
    // bytes_read = { std::istreambuf_iterator<byte>(ifs), {} };

    ifstream ifs_regular{file_path};
    bytes_read.assign(file_size(file_path), byte{0});
    ifs_regular.read((char*)bytes_read.data(), bytes_read.size());

    return bytes_read;
}


template <typename T>
auto direct_copy_bytes(T x)
{
    array<byte, sizeof (T)> bytes;
    auto start = reinterpret_cast<byte*>(&x);
    copy(start, start + sizeof x, bytes.data());
    return bytes;
}

template <typename T>
auto reverse_copy_bytes(T x)
{
    array<byte, sizeof (T)> bytes;
    auto start = reinterpret_cast<byte*>(&x);
    reverse_copy(start, start + sizeof x, bytes.data());
    return bytes;
}

template <typename Int>
auto to_big_endian_array(Int x)
{
    return endian::native == endian::big ? direct_copy_bytes(x) : reverse_copy_bytes(x);
}

template <typename Int>
auto to_little_endian_array(Int x)
{
    return endian::native == endian::little ? direct_copy_bytes(x) : reverse_copy_bytes(x);
}

template <typename Int, typename ItOut>
auto to_little_endian(Int x, ItOut beg)
{
    auto bytes = to_little_endian_array(x);
    return copy(cbegin(bytes), cend(bytes), beg);
}

template <typename Int, typename ItOut>
auto to_big_endian(Int x, ItOut beg)
{
    auto bytes =  to_big_endian_array(x);
    return copy(cbegin(bytes), cend(bytes), beg);
}

template <typename To, typename ByteIter>
To from_little_endian(ByteIter beg)
{
    To converted;
    if (endian::native == endian::little)
    {
        copy(beg, beg + sizeof(To), reinterpret_cast<byte*>(&converted));
    }
    else
    {
        reverse_copy(beg, beg + sizeof(To), reinterpret_cast<byte*>(&converted));
    }
    return converted;
}

template <typename To>
To from_little_endian_array(array<byte, sizeof(To)> bytes)
{
    To converted;
    if (endian::native == endian::little)
    {
        copy(cbegin(bytes), cend(bytes), reinterpret_cast<byte*>(&converted));
    }
    else
    {
        reverse_copy(cbegin(bytes), cend(bytes), reinterpret_cast<byte*>(&converted));
    }
    return converted;
}

template <typename To, typename ByteIter>
To from_big_endian(ByteIter beg)
{
    To converted;
    if (endian::native == endian::big)
    {
        copy(beg, beg + sizeof(To), reinterpret_cast<byte*>(&converted));
    }
    else
    {
        reverse_copy(beg, beg + sizeof(To), reinterpret_cast<byte*>(&converted));
    }
    return converted;
}

template <typename To>
To from_big_endian_array(array<byte, sizeof(To)> bytes)
{
    To converted;
    if (endian::native == endian::big)
    {
        copy(cbegin(bytes), cend(bytes), reinterpret_cast<byte*>(&converted));
    }
    else
    {
        reverse_copy(cbegin(bytes), cend(bytes), reinterpret_cast<byte*>(&converted));
    }
    return converted;
}

string to_string(vector<byte> v)
{
    return {reinterpret_cast<char*>(v.data()), v.size()};
}

template <typename T>
void insert_multiple(vector<T> &vec, size_t count, T val)
{
    for (size_t i = 0; i < count; ++i)
    {
        vec.push_back(val);
    }   
}

/* sha-244 & 256 */
constexpr size_t BLOCK_SIZE_BYTES = 64;
constexpr size_t BLOCK_SIZE = BLOCK_SIZE_BYTES * 8;
constexpr size_t BLOCK_ROLLOVER_BYTES = 56;
constexpr size_t BLOCK_ROLLOVER = BLOCK_ROLLOVER_BYTES * 8;
constexpr size_t WORDS_PER_BLOCK = 16;
using block_t = array<uint32_t, WORDS_PER_BLOCK>;
using byte_block_t = array<byte, BLOCK_SIZE_BYTES>;

struct Hash256Progress;

struct Scramble /* functions used by SHA-224 and SHA-256  */
{
    static constexpr uint32_t CH(uint32_t x, uint32_t y, uint32_t z)
    {
        return (x & y) ^ ( (~ x) & z);
    }
    static constexpr uint32_t MAJ(uint32_t x, uint32_t y, uint32_t z)
    {
        return (x & y) ^ (x & z) ^ (y & z);
    }
    static constexpr uint32_t BSIG0(uint32_t x)
    {
        return rotr(x, 2) ^ rotr(x, 13) ^ rotr(x, 22);
    }
    static constexpr uint32_t BSIG1(uint32_t x)
    {
        return rotr(x, 6) ^ rotr(x, 11) ^ rotr(x, 25);
    }
    static constexpr uint32_t SSIG0(uint32_t x)
    {
        return rotr(x, 7) ^ rotr(x, 18) ^ (x >> 3);
    }
    static constexpr uint32_t SSIG1(uint32_t x)
    {
        return rotr(x, 17) ^ rotr(x, 19) ^ (x >> 10);
    }

    static constexpr array<uint32_t, 64> K_WORDS = {
        0x428a2f98, 0x71374491, 0xb5c0fbcf, 0xe9b5dba5,
        0x3956c25b, 0x59f111f1, 0x923f82a4, 0xab1c5ed5,
        0xd807aa98, 0x12835b01, 0x243185be, 0x550c7dc3,
        0x72be5d74, 0x80deb1fe, 0x9bdc06a7, 0xc19bf174,
        0xe49b69c1, 0xefbe4786, 0x0fc19dc6, 0x240ca1cc,
        0x2de92c6f, 0x4a7484aa, 0x5cb0a9dc, 0x76f988da,
        0x983e5152, 0xa831c66d, 0xb00327c8, 0xbf597fc7,
        0xc6e00bf3, 0xd5a79147, 0x06ca6351, 0x14292967,
        0x27b70a85, 0x2e1b2138, 0x4d2c6dfc, 0x53380d13,
        0x650a7354, 0x766a0abb, 0x81c2c92e, 0x92722c85,
        0xa2bfe8a1, 0xa81a664b, 0xc24b8b70, 0xc76c51a3,
        0xd192e819, 0xd6990624, 0xf40e3585, 0x106aa070,
        0x19a4c116, 0x1e376c08, 0x2748774c, 0x34b0bcb5,
        0x391c0cb3, 0x4ed8aa4a, 0x5b9cca4f, 0x682e6ff3,
        0x748f82ee, 0x78a5636f, 0x84c87814, 0x8cc70208,
        0x90befffa, 0xa4506ceb, 0xbef9a3f7, 0xc67178f2
    };

    // initial state for SHA-224
    static constexpr array<uint32_t, 8> H_init_244 = {
        0xc1059ed8,
        0x367cd507,
        0x3070dd17,
        0xf70e5939,
        0xffc00b31,
        0x68581511,
        0x64f98fa7,
        0xbefa4fa4
    };

    // initial state for SHA-256
    static constexpr array<uint32_t, 8> H_init_256 = {
        0x6a09e667,
        0xbb67ae85,
        0x3c6ef372,
        0xa54ff53a,
        0x510e527f,
        0x9b05688c,
        0x1f83d9ab,
        0x5be0cd19
    };
    
    static int padding_zeros_needed(uint64_t message_length)
    {
        const auto padding_div = 512;
        const auto padding_mod = 448;
        auto d = (message_length + 1) / padding_div;
        auto m = (message_length + 1) % padding_div;
        if (m < padding_mod)
        {
            return padding_mod - m;
        }
        if (m > padding_mod)
        {
            return (padding_div - m) + padding_mod;
        }
        return 0;
    }

    static auto init_W(block_t message_block)
    {
        array<uint32_t, 64> W_WORDS;
        copy(cbegin(message_block), cbegin(message_block) + 16, begin(W_WORDS));
        for (size_t t = 16; t < 64; ++t)
        {
            W_WORDS[t] = SSIG1(W_WORDS[t-2]) + W_WORDS[t-7] + SSIG0(W_WORDS[t-15]) + W_WORDS[t-16];
        }
        return W_WORDS;
    }
    
    static auto block_work(const Hash256Progress &prog);
    static auto block_work_functional( const Hash256Progress &prog);
};


/*
Scrambler2 used for SHA-384 and SHA-512 

    CH( x, y, z) = (x AND y) XOR ( (NOT x) AND z)

    MAJ( x, y, z) = (x AND y) XOR (x AND z) XOR (y AND z)

    BSIG0(x) = ROTR^28(x) XOR ROTR^34(x) XOR ROTR^39(x)

    BSIG1(x) = ROTR^14(x) XOR ROTR^18(x) XOR ROTR^41(x)

    SSIG0(x) = ROTR^1(x) XOR ROTR^8(x) XOR SHR^7(x)

    SSIG1(x) = ROTR^19(x) XOR ROTR^61(x) XOR SHR^6(x)

    K_WORDS = (64 bit words)
        428a2f98d728ae22 7137449123ef65cd b5c0fbcfec4d3b2f e9b5dba58189dbbc
        3956c25bf348b538 59f111f1b605d019 923f82a4af194f9b ab1c5ed5da6d8118
        d807aa98a3030242 12835b0145706fbe 243185be4ee4b28c 550c7dc3d5ffb4e2
        72be5d74f27b896f 80deb1fe3b1696b1 9bdc06a725c71235 c19bf174cf692694
        e49b69c19ef14ad2 efbe4786384f25e3 0fc19dc68b8cd5b5 240ca1cc77ac9c65
        2de92c6f592b0275 4a7484aa6ea6e483 5cb0a9dcbd41fbd4 76f988da831153b5
        983e5152ee66dfab a831c66d2db43210 b00327c898fb213f bf597fc7beef0ee4
        c6e00bf33da88fc2 d5a79147930aa725 06ca6351e003826f 142929670a0e6e70
        27b70a8546d22ffc 2e1b21385c26c926 4d2c6dfc5ac42aed 53380d139d95b3df
        650a73548baf63de 766a0abb3c77b2a8 81c2c92e47edaee6 92722c851482353b
        a2bfe8a14cf10364 a81a664bbc423001 c24b8b70d0f89791 c76c51a30654be30
        d192e819d6ef5218 d69906245565a910 f40e35855771202a 106aa07032bbd1b8
        19a4c116b8d2d0c8 1e376c085141ab53 2748774cdf8eeb99 34b0bcb5e19b48a8
        391c0cb3c5c95a63 4ed8aa4ae3418acb 5b9cca4f7763e373 682e6ff3d6b2b8a3
        748f82ee5defb2fc 78a5636f43172f60 84c87814a1f0ab72 8cc702081a6439ec
        90befffa23631e28 a4506cebde82bde9 bef9a3f7b2c67915 c67178f2e372532b
        ca273eceea26619c d186b8c721c0c207 eada7dd6cde0eb1e f57d4f7fee6ed178
        06f067aa72176fba 0a637dc5a2c898a6 113f9804bef90dae 1b710b35131c471b
        28db77f523047d84 32caab7b40c72493 3c9ebe0a15c9bebc 431d67c49c100d4c
        4cc5d4becb3e42b6 597f299cfc657e2a 5fcb6fab3ad6faec 6c44198c4a475817
*/

template <typename Container>
vector<string> bytes_to_lines(Container v)
{
    static auto new_stream = [] {
        stringstream the_new_stream;
        the_new_stream.setf(the_new_stream.hex, the_new_stream.basefield);
        the_new_stream.fill('0');
        the_new_stream.width(2);
        return the_new_stream;
    };
    vector<string> lines;
    stringstream stream = new_stream();
    int count_in_line = 0;
    for (byte b: v)
    {
        ++count_in_line;
        stream.width(2);
        stream << static_cast<int>(b);
        if (count_in_line == 16)
        {
            lines.push_back(stream.str());
            stream = new_stream();
            count_in_line = 0;
        }
        else if (count_in_line % 4 == 0)
        {
            stream << ' ';
        }
    }

    string last_line = stream.str();
    if ( last_line.size() )
    {
        lines.push_back(last_line);
    }

    return lines;
}

struct Hash256Progress
{
    array<uint32_t, 64> W;
    array<uint32_t, 8> H = Scramble::H_init_256;
    void accumulate(decltype(H) working)
    {
        for (size_t i = 0; i < H.size(); i++)
        {
            H[i] += working[i];
        }
        
    }
    auto digest()
    {
        array<byte, 32> a;
        auto ins = a.begin();
        for (uint32_t h: H)
        {
            ins = to_big_endian(h, ins);
        }
        if (ins != a.end())
        {
            throw runtime_error("ASSERT-3: did not write everything when writing digest");
        }
        return a;
    }
};

template <typename F, typename X>
X iterate(F f, X x, size_t count)
{
    for (size_t i = 0; i != count; i++)
    {
        x = f(x);
    }
    return x;
}

auto Scramble::block_work_functional( const Hash256Progress &prog)
{
    static auto const_loop = [&prog] (const auto &loop_control)
    {
        auto working = loop_control.first;
        auto &[a,b,c,d,e,f,g,h] = working;
        auto t = loop_control.second;
        uint32_t T1 = h + BSIG1(e) + CH(e,f,g) + K_WORDS[t] + prog.W[t];
        uint32_t T2 = BSIG0(a) + MAJ(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
        return make_pair(working, t + 1);
    };
    static auto loop = [&prog] (auto loop_control)
    {
        auto &working = loop_control.first;
        auto &[a,b,c,d,e,f,g,h] = working;
        auto &t = loop_control.second;
        uint32_t T1 = h + BSIG1(e) + CH(e,f,g) + K_WORDS[t] + prog.W[t];
        uint32_t T2 = BSIG0(a) + MAJ(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
        ++t;
        return  loop_control;
    };
    return iterate(loop, make_pair(prog.H, 0), 64);
}

auto Scramble::block_work( const Hash256Progress &prog)
{
    auto working = prog.H;
    auto &[a,b,c,d,e,f,g,h] = working;
    // return iterate(iteration, prog.H, 64);
    for (size_t t = 0; t < 64; ++t)
    {
        uint32_t T1 = h + BSIG1(e) + CH(e,f,g) + K_WORDS[t] + prog.W[t];
        uint32_t T2 = BSIG0(a) + MAJ(a,b,c);
        h = g;
        g = f;
        f = e;
        e = d + T1;
        d = c;
        c = b;
        b = a;
        a = T1 + T2;
    }
    return working;
}

constexpr int block_count(size_t message_length_bits)
{
    int div = (message_length_bits + 1) / BLOCK_SIZE;
    int mod = (message_length_bits + 1) % BLOCK_SIZE;
    return div + 1 + (mod > BLOCK_ROLLOVER);
}

template<typename Tout, typename Iterator, typename IteratorOut>
IteratorOut many_from_big_endian(Iterator beg, Iterator end, IteratorOut start)
{
    auto byte_count = end - beg;
    auto bytes_per_unit = sizeof(Tout);
    if (byte_count % bytes_per_unit != 0)
    {
        throw runtime_error("number of bytes given is not an integer multiple of the bytes per unit (count " + to_string(byte_count) + ", unit " + to_string(bytes_per_unit) + ")");
    }
    for (auto i = beg; i != end; i += sizeof(Tout))
    {
        *(start++) = from_big_endian<Tout>(i);
    }
    return start;
}

template<typename Tout, typename Iterator, typename IteratorOut>
IteratorOut many_from_little_endian(Iterator beg, Iterator end, IteratorOut start)
{
    auto byte_count = end - beg;
    auto bytes_per_unit = sizeof(Tout);
    if (byte_count % bytes_per_unit != 0)
    {
        throw runtime_error("number of bytes given is not an integer multiple of the bytes per unit (count " + to_string(byte_count) + ", unit " + to_string(bytes_per_unit) + ")");
    }
    for (auto i = beg; i != end; i += sizeof(Tout))
    {
        *(start++) = from_little_endian<Tout>(i);
    }
    return start;
}

byte_block_t pad_block(vector<byte>::const_iterator msg_beg, vector<byte>::const_iterator msg_end, size_t msg_length)
{
    const auto msg_bytes = msg_end - msg_beg;
    byte_block_t padded_block;
    copy(msg_beg, msg_end, padded_block.data());
    if (msg_bytes < BLOCK_SIZE_BYTES) // padding needed
    {
        padded_block[msg_bytes] = byte{0x80};
        auto padded_length = msg_bytes + 1;
        auto limit = padded_length > BLOCK_ROLLOVER_BYTES? BLOCK_SIZE_BYTES : BLOCK_ROLLOVER_BYTES;
        while (padded_length < limit)
        {
            padded_block[padded_length++] = byte{0};
        }
        if (padded_length == BLOCK_ROLLOVER_BYTES)
        {
            for (byte b: to_big_endian_array(msg_length))
            {
                padded_block[padded_length++] = b;
            }
        }
    }
    return padded_block;
}

block_t get_message_block(const vector<byte> &message, int block_index)
{
    if (block_index >= block_count(message.size() * 8))
    {
        throw runtime_error("ASSERT-4: got block index bigger than block count");
    }

    const auto start = block_index * BLOCK_SIZE_BYTES;
    const auto bytes_after_start = message.size() - start;
    const auto stop = min(bytes_after_start, BLOCK_SIZE_BYTES);

    auto block_beg =  cbegin(message) + start;
    auto block_end = block_beg + stop;

    auto padded = pad_block(block_beg, block_end, message.size());
    if (padded.size() != 64)
    {
        throw runtime_error("ASSERT-2: block size should be 64 bytes");
    }

    block_t to_be_returned_block;
    many_from_big_endian<uint32_t>(cbegin(padded), cend(padded), to_be_returned_block.data());
    return to_be_returned_block;
}

auto to_string(block_t message_block)
{
    stringstream ss;
    int i = 0;
    ss.setf(ss.hex, ss.basefield);
    ss.fill('0');
    for (auto word: message_block)
    {
        for (auto b : to_big_endian_array(word))
        {
            ss.width(2);
            ss << (int) b;
        }
        ss << (i % 2 ? '\n' : ' ');
        ++i;
    }
    return ss.str();
}

auto hash_sha256(vector<byte> message)
{
    Hash256Progress work;
    // Scramble::pad_block(cbegin(message));

    cout << "Block count: " << block_count(message.size() * 8) << endl;

    cout << "=== BEGIN MESSAGE ===\n";
    for (string line : bytes_to_lines(message))
    {
        cout << line << '\n';
    }
    cout << "=== END   MESSAGE ===" << endl;
    
    for (size_t i = 0; i < block_count(message.size() * 8); ++i)
    {
        block_t message_block = get_message_block(message, i);

        cout << "=== BEGIN PADDED MESSAGE BLOCK " << to_string(i) << " ===" << endl;
        cout << to_string(message_block);
        cout << "=== END PADDED MESSAGE ===" << endl;
        
        work.W = Scramble::init_W(message_block);
        auto block_result = Scramble::block_work(work);
        work.accumulate(block_result);
    }
    
    return work.digest();
}
