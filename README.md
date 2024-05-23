# SHA-2 algorithms

This is my implementation of the SHA-2 hashing algorithms. Written in C++ and using C++23 features, making extensive use of templates and concepts.
This is a learning exercise and has helped me better understard C++ templates as well as getting familiar with new C++ features. This program is not intended for any serious use nor does it have security in mind.

Reference: [RFC6234](https://datatracker.ietf.org/doc/html/rfc6234)

Algorithms implemented:
* sha-256
* sha-384
* sha-512

# Usage

## namespace `algorithms`

contains all the algorithms in their individial sub-namespace. Each algorithm has a class called `hash` which is the main class that is used to calculate hashes. 

For example `algorithms::sha384::hash` is the class that you will need to instantiate.

The API has been modelled after `hashlib` python standard library. Once you have an instance you call `hash::update` with a range of data, as many times as needed to exhaust all data. At the end you can call `hash::digest()` to calculate the final hash value.

Important to note that `hash::digest()` does not modify the state and if needed you can use `hash::update` again to add more data. Every time you call `hash::digest()` between 1 and 2 blocks will need to be processed. The size of each block for the algorithms is found from in the details class for each algorithm for example `algorithms::sha384::details::block_size`.

## namespace `integer`

### struct `uint128_t`

128-bit unsigned integer with most integer operations implemented. Intenally comprised of two 64-bit integers, stored with endianess that matches the host machine's architecture.

Operations supported:
* Left / Righ shift <</>>
* Addition +
* Subtraction -
* Bitwise Negation ~
* Bitwise AND &
* Bitwise OR | 
* Bitwise XOR ^

Additional operations supported:
* Convert to hexadecimal string
* Return underlying units (span of uint64_t)

Also because this integer adheres to the system's endianess, it can be loaded
and dumped using `msd_utils/endian.hpp`.

# Compile using cmake and conan

Assuming you have all requirements installed then just execute the following

```bash
mkdir build
cd build
cmake ../src
cmake --build .
```

Note: the requirements are only needed if you want to build the tests, otherwise pass `-DBUILD_TESTS=FALSE`
to the first cmake command and it should build without a hitch.

Requirements are listed in `conanfile.txt`

If you want to install the requirements automatically using [conan](https://github.com/conan-io/conan)
then run `conan-build.sh` (replace profile name in the script, if required). For windows users you should
be able to just copy the commands one by one.

# Run

To compute the hash of a string just pass it as an argument

`./mysha <message> <message2>...`

This will print out the sha256 hash of each message

# TODO

See TODO file.
