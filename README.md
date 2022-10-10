# SHA-256 implementation

This is an implementation of the hashing algorithm SHA-256. Written in C++ and using C++20 features.
This is a learning exercise and has helped me better understard C++ templates as well as learning 
new features released in the C++20 standard. This program is not intended for any serious use nor
does it have security in mind.

Source: [RFC6234](https://datatracker.ietf.org/doc/html/rfc6234)

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

`./mysha <file-path>`

# TODO

See TODO file.
