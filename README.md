This project aims to impersonate Chrome's TLS fingerprint with OpenSSL.

# Dependencies
Requires OpenSSL(shared) after [03541d7](<https://github.com/openssl/openssl/commit/03541d7302d016aa28d436364d72d58baa3e2114>) with brotli support.

# Building
This project uses [CMake](<https://cmake.org/>) as its build system.

To configure: (Replace `/path/to/openssl` with your OpenSSL installation path, on Windows, replace backslashes(`\`) with forward slashes(`/`))
```cmd
cmake -S . -B build "-DOPENSSL_ROOT_DIR=/path/to/openssl"
```

To build:
```cmd
cmake --build build --config Release
```

Run the executable:

**MSVC:**
```cmd
build/Release/ssl_imp
```

**GCC-like:**
```sh
build/ssl_imp
```

