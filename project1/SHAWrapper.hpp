//
// Created by horak_000 on 24. 2. 2019.
//
#ifndef PB173_SHA_WRAPPER_H
#define PB173_SHA_WRAPPER_H

#include <stdexcept>
#include "mbedtls/sha512.h"
#include "HexUtils.hpp"

enum class SHA {
    S512 = 0,
    S384 = 1
};

//length in BYTES
class SHAWrapper {
    //bitMASK
    mbedtls_sha512_context _context{};

public:
    explicit SHAWrapper(SHA type)  {
        mbedtls_sha512_init(&_context);
        mbedtls_sha512_starts_ret(&_context, static_cast<int>(type));
    }

    ~SHAWrapper() {
        mbedtls_sha512_free( &_context );
    }

    SHAWrapper(const SHAWrapper& other) = delete;
    SHAWrapper&operator=(const SHAWrapper& other) = delete;

    void feed(unsigned char* data, size_t dataLen) {
        if (mbedtls_sha512_update_ret(&_context, data, dataLen) != 0) {
            throw std::runtime_error("Failed to update hash.");
        }
    }

    std::string finish() {
        unsigned char result[64];
        if (mbedtls_sha512_finish_ret(&_context, result) != 0) {
            throw std::runtime_error("Failed to finish hash.");
        }
        return HexUtils::bin_to_hex(result, 64);
    }
};

#endif //PB173_SHA_WRAPPER_H
