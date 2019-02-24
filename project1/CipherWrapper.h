//
// Created by horak_000 on 24. 2. 2019.
//
#ifndef PB173_CIPHERWRAPPER_H
#define PB173_CIPHERWRAPPER_H

#include <iostream>
#include <vector>

#include "mbedtls/cipher.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

//type-safe
enum class Operation {
    NONE = MBEDTLS_OPERATION_NONE,
    ENCRYPT = MBEDTLS_ENCRYPT,
    DECRYPT = MBEDTLS_DECRYPT
};

enum class Padding {
    PKCS7 = MBEDTLS_PADDING_PKCS7,                 /**< PKCS7 padding (default).        */
    ONE_AND_ZEROS = MBEDTLS_PADDING_ONE_AND_ZEROS, /**< ISO/IEC 7816-4 padding.         */
    ZEROS_AND_LEN = MBEDTLS_PADDING_ZEROS_AND_LEN, /**< ANSI X.923 padding.             */
    ZEROS = MBEDTLS_PADDING_ZEROS,                 /**< Zero padding (not reversible). */
    NONE = MBEDTLS_PADDING_NONE,                     /**< Never pad (full blocks only).   */
};

class Random {
    mbedtls_entropy_context _entropy{};
    mbedtls_ctr_drbg_context _ctr_drbg{};

public:
    Random() : Random("some_random_sequence") {}

    explicit Random(const std::string& salt) {
        mbedtls_entropy_init( &_entropy );
        mbedtls_ctr_drbg_init( &_ctr_drbg );

        auto *temp = (const unsigned char *) salt.c_str();
        if( mbedtls_ctr_drbg_seed( &_ctr_drbg, mbedtls_entropy_func, &_entropy, temp, salt.length()) != 0 ) {
            throw std::runtime_error("Could not init seed.");
        }
        mbedtls_ctr_drbg_set_prediction_resistance( &_ctr_drbg, MBEDTLS_CTR_DRBG_PR_OFF );
    }

    Random(const Random& other) = delete;
    Random&operator=(const Random& other) = delete;

    template <size_t N>
    std::vector<unsigned char> get() {
        unsigned char data[N];
        if (mbedtls_ctr_drbg_random( &_ctr_drbg, data, N) != 0) {
            throw std::runtime_error("Could not generate random sequence.");
        }
        return std::vector<unsigned char>(data, data + N);
    }

    ~Random() {
        mbedtls_ctr_drbg_free( &_ctr_drbg );
        mbedtls_entropy_free( &_entropy );
    }
};

//length in BYTES
template <int KeyLen, int IVlen>
class CipherWrapper {
    //bitMASK
    unsigned char OK = 0x00;
    const mbedtls_cipher_info_t *_info;
    mbedtls_cipher_context_t _context{};

public:
    explicit CipherWrapper(mbedtls_cipher_type_t type) : _info(mbedtls_cipher_info_from_type(type)) {
        mbedtls_cipher_setup(&_context, _info);
    }

    ~CipherWrapper() {
        mbedtls_cipher_free( &_context );
    }

    CipherWrapper(const CipherWrapper& other) = delete;
    CipherWrapper&operator=(const CipherWrapper& other) = delete;

    void setInitVector(const unsigned char* vector, size_t len) {
        if (len != IVlen) {
            std::cerr << "Invalid init vector length.\n";
            return;
        }
        if (mbedtls_cipher_set_iv(&_context, vector, len) != 0) {
            throw std::runtime_error("Failed to initialize init vector - unable to continue.");
        }
        OK |= 0x01;
    }

    void reset() {
        if (mbedtls_cipher_reset(&_context) != 0) {
            std::cerr << "Failed to reset cipher context\n";
        }
    }

    void setKey(unsigned char* key, size_t len, mbedtls_operation_t mode) {
        if (len != KeyLen) {
            std::cerr << "Invalid key length.\n";
            return;
        }
        if (mbedtls_cipher_setkey(&_context, key, KeyLen * 8, mode) != 0) {
            throw std::runtime_error("Failed to initialize AES key - unable to continue.");
        }
        OK |= 0x02;
    }

    //******************
    //ONLY THESE ARE NEEDED
    //*****************
    void init(unsigned char* key, size_t len, Operation mode) {
        reset();
        setKey(key, len, static_cast<mbedtls_operation_t>(mode));
        std::cout << "Note: using zero filled init vector.\n";
    }

    void init(unsigned char* key, size_t len, Operation mode, Padding padding) {
        reset();
        mbedtls_cipher_set_padding_mode(&_context, static_cast<mbedtls_cipher_padding_t>(padding));
        setKey(key, len,  static_cast<mbedtls_operation_t>(mode) );
        std::cout << "Note: using zero filled init vector.\n";
    }

    void init(unsigned char* key, size_t key_len, const unsigned char* vector, size_t vec_len, Operation mode) {
        reset();
        setInitVector(vector, vec_len);
        setKey(key, key_len, static_cast<mbedtls_operation_t>(mode));
    }

    void init(unsigned char* key, size_t key_len, const unsigned char* vector, size_t vec_len, Operation mode, Padding padding) {
        reset();
        mbedtls_cipher_set_padding_mode(&_context, static_cast<mbedtls_cipher_padding_t>(padding));
        setInitVector(vector, vec_len);
        setKey(key, key_len, static_cast<mbedtls_operation_t>(mode));
    }

    void feed(unsigned char* data, size_t dataLen, unsigned char* result, size_t* result_len) {
        if (! (OK & 0x02) ) {
            throw std::runtime_error("Cipher not initialized properly.");
        }
        if (mbedtls_cipher_update(&_context, data, dataLen, result, result_len) != 0) {
            throw std::runtime_error("Failed to update cipher.");
        }
    }

    void finish(unsigned char* result, size_t* result_len) {
        if (mbedtls_cipher_finish(&_context, result, result_len) != 0) {
            throw std::runtime_error("Failed to finish cipher.");
        }
    }

    //** MORE C++ like approach

    void init(const std::vector<unsigned char>& key, Operation mode) {
        reset();
        setKey(key.data(), key.size(), static_cast<mbedtls_operation_t>(mode));
        std::cout << "Note: using zero filled init vector.\n";
    }

    void init(const std::vector<unsigned char>& key, Operation mode, Padding padding) {
        reset();
        mbedtls_cipher_set_padding_mode(&_context, static_cast<mbedtls_cipher_padding_t>(padding));
        setKey(key.data(), key.size(), static_cast<mbedtls_operation_t>(mode));
        std::cout << "Note: using zero filled init vector.\n";
    }

    void init(const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv, Operation mode) {
        reset();
        setInitVector(iv.data(), iv.size());
        setKey(key.data(), key.size(), static_cast<mbedtls_operation_t>(mode));
    }

    void init(const std::vector<unsigned char>& key, const std::vector<unsigned char>& iv, Operation mode, Padding padding) {
        reset();
        mbedtls_cipher_set_padding_mode(&_context, static_cast<mbedtls_cipher_padding_t>(padding));
        setInitVector(iv.data(), iv.size());
        setKey(key.data(), key.size(), static_cast<mbedtls_operation_t>(mode));
    }

    std::vector<unsigned char> feed(const std::vector<unsigned char>& data) {
        if (! (OK & 0x02) ) {
            throw std::runtime_error("Cipher not initialized properly.");
        }
        unsigned char output[data.size() + IVlen]{};
        size_t out_len;
        if (mbedtls_cipher_update(&_context, data.data(), data.size(), output, &out_len) != 0) {
            throw std::runtime_error("Failed to update cipher.");
        }
        return std::vector<unsigned char>(output, out_len);
    }

    std::vector<unsigned char> finish() {
        unsigned char output[2 * IVlen]{};
        size_t out_len;
        if (mbedtls_cipher_finish(&_context, output, &out_len) != 0) {
            throw std::runtime_error("Failed to finish cipher.");
        }
        return std::vector<unsigned char>(output, out_len);
    }
};

#endif //PB173_CIPHERWRAPPER_H
