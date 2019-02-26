//
// Created by horak_000 on 26. 2. 2019.
//

#ifndef PB173_AES_CBC_PKCS7_H
#define PB173_AES_CBC_PKCS7_H

#include <ostream>
#include <vector>
#include <fstream>
#include <cstring>
#include <algorithm>

#include "mbedtls/sha512.h"

#include "CipherWrapper.hpp"
#include "HexUtils.hpp"

template<size_t len>
size_t read_n(std::istream &in, unsigned char *data) {
    char temp[len];
    in.read(temp, len);
    std::transform(temp, temp + len, data, [](const char &c) {
        return static_cast<unsigned char>(c);
    });
    return static_cast<size_t >(in.gcount());
}

void write_n(std::ostream &out, unsigned char *data, int length);

std::string hash_sha512(std::istream &in);

bool verify_sha512(std::istream &in, std::ostream &out, const std::string &hash);

void encrypt(std::istream &in, std::ostream &out, unsigned char key[16], unsigned char vector[16]);

void decrypt(std::istream &in, std::ostream &out, unsigned char key[16], unsigned char iv[16]);

void get16byte(unsigned char *out, const std::string &source);

#endif //PB173_AES_CBC_PKCS7_H
