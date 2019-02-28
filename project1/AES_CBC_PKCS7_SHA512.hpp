//
// Created by horak_000 on 26. 2. 2019.
//

#ifndef PB173_AES_CBC_PKCS7_H
#define PB173_AES_CBC_PKCS7_H

#include <ostream>
#include <vector>
#include <fstream>


#include "CipherWrapper.hpp"
#include "SHAWrapper.hpp"
#include "Print.hpp"

template<size_t len>
size_t read_n(std::istream &in, unsigned char *data) {
    //char temp[len];
    in.read((char *) data, len);
    //the "nice way"
//    std::transform(temp, temp + len, data, [](const char &c) {
//        return static_cast<unsigned char>(c);
//    });
    return static_cast<size_t>(in.gcount());
}

void write_n(std::ostream &, unsigned char *, size_t);

std::string hash_sha512(std::istream &);

bool verify_sha512(std::istream &, std::ostream &, const std::string &);

void encrypt(std::istream &, std::ostream &, const std::string &, const std::string &, Padding, bool, std::ostream&);

void decrypt(std::istream &, std::ostream &, const std::string &, const std::string &, Padding, bool);

void get16byte(unsigned char *, const std::string &);

//to exclude main from testing
int app(int, const std::vector<std::string> &, std::ostream&);

#endif //PB173_AES_CBC_PKCS7_H
