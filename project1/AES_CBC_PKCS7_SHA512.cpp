//
// Created by horak_000 on 26. 2. 2019.
//
#include "AES_CBC_PKCS7_SHA512.hpp"

void write_n(std::ostream &out, unsigned char *data, size_t length) {
    out.write((char *) data, length);
}

std::string hash_sha512(std::istream &in) {
    mbedtls_sha512_context context;

    mbedtls_sha512_init(&context);
    mbedtls_sha512_starts_ret(&context, 0); //SHA-512 constant missing - 0

    while (in.good()) {
        unsigned char input[256];
        size_t in_len = read_n<256>(in, input);
        if (mbedtls_sha512_update_ret(&context, input, in_len) != 0) {
            std::cerr << "Fail";
            return "Failed";
        }
    }

    unsigned char result[64];
    if (mbedtls_sha512_finish_ret(&context, result) != 0) {
        std::cerr << "Fail";
        return "Failed";
    }
    mbedtls_sha512_free(&context);
    return HexUtils::bin_to_hex(result, 64);
}

bool verify_sha512(std::istream &in, std::ostream &out, const std::string &hash) {
    std::string hash_new = hash_sha512(in);
    out << "Computed hash: " << hash_new << std::endl;
    out << "Given hash:    " << hash << std::endl;
    return hash_sha512(in) == hash;
}

void encrypt(std::istream &in, std::ostream &out, unsigned char key[16], unsigned char vector[16]) {
    CipherWrapper<16, 16> wrapper{MBEDTLS_CIPHER_AES_128_CBC};

    if (vector == nullptr) {
        Random random{};
        std::vector<unsigned char> iv = random.get<16>();
        wrapper.init(key, 16, iv.data(), 16, Operation::ENCRYPT, Padding::PKCS7);
    } else {
        wrapper.init(key, 16, vector, 16, Operation::ENCRYPT, Padding::PKCS7);
    }
    while (in.good()) {
        unsigned char input[256];
        size_t in_len = read_n<256>(in, input);
        unsigned char output[272]{}; //256 + block size length
        size_t out_len;

        wrapper.feed(input, in_len, output, &out_len);
        write_n(out, output, out_len);
    }
    unsigned char fin[16];
    size_t fin_len;
    wrapper.finish(fin, &fin_len);
    write_n(out, fin, fin_len);
}

void decrypt(std::istream &in, std::ostream &out, unsigned char key[16], unsigned char iv[16]) {
    CipherWrapper<16, 16> wrapper{MBEDTLS_CIPHER_AES_128_CBC};
    wrapper.init(key, 16, iv, 16, Operation::DECRYPT, Padding::PKCS7);
    while (in.good()) {
        unsigned char input[256];
        size_t in_len = read_n<256>(in, input);
        unsigned char output[272]{}; //256 + block size length
        size_t out_len;

        wrapper.feed(input, in_len, output, &out_len);
        write_n(out, output, out_len);
    }
    unsigned char fin[16];
    size_t fin_len;
    wrapper.finish(fin, &fin_len);
    write_n(out, fin, fin_len);
}

void get16byte(unsigned char *out, const std::string &source) {
    if (source.length() != 32) {
        throw std::runtime_error("Wrong key or init vector - must be 16 bytes, e.g. 32 hex chars.\n");
    }
    HexUtils::hex_to_bin(source, out);
}
