//
// Created by horak_000 on 19. 2. 2019.
//

#include <ostream>
#include <vector>
#include <fstream>
#include <cstring>
#include <algorithm>

#include "mbedtls/sha512.h"

#include "CipherWrapper.h"
#include "Print.hpp"
#include "HexUtils.h"

template<size_t len>
size_t read_n(std::ifstream &in, unsigned char *data) {
    char temp[len];
    in.read(temp, len);
    std::transform(temp, temp + len, data, [](const char &c) {
        return static_cast<unsigned char>(c);
    });
    return static_cast<size_t >(in.gcount());
}

void save_n(std::ofstream &out, unsigned char *data, size_t n) {
    out.write((char *) data, n);
}

std::string hash_sha512(std::ifstream &in) {
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
    return HexUtils::char_to_hex(result, 64);
}

bool verify_sha512(std::ifstream &in, std::ofstream &out, const std::string &hash) {
    std::string hash_new = hash_sha512(in);
    out << "Computed hash: " << hash_new << std::endl;
    out << "Given hash:    " << hash << std::endl;
    return hash_sha512(in) == hash;
}

void encrypt(std::ifstream &in, std::ofstream &out, unsigned char key[16], unsigned char vector[16]) {
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
        save_n(out, output, out_len);
    }
    unsigned char fin[16];
    size_t fin_len;
    wrapper.finish(fin, &fin_len);
    save_n(out, fin, fin_len);
}

void decrypt(std::ifstream &in, std::ofstream &out, unsigned char key[16], unsigned char iv[16]) {
    CipherWrapper<16, 16> wrapper{MBEDTLS_CIPHER_AES_128_CBC};
    wrapper.init(key, 16, iv, 16, Operation::DECRYPT, Padding::PKCS7);
    while (in.good()) {
        unsigned char input[256];
        size_t in_len = read_n<256>(in, input);
        unsigned char output[272]{}; //256 + block size length
        size_t out_len;

        wrapper.feed(input, in_len, output, &out_len);
        save_n(out, output, out_len);
    }
    unsigned char fin[16];
    size_t fin_len;
    wrapper.finish(fin, &fin_len);
    save_n(out, fin, fin_len);
}

void get16byte(unsigned char *out, const std::string &source) {
    if (source.length() != 32) {
        throw std::runtime_error("Wrong key or init vector - must be 16 bytes, e.g. 32 hex chars.\n");
    }
    HexUtils::hex_to_char(source, out);
}

int main(int argc, char *argv[]) {
    std::vector<CommandLineArgument> appArgs = {
            CommandLineArgument{'h', "help", "\tshow help", false},
            CommandLineArgument{'e', "encrypt", "\tencyrpt given file using AES", false},
            CommandLineArgument{'d', "decrypt", "\tdecrypt file using AES", false},
            CommandLineArgument{'s', "hash", "\tcreate hash", false},
            CommandLineArgument{'v', "verify", "\tverify hash, value: hash to compare", true},
            CommandLineArgument{'r', "random", "\tgenerate random initialization vector, for encryption only", false}
    };

    ApplicationHelp a{"Crypto-project", "Jiří Horák", "description", appArgs, ApplicationVersion{1, 0},
                      "command template: [input file] [output file] [action] [cipher: key 16 bytes, / hash: hash to compare | in hex string] [cipher only: init vector (will use zeros if not present) OR --rand for encryption only]"};
    using namespace std;

    if (argc < 3) {
        printApplicationHelp(a, cout);
        return 0;
    }

    vector<string> args(argv, argv + argc);
    ifstream in{args[1]};
    if (!in.is_open()) {
        cout << "Failed to open " << args[1] << '\n';
        return 1;
    }

    ofstream out{args[2]}; //std::ios::binary
    unsigned char key[16]{};
    const string &action = args[3];

    if (action == "-e" || action == "--encrypt") {
        if (argc < 5) {
            cerr << "Key is missing.\n";
            return 1;
        }
        get16byte(key, args[4]);
        unsigned char iv[16]{};
        if (argc == 6) {
            //given IV - generate random or get from console
            if (args[5] == "-r" || args[5] == "--rand") {
                encrypt(in, out, key, nullptr);
            } else {
                //parse IV
                get16byte(iv, args[5]);
                encrypt(in, out, key, iv);
            }
        } else {
            //zeros
            cout << "No valid IV given, will use zeros.";
            encrypt(in, out, key, iv);
        }

    } else if (action == "-d" || action == "--decrypt") {
        if (argc < 5) {
            cerr << "Key is missing or too many arguments given.\n";
            return 1;
        }
        get16byte(key, args[4]);

        unsigned char random_vector[16]{};
        if (argc == 6) {
            if (args[5].length() != 32) {
                std::cerr << "Invalid IV lenght - expected 16 bytes, e.g 32 hex chars.";
                return 1;
            }
            HexUtils::hex_to_char(args[5], random_vector);
        } else {
            std::cout << "No valid IV given, will use zeros.";
        }
        decrypt(in, out, key, random_vector);

    } else if (action == "-s" || action == "--hash") {
        string hash = hash_sha512(in);
        cout << hash;
    } else if (action == "-v" || action == "--verify") {
        if (argc != 5) {
            cerr << "Hash to compare is missing or too many arguments given.\n";
            return 1;
        }
        if (!verify_sha512(in, out, args[4])) {
            cout << "Verification failed: given hash does not match.\n";
        } else {
            cout << "Verification successful.\n";
        }
    } else if (action == "-h" || action == "--help") {
        printApplicationHelp(a, cout);
    }
}
