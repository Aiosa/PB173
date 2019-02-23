//
// Created by horak_000 on 19. 2. 2019.
//

#include <ostream>
#include <vector>
#include <fstream>
#include <cstring>
#include <algorithm>

#include "Print.hpp"

#include "mbedtls/cipher.h"
#include "mbedtls/sha512.h"
#include "mbedtls/ctr_drbg.h"
#include "mbedtls/entropy.h"

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
//ugly
//    while (n > 0) {
//        out.write((char *) data++, 1);
//        --n;
//    }
    out.write((char *) data, n);
}


std::string hex_from_byte(unsigned char value) {
    switch (value) {
        case 0x0:
            return "0";
        case 0x1:
            return "1";
        case 0x2:
            return "2";
        case 0x3:
            return "3";
        case 0x4:
            return "4";
        case 0x5:
            return "5";
        case 0x6:
            return "6";
        case 0x7:
            return "7";
        case 0x8:
            return "8";
        case 0x9:
            return "9";
        case 0xA:
            return "A";
        case 0xB:
            return "B";
        case 0xC:
            return "C";
        case 0xD:
            return "D";
        case 0xE:
            return "E";
        case 0xF:
            return "F";
        default:
            return "";
    }
}

unsigned char byte_from_hex(char hex) {
    switch (hex) {
        case '0':
            return 0x0;
        case '1':
            return 0x1;
        case '2':
            return 0x2;
        case '3':
            return 0x3;
        case '4':
            return 0x4;
        case '5':
            return 0x5;
        case '6':
            return 0x6;
        case '7':
            return 0x7;
        case '8':
            return 0x8;
        case '9':
            return 0x9;
        case 'A':
            return 0xA;
        case 'B':
            return 0xB;
        case 'C':
            return 0xC;
        case 'D':
            return 0xD;
        case 'E':
            return 0xE;
        case 'F':
            return 0xF;
        default:
            return 0x0;
    }
}

std::string char_to_hex(const unsigned char* buff, size_t ilen) {
    std::string res;
    for (size_t i = 0; i < ilen; i++) {
        res += hex_from_byte(*(buff + i) >> 4) + hex_from_byte(*(buff + i) & (unsigned char)0x0F);
    }
    return res;
}

//out must be at least hex / 2 bytes long
void hex_to_char(const std::string& hex, unsigned char* out) {
    if (hex.length() % 2 == 1) {
        std::cerr << "Invalid conversion from even length hex string.";
        return;
    }
    for (size_t i = 0; i < hex.length(); i++) {
        out[i / 2] = byte_from_hex(hex[i]) << 4 | byte_from_hex(hex[++i]);
    }
}

std::string hash_sha512(std::ifstream& in) {
    mbedtls_sha512_context context;

    mbedtls_sha512_init(&context);
    mbedtls_sha512_starts_ret(&context, 0); //SHA-512 constant missing - 0

    while (in.good()) {
        unsigned char input[256];
        size_t in_len = read_n<256>(in, input);
        if (mbedtls_sha512_update_ret(&context, input, in_len) != 0){
            std::cerr << "Fail";
            return "Failed";
        }
    }

    unsigned char result[64];
    if (mbedtls_sha512_finish_ret(&context, result) != 0){
        std::cerr << "Fail";
        return "Failed";
    }
    return char_to_hex(result, 64);
}

bool verify_sha512(std::ifstream& in, std::ofstream& out, const std::string& hash) {
    std::string hash_new = hash_sha512(in);
    out << "Computed hash: " << hash_new << std::endl;
    out << "Given hash:    " << hash << std::endl;
    return hash_sha512(in) == hash;
}

void getIV() {
    //init here doesnt matter cause its used only once anyway
    mbedtls_entropy_context entropy;
    mbedtls_entropy_init( &entropy );

    mbedtls_ctr_drbg_context ctr_drbg;

    std::string rand{"some_random_sequence"};
    //unsafe, but we use C library anyway
    const unsigned char *salt = (const unsigned char *) rand.c_str();
    mbedtls_ctr_drbg_init( &ctr_drbg );

    if( mbedtls_ctr_drbg_seed( &ctr_drbg , mbedtls_entropy_func, &entropy, salt, rand.length() ) != 0 ) {
        std::cerr << "Failed to generate random initialization vector. Will use zeros.";
    }
}


void encrypt(std::ifstream &in, std::ofstream &out, unsigned char key[16]) {
    unsigned char random_vector[16]{};

    //cipher description
    const mbedtls_cipher_info_t *info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CBC);
    mbedtls_cipher_context_t context;
    //setup context
    mbedtls_cipher_setup(&context, info);
    mbedtls_cipher_set_padding_mode(&context, MBEDTLS_PADDING_PKCS7); //sichr

    if (mbedtls_cipher_set_iv(&context, random_vector, 16)) {
        std::cerr << "Failed to initialize init vector - unable to continue. Closing...";
        return;
    }
    if (mbedtls_cipher_reset(&context)) {
        std::cerr << "Failed to reset cipher context. Closing...";
        return;
    }
    if (mbedtls_cipher_setkey(&context, key, 16 * 8, MBEDTLS_ENCRYPT)) {
        std::cerr << "Failed to initialize AES key - unable to continue. Closing...";
        return;
    }

    while (in.good()) {
        unsigned char input[256];
        size_t in_len = read_n<256>(in, input);
        unsigned char output[272]{}; //256 + block size length
        size_t out_len;
        int res = mbedtls_cipher_update(&context, input, in_len, output, &out_len);
        if (res != 0) {
            std::cerr << "Failed to update cipher. NOTE: inconsistent data written into output. Closing...";
            return;
        }
        //std::cout << char_to_hex(output, out_len) << "\n";
        save_n(out, output, out_len);
    }

    unsigned char fin[16];
    size_t fin_len;
    mbedtls_cipher_finish(&context, fin, &fin_len);
    //std::cout << "finish: " << char_to_hex(fin, fin_len);
    save_n(out, fin, fin_len);
}

void decrypt(std::ifstream &in, std::ofstream &out, unsigned char key[16], unsigned char iv[16]) {
    //cipher description
    const mbedtls_cipher_info_t *info = mbedtls_cipher_info_from_type(MBEDTLS_CIPHER_AES_128_CBC);
    mbedtls_cipher_context_t context;
    //setup context
    mbedtls_cipher_setup(&context, info);
    mbedtls_cipher_set_padding_mode(&context, MBEDTLS_PADDING_PKCS7); //sichr

    if (mbedtls_cipher_set_iv(&context, iv, 16)) {
        std::cerr << "Failed to initialize init vector - unable to continue. Closing...";
        return;
    }
    if (mbedtls_cipher_reset(&context)) {
        std::cerr << "Failed to reset cipher context. Closing...";
        return;
    }
    if (mbedtls_cipher_setkey(&context, key, 16 * 8, MBEDTLS_DECRYPT)) {
        std::cerr << "Failed to initialize AES key - unable to continue. Closing...";
        return;
    }

    while (in.good()) {
        unsigned char input[256];
        size_t in_len = read_n<256>(in, input);

        unsigned char output[272]{}; //input len + block size 256 + 16
        size_t out_len;
        if (mbedtls_cipher_update(&context, input, in_len, output, &out_len) != 0) {
            std::cerr << "Failed to update cipher. NOTE: inconsistent data written into output. Closing...";
            return;
        }
        save_n(out, output, out_len);
    }
    unsigned char fin[16];
    size_t fin_len;
    mbedtls_cipher_finish(&context, fin, &fin_len);
    save_n(out, fin, fin_len);
}

int getKey(unsigned char* key, const std::string& keySource) {
    if (keySource.length() != 32) {
        std::cerr << "Wrong key length - it must be exactly 16 chars long.\n";
        return 1;
    }
    hex_to_char(keySource, key);
    return 0;
}

int main(int argc, char *argv[]) {
    std::vector<CommandLineArgument> appArgs = {
            CommandLineArgument{'h', "help", "\tshow help", false},
            CommandLineArgument{'e', "encrypt", "\tencyrpt given file using AES", false},
            CommandLineArgument{'d', "decrypt", "\tdecrypt file using AES", false},
            CommandLineArgument{'s', "hash", "\tcreate hash", false},
            CommandLineArgument{'v', "verify", "\tverify hash, value: hash to compare", true},
    };

    ApplicationHelp a{"Crypto-project", "Jiří Horák", "description", appArgs, ApplicationVersion{1, 0},
                      "command template: [input file] [output file] [action] [optional: key 16 bytes / hash to compare, both in hex string!] [optional: IV for decryption (will use zeros of not given)] (max 1 for each)"};
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
        if (argc != 5) {
            cerr << "Key is missing or too many arguments given.\n";
            return 1;
        }
        if (getKey(key, args[4]) != 0) {
            cerr << "Skipping encryption, invalid key.";
        } else {
            encrypt(in, out, key);
        }

    } else if (action == "-d" || action == "--decrypt") {
        if (argc < 5) {
            cerr << "Key is missing or too many arguments given.\n";
            return 1;
        }
        if (getKey(key, args[4]) != 0) {
            cerr << "Skipping decryption, invalid key.";
        } else {
            unsigned char random_vector[16]{};
            if (argc == 6) {
                if (args[5].length() != 32) {
                    std::cerr << "Invalid IV lenght - expected 16 bytes, e.g 32 hex chars.";
                    return 1;
                }
                hex_to_char(args[5], random_vector);
            } else {
                std::cout << "No IV given, using zeros.";
            }
            decrypt(in, out, key, random_vector);
        }
    } else if (action == "-s" || action == "--hash") {
        string hash = hash_sha512(in);
        out << hash;
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

