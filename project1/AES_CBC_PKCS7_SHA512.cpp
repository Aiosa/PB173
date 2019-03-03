//
// Created by horak_000 on 26. 2. 2019.
//
#include "AES_CBC_PKCS7_SHA512.hpp"

void write_n(std::ostream &out, unsigned char *data, size_t length) {
    out.write((char *) data, length);
}

std::string hash_sha512(std::istream &in) {
    SHAWrapper wrapper{SHA::S512};

    while (in.good()) {
        unsigned char input[256];
        size_t in_len = read_n<256>(in, input);
        wrapper.feed(input, in_len);
    }

    return wrapper.finish();
}

bool verify_sha512(std::istream &in, std::ostream &out, const std::string &hash) {
    std::string hash_new = hash_sha512(in);
    out << "Computed hash: " << hash_new << std::endl;
    out << "Given hash:    " << hash << std::endl;
    return hash_sha512(in) == hash;
}

void encrypt(std::istream &in, std::ostream &out,
             const std::string& key, const std::string& iv,
             Padding padding, bool hex, std::ostream& cout) {

    unsigned char key_bytes[16];
    get16byte(key_bytes, key);

    CipherWrapper<16, 16> wrapper{MBEDTLS_CIPHER_AES_128_CBC};

    if (iv.empty()) {
        Random random{};
        std::vector<unsigned char> new_iv = random.get<16>();
        wrapper.init(key_bytes, 16, new_iv.data(), 16, Operation::ENCRYPT, padding);
        cout << HexUtils::bin_to_hex(new_iv.data(), new_iv.size());
    } else {
        unsigned char iv_bytes[16];
        get16byte(iv_bytes, iv);
        wrapper.init(key_bytes, 16, iv_bytes, 16, Operation::ENCRYPT, padding);
    }

    while (in.good()) {
        unsigned char input[256];
        size_t in_len = read_n<256>(in, input);
        unsigned char output[272]{}; //256 + block size length
        size_t out_len;

        wrapper.feed(input, in_len, output, &out_len);
        if (hex)
            out << HexUtils::bin_to_hex(output, out_len);
        else
            write_n(out, output, out_len);
    }
    unsigned char fin[16];
    size_t fin_len;
    wrapper.finish(fin, &fin_len);
    if (hex) {
        out << HexUtils::bin_to_hex(fin, fin_len);
    } else {
        write_n(out, fin, fin_len);
    }

}

void decrypt(std::istream &in, std::ostream &out,
             const std::string& key, const std::string& iv,
             Padding padding, bool hex) {

    unsigned char key_bytes[16];
    get16byte(key_bytes, key);
    unsigned char iv_bytes[16];
    get16byte(iv_bytes, iv);

    CipherWrapper<16, 16> wrapper{MBEDTLS_CIPHER_AES_128_CBC};
    wrapper.init(key_bytes, 16, iv_bytes, 16, Operation::DECRYPT, padding);
    while (in.good()) {
        unsigned char input[256];
        size_t in_len = read_n<256>(in, input);
        unsigned char output[272]{}; //256 + block size length
        size_t out_len;

        if (hex) {
            unsigned char data_bin[128];
            HexUtils::hex_to_bin(input, in_len, data_bin, in_len / 2);
            wrapper.feed(data_bin, in_len / 2, output, &out_len);
        } else {
            wrapper.feed(input, in_len, output, &out_len);
        }
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

int app(int argc, const std::vector<std::string>& args, std::ostream& cout) {

    std::vector<CommandLineArgument> appArgs = {
            CommandLineArgument{'h', "help", "\tshow help", false},
            CommandLineArgument{'e', "encrypt", "\tencrypt given file using AES", false},
            CommandLineArgument{'d', "decrypt", "\tdecrypt file using AES", false},
            CommandLineArgument{'s', "hash", "\tcreate hash", false},
            CommandLineArgument{'v', "verify", "\tverify hash, value: hash to compare", true},
            CommandLineArgument{'r', "rand", "\tgenerate random initialization vector, for encryption only", false}
    };

    ApplicationHelp a{"Crypto-project", "Jiří Horák", "description", appArgs, ApplicationVersion{1, 0},
                      "command template: [input file] [output file] [action] [key 16 bytes (cipher) / hash to compare (verify) | in hex string] [cipher only: init vector (use zeros if not present) OR --rand for encryption only]"};

    if (argc < 3) {
        printApplicationHelp(a, cout);
        return 0;
    }

    std::ifstream in{args[1], std::ios::binary | std::ios::in};
    if (!in.is_open()) {
        std::cerr << "Failed to open " << args[1] << '\n';
        return 1;
    }
    if (!in.good()) {
        std::cerr << "Failed to read from file " << args[1] << '\n';
        return 1;
    }

    std::ofstream out{args[2], std::ios::binary | std::ios::out};
    if (!out.is_open()) {
        std::cerr << "Failed to write into file " << args[1] << '\n';
        return 1;
    }

    const  std::string &action = args[3];

    if (action == "-e" || action == "--encrypt") {
        if (argc < 5) {
            std::cerr << "Key is missing.\n";
            return 1;
        }

        if (argc == 6) {
            //given IV - generate random or get from console
            if (args[5] == "-r" || args[5] == "--rand") {
                encrypt(in, out, args[4], "", Padding::PKCS7, false, cout);
            } else {
                encrypt(in, out, args[4], args[5], Padding::PKCS7, false, cout);
            }
        } else {
            //zeros
            std::cerr << "No valid IV given, will use zeros.\n";
            encrypt(in, out, args[4], "00000000000000000000000000000000", Padding::PKCS7, false, cout);
        }

    } else if (action == "-d" || action == "--decrypt") {
        if (argc < 5) {
            std::cerr << "Key is missing or too many arguments given.\n";
            return 1;
        }
        if (argc == 6) {
            decrypt(in, out, args[4], args[5], Padding::PKCS7, false);
        } else {
            std::cerr << "No valid IV given, will use zeros.\n";
            decrypt(in, out, args[4], "00000000000000000000000000000000", Padding::PKCS7, false);
        }

    } else if (action == "-s" || action == "--hash") {
        std::string hash = hash_sha512(in);
        cout << hash;
    } else if (action == "-v" || action == "--verify") {
        if (argc != 5) {
            std::cerr << "Hash to compare is missing or too many arguments given.\n";
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
    return 0;
}
