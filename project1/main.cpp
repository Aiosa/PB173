//
// Created by horak_000 on 19. 2. 2019.
//

#include "Print.hpp"
#include "AES_CBC_PKCS7_SHA512.hpp"

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
            HexUtils::hex_to_bin(args[5], random_vector);
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
