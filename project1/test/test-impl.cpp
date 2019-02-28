#include "catch.hpp"

#include <sstream>

#include "../AES_CBC_PKCS7_SHA512.hpp"

TEST_CASE("HexUtils") {
    unsigned char data[16]{0x00, 0x01, 0x02, 0x03,
                           0x04, 0x05, 0x06, 0x07,
                           0x08, 0x09, 0xa1, 0xd2,
                           0x55, 0x6a, 0xff, 0x51};
    CHECK(HexUtils::bin_to_hex(data, 16) == "00010203040506070809A1D2556AFF51");
    unsigned char out[16]{};
    HexUtils::hex_to_bin("00010203040506070809A1D2556AFF51", out);
    for (int i = 0; i < 16; i++) {
        CHECK(out[i] == data[i]);
    }

    unsigned char bytes[16];
    HexUtils::hex_to_bin("6bc1bee22e409f96e93d7e117393172a", bytes);
    std::string original = HexUtils::bin_to_hex(bytes, 16);
    CHECK(original == HexUtils::toUpper("6bc1bee22e409f96e93d7e117393172a"));

    CHECK_THROWS_AS(HexUtils::hex_from_byte(240), std::runtime_error);
    CHECK_THROWS_AS(HexUtils::byte_from_hex('r'), std::runtime_error);
}

TEST_CASE("SHA-512") {
    //from https://www.di-mgt.com.au/sha_testvectors.html
    std::stringstream abc{"abc"};
    CHECK(hash_sha512(abc) == HexUtils::toUpper(
            "ddaf35a193617abacc417349ae204131"
            "12e6fa4e89a97ea20a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd"
            "454d4423643ce80e2a9ac94fa54ca49f")
    );

    std::stringstream empty{""};
    CHECK(hash_sha512(empty) == HexUtils::toUpper(
            "cf83e1357eefb8bdf1542850d66d8007"
            "d620e4050b5715dc83f4a921d36ce9ce"
            "47d0d13c5d85f2b0ff8318d2877eec2f"
            "63b931bd47417a81a538327af927da3e")
    );

    std::stringstream alphabet{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"};
    CHECK(hash_sha512(alphabet) == HexUtils::toUpper(
            "204a8fc6dda82f0a0ced7beb8e08a416"
            "57c16ef468b228a8279be331a703c335"
            "96fd15c13b1b07f9aa1d3bea57789ca0"
            "31ad85c7a71dd70354ec631238ca3445")
    );

    std::stringstream alphabet2{
            "abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"};
    CHECK(hash_sha512(alphabet2) == HexUtils::toUpper(
            "8e959b75dae313da8cf4f72814fc143f"
            "8f7779c6eb9f7fa17299aeadb6889018"
            "501d289e4900f7e4331b99dec4b5433a"
            "c7d329eeb6dd26545e96e55b874be909")
    );

    std::stringstream billion_a{std::string(1000000, 'a')};
    CHECK(hash_sha512(billion_a) == HexUtils::toUpper(
            "e718483d0ce769644e2e42c7bc15b463"
            "8e1f98b13b2044285632a803afa973eb"
            "de0ff244877ea60a4cb0432ce577c31b"
            "eb009c5c2c49aa2e4eadb217ad8cc09b")
    );
}

TEST_CASE("ENCRYPT: AES-128 | CBC | 16 byte msg | PADDING none | hex output") {

    std::string iv;
    std::string key;
    std::stringstream input;
    std::string result;

    SECTION("IV 00000000000000000000000000000000 | "
            "MSG 00000000000000000000000000000000 | "
            "KEY 80000000000000000000000000000000") {

        iv = "00000000000000000000000000000000";
        key = "80000000000000000000000000000000";
        unsigned char bytes[16];
        HexUtils::hex_to_bin(HexUtils::toUpper("00000000000000000000000000000000"), bytes);
        input.write((char *) bytes, 16);
        result = "0edd33d3c621e546455bd8ba1418bec8";
    }

    SECTION("IV 000102030405060708090A0B0C0D0E0F | "
            "MSG 6bc1bee22e409f96e93d7e117393172a | "
            "KEY 2b7e151628aed2a6abf7158809cf4f3c") {

        iv = "000102030405060708090A0B0C0D0E0F";
        key = "2b7e151628aed2a6abf7158809cf4f3c";
        unsigned char bytes[16];
        HexUtils::hex_to_bin(HexUtils::toUpper("6bc1bee22e409f96e93d7e117393172a"), bytes);
        input.write((char *) bytes, 16);
        result = "7649abac8119b246cee98e9b12e9197d";
    }

    SECTION("IV 73bed6b8e3c1743b7116e69e22229516 | "
            "MSG f69f2445df4f9b17ad2b417be66c3710 | "
            "KEY 2b7e151628aed2a6abf7158809cf4f3c") {

        iv = "73bed6b8e3c1743b7116e69e22229516";
        key = "2b7e151628aed2a6abf7158809cf4f3c";
        unsigned char bytes[16];
        HexUtils::hex_to_bin(HexUtils::toUpper("f69f2445df4f9b17ad2b417be66c3710"), bytes);
        input.write((char *) bytes, 16);
        result = "3ff1caa1681fac09120eca307586e1a7";
    }

    std::stringstream output;
    encrypt(input, output, key, iv, Padding::NONE, true);
    CHECK(output.str() == HexUtils::toUpper(result));
}

TEST_CASE("ENCRYPT: AES-128 | CBC | 16 byte msg | PADDING none | bin output") {

    std::string iv;
    std::string key;
    std::stringstream input;
    std::string result;

    SECTION("IV 00000000000000000000000000000000 | "
            "MSG 00000000000000000000000000000000 | "
            "KEY 80000000000000000000000000000000") {

        iv = "00000000000000000000000000000000";
        key = "80000000000000000000000000000000";
        unsigned char bytes[16];
        HexUtils::hex_to_bin(HexUtils::toUpper("00000000000000000000000000000000"), bytes);
        input.write((char *) bytes, 16);
        result = "0edd33d3c621e546455bd8ba1418bec8";
    }

    SECTION("IV 000102030405060708090A0B0C0D0E0F | "
            "MSG 6bc1bee22e409f96e93d7e117393172a | "
            "KEY 2b7e151628aed2a6abf7158809cf4f3c") {

        iv = "000102030405060708090A0B0C0D0E0F";
        key = "2b7e151628aed2a6abf7158809cf4f3c";
        unsigned char bytes[16];
        HexUtils::hex_to_bin(HexUtils::toUpper("6bc1bee22e409f96e93d7e117393172a"), bytes);
        input.write((char *) bytes, 16);
        result = "7649abac8119b246cee98e9b12e9197d";
    }

    SECTION("IV 73bed6b8e3c1743b7116e69e22229516 | "
            "MSG f69f2445df4f9b17ad2b417be66c3710 | "
            "KEY 2b7e151628aed2a6abf7158809cf4f3c") {

        iv = "73bed6b8e3c1743b7116e69e22229516";
        key = "2b7e151628aed2a6abf7158809cf4f3c";
        unsigned char bytes[16];
        HexUtils::hex_to_bin(HexUtils::toUpper("f69f2445df4f9b17ad2b417be66c3710"), bytes);
        input.write((char *) bytes, 16);
        result = "3ff1caa1681fac09120eca307586e1a7";
    }

    std::stringstream output;
    encrypt(input, output, key, iv, Padding::NONE, false);
    CHECK(HexUtils::bin_to_hex(output.str()) == HexUtils::toUpper(result));
}

TEST_CASE("DECRYPT: AES-128 | CBC | 16 byte msg | PADDING none | hex input") {

    std::string iv;
    std::string key;
    std::stringstream input;
    std::string result;

    SECTION("IV 000102030405060708090a0b0c0d0e0f | "
            "CIPHER 7649abac8119b246cee98e9b12e9197d | "
            "KEY 2b7e151628aed2a6abf7158809cf4f3c") {

        iv = "000102030405060708090a0b0c0d0e0f";
        key = "2b7e151628aed2a6abf7158809cf4f3c";
        input = std::stringstream{"7649abac8119b246cee98e9b12e9197d"};
        result = "6bc1bee22e409f96e93d7e117393172a";
    }

    SECTION("IV 73bed6b8e3c1743b7116e69e22229516 | "
            "CIPHER 3ff1caa1681fac09120eca307586e1a7 | "
            "KEY 2b7e151628aed2a6abf7158809cf4f3c") {

        iv = "73bed6b8e3c1743b7116e69e22229516";
        key = "2b7e151628aed2a6abf7158809cf4f3c";
        input = std::stringstream{"3ff1caa1681fac09120eca307586e1a7"};
        result = "f69f2445df4f9b17ad2b417be66c3710";
    }

    std::stringstream output;
    decrypt(input, output, key, iv, Padding::NONE, true);
    //the result is in binary form, not interpretable as hex (it would be interpretable if we decrypted our own encrypted data)
    CHECK(HexUtils::bin_to_hex(output.str()) == HexUtils::toUpper(result));
}

TEST_CASE("DECRYPT: AES-128 | CBC | 16 byte msg | PADDING none | bin input") {

    std::string iv;
    std::string key;
    std::stringstream input;
    unsigned char cipher[16];

    std::string result;

    SECTION("IV 000102030405060708090A0B0C0D0E0F | "
            "CIPHER 7649abac8119b246cee98e9b12e9197d | "
            "KEY 2b7e151628aed2a6abf7158809cf4f3c") {

        iv = "000102030405060708090A0B0C0D0E0F";
        key = "2b7e151628aed2a6abf7158809cf4f3c";
        HexUtils::hex_to_bin(HexUtils::toUpper("7649abac8119b246cee98e9b12e9197d"), cipher);
        input.write((char *) cipher, 16); //raw data
        result = "6bc1bee22e409f96e93d7e117393172a";
    }

    SECTION("IV 00000000000000000000000000000000 | "
            "CIPHER 69c4e0d86a7b0430d8cdb78070b4c55a | "
            "KEY 000102030405060708090a0b0c0d0e0f") {

        iv = "00000000000000000000000000000000";
        key = "000102030405060708090a0b0c0d0e0f";
        HexUtils::hex_to_bin(HexUtils::toUpper("69c4e0d86a7b0430d8cdb78070b4c55a"), cipher);
        input.write((char *) cipher, 16);
        result = "00112233445566778899aabbccddeeff";
    }

    std::stringstream output;
    decrypt(input, output, key, iv, Padding::NONE, false);
    //the result is in binary form, not interpretable as hex (it would be interpretable if we decrypted our own encrypted data)
    CHECK(HexUtils::bin_to_hex(output.str()) == HexUtils::toUpper(result));
}

TEST_CASE("ALL: AES-128 custom msg with PKCS7 padding") {
    std::string iv;
    std::string key;
    std::stringstream input;

    std::string msg;

    SECTION("Long text") {
        iv = "30c81c46a35ce411e5fbc1191a0a52ef";
        key = "73bed6b8e3c1743b7116e69e22229516";
        msg = "Miusov, as a man man of breeding and deilcacy, could not but feel some inwrd qualms,\n"
              "when he reached the Father Superior's with Ivan: he felt ashamed of havin lost his temper.\n"
              "He felt that he ought to have disdaimed that despicable wretch, Fyodor Pavlovitch,\n"
              "too much to have been upset by him in Father Zossima's cell, and so to have forgotten himself.\n"
              "\"Teh monks were not to blame, in any case,\" he reflceted, on the steps. \"And if they're decent\n"
              "people here (and the Father Superior, I understand, is a nobleman) why not be friendly and\n"
              "courteous withthem? I won't argue, I'll fall in with everything, I'll win them by politness,\n"
              "and show them that I've nothing to do with that Aesop, thta buffoon, that Pierrot, and have\n"
              "merely been takken in over this affair, just as they have.\"";
        input = std::stringstream{msg};

        SECTION("hex conversion") {
            std::stringstream encrypted;
            encrypt(input, encrypted, key, iv, Padding::PKCS7, false);

            std::stringstream output;
            decrypt(encrypted, output, key, iv, Padding::PKCS7, false);

            CHECK(output.str() == msg);
        }

        SECTION("bites only") {
            std::stringstream encrypted;
            encrypt(input, encrypted, key, iv, Padding::PKCS7, true);

            std::stringstream output;
            decrypt(encrypted, output, key, iv, Padding::PKCS7, true);

            CHECK(output.str() == msg);
        }

        SECTION("invalid key for decryption") {
            //key = "73bed6b8e3c1743b7116e69e22229516";
            std::string key_wrong = "63bed6b8e3c1743b7116e69e22229516";

            std::stringstream encrypted;
            encrypt(input, encrypted, key, iv, Padding::PKCS7, false);

            std::stringstream output;
            CHECK_THROWS_AS(decrypt(encrypted, output, key_wrong, iv, Padding::PKCS7, false), std::runtime_error);
        }
    }
}

TEST_CASE("AES lengthy errors") {
    std::string iv;
    std::string key;
    std::stringstream input;

    std::string msg;

    iv = "30c81c46a35ce411e5fbc1191a0a52ef";
    key = "73bed6b8e3c1743b7116e69e22229516";
    msg = "My custom msg.";
    input = std::stringstream{msg};

    SECTION("invalid key length") {
        std::string invalid_length_key = "73bed6b8e3c1743b7116e69e2222951";
        std::stringstream encrypted;

        CHECK_THROWS_AS(encrypt(input, encrypted, invalid_length_key, iv, Padding::PKCS7, false), std::runtime_error);
        CHECK_THROWS_AS(decrypt(input, encrypted, invalid_length_key, iv, Padding::PKCS7, false), std::runtime_error);
    }

    SECTION("invalid IV length") {
        std::string invalid_length_IV = "30c81c46a35ce411e5fbc1191a";
        std::stringstream encrypted;

        CHECK_THROWS_AS(encrypt(input, encrypted, key, invalid_length_IV, Padding::PKCS7, false), std::runtime_error);
        CHECK_THROWS_AS(decrypt(input, encrypted, key, invalid_length_IV, Padding::PKCS7, false), std::runtime_error);
    }
}

TEST_CASE("FILE error") {
    //do not create if not exists
    //CHECK(app(4, std::vector<std::string>{"program.exe", "noexistingfile", "wont_reach_here", "args"}) == 1);
    //will create emulate access rights
    //CHECK(app(4, std::vector<std::string>{"program.exe", "long.txt", "noexistingfile", "args"}) == 1);
}


