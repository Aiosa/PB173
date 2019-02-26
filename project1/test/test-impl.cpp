#include <sstream>
#include "catch.hpp"

#include "../AES_CBC_PKCS7_SHA512.hpp"

std::string toUpper(std::string lowercase) {
    std::transform(lowercase.begin(), lowercase.end(), lowercase.begin(), ::toupper);
    return lowercase;
}

TEST_CASE("HexUtils") {
    unsigned char data[16] { 0x00, 0x01, 0x02, 0x03,
                             0x04, 0x05, 0x06, 0x07,
                             0x08, 0x09, 0xa1, 0xd2,
                             0x55, 0x6a, 0xff, 0x51 };
    CHECK(HexUtils::bin_to_hex(data, 16) == "00010203040506070809A1D2556AFF51");
    unsigned char out[16] {};
    HexUtils::hex_to_bin("00010203040506070809A1D2556AFF51", out);
    for (int i = 0; i < 16; i++) {
        CHECK(out[i] == data[i]);
    }
}

TEST_CASE("SHA-512") {
    //from https://www.di-mgt.com.au/sha_testvectors.html
    std::stringstream teststr{"abc"};
    CHECK(hash_sha512(teststr) == toUpper(
            "ddaf35a193617abacc417349ae204131"
            "12e6fa4e89a97ea0a9eeee64b55d39a"
            "2192992a274fc1a836ba3c23a3feebbd"
            "454d4423643ce80e 2a9ac94fa54ca49f" )
    );

    teststr = std::stringstream{""};
    CHECK(hash_sha512(teststr) == toUpper(
            "cf83e1357eefb8bdf1542850d66d8007"
            "d620e4050b5715dc83f4a921d36ce9ce"
            "47d0d13c5d85f2b0ff8318d2877eec2f"
            "63b931bd47417a81a538327af927da3e" )
    );

    teststr = std::stringstream{"abcdbcdecdefdefgefghfghighijhijkijkljklmklmnlmnomnopnopq"};
    CHECK(hash_sha512(teststr) == toUpper(
            "204a8fc6dda82f0a0ced7beb8e08a416"
            "57c16ef468b228a8279be331a703c335"
            "96fd15c13b1b07f9aa1d3bea57789ca0"
            "31ad85c7a71dd70354ec631238ca3445" )
    );

    teststr = std::stringstream{"abcdefghbcdefghicdefghijdefghijkefghijklfghijklmghijklmnhijklmnoijklmnopjklmnopqklmnopqrlmnopqrsmnopqrstnopqrstu"};
    CHECK(hash_sha512(teststr) == toUpper(
            "8e959b75dae313da8cf4f72814fc143f"
            "8f7779c6eb9f7fa17299aeadb6889018"
            "501d289e4900f7e4331b99dec4b5433a"
            "c7d329eeb6dd26545e96e55b874be909" )
    );

    teststr = std::stringstream{std::string(1000000, 'a')};
    CHECK(hash_sha512(teststr) == toUpper(
            "e718483d0ce769644e2e42c7bc15b463"
            "8e1f98b13b2044285632a803afa973eb"
            "de0ff244877ea60a4cb0432ce577c31b"
            "eb009c5c2c49aa2e4eadb217ad8cc09b" )
    );
}

TEST_CASE("AES-128 CBC pkcs#7 padding"){

    unsigned char zero_iv[16]{};
    unsigned char random_iv[16]{ 0x56, 0xaa, 0x00, 0x51,
                                 0x1a, 0xd5, 0x99, 0x01,
                                 0x7f, 0xf1, 0xf1, 0xf1,
                                 0xaa, 0xda, 0x00, 0x6b
    };
    unsigned char key[16];

    std::stringstream data{"00112233445566778899aabbccddeeff"};
    std::stringstream output;
    get16byte(key, toUpper("000102030405060708090a0b0c0d0e0f"));
    encrypt(data, output, key, zero_iv);
    CHECK(HexUtils::bin_to_hex(output.str()) == toUpper("69c4e0d86a7b0430d8cdb78070b4c55a"));


}