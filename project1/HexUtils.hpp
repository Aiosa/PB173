//
// Created by horak_000 on 24. 2. 2019.
//

#ifndef PB173_HEXUTILS_H
#define PB173_HEXUTILS_H

#include <string>
#include <iostream>

struct HexUtils {
    static std::string hex_from_byte(unsigned char value) {
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

    static unsigned char byte_from_hex(char hex) {
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

    static std::string bin_to_hex(const unsigned char* buff, size_t ilen) {
        std::string res;
        for (size_t i = 0; i < ilen; i++) {
            res += hex_from_byte(*(buff + i) >> 4) + hex_from_byte(*(buff + i) & (unsigned char)0x0F);
        }
        return res;
    }

    static std::string bin_to_hex(const std::string& buff) {
        return bin_to_hex((const unsigned char*) buff.data(), buff.length());
    }

//out must be at least hex / 2 bytes long
    static void hex_to_bin(const std::string& hex, unsigned char* out) {
        if (hex.length() % 2 == 1) {
            std::cerr << "Invalid conversion from even length hex string.";
            return;
        }
        for (size_t i = 0; i < hex.length(); i++) {
            out[i] = byte_from_hex(hex[i]) << 4;
            ++i;
            out[i] |= byte_from_hex(hex[i]);
        }
    }
};

#endif //PB173_HEXUTILS_H
