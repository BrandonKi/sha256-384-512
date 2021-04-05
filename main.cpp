#include <iostream>

#include "sha256.h"
#include "sha384.h"
#include "sha512.h"

#include "examplesha256.h"


#include <stdexcept>
#include <sstream>
#include <iomanip>
#include <string>
#include <cstdint>
std::string string_to_hex(const std::string& in) {
    std::stringstream ss;

    ss << std::hex << std::setfill('0');
    for (size_t i = 0; in.length() > i; ++i) {
        ss << std::setw(2) << static_cast<unsigned int>(static_cast<unsigned char>(in[i]));
    }

    return ss.str();
}



int main() {
    std::cout << string_to_hex(sha256::hash("abc"));
}
