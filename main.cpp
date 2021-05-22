#include <iostream>

#include "sha256.h"
#include "sha384.h"
#include "sha512.h"


int main() {
     std::cout << sha256::to_hex(sha256::hash("abc")) << '\n';

}
