#include <iostream>
#include <fstream>
#include <iomanip>
#include <sstream>
#include <vector>
#include <openssl/sha.h>

std::string sha256_file(const char* path) {
    std::ifstream file(path, std::ios::binary);
    if (!file.good()) {
        return ""; // Or throw an exception
    }

    SHA256_CTX sha256;
    SHA256_Init(&sha256);

    const int bufferSize = 4096;
    char buffer[bufferSize];

    while (file.read(buffer, bufferSize)) {
        SHA256_Update(&sha256, buffer, file.gcount());
    }
    // Handle the remaining bytes (if file size is not a multiple of bufferSize)
    SHA256_Update(&sha256, buffer, file.gcount());

    unsigned char hash[SHA256_DIGEST_LENGTH];
    SHA256_Final(hash, &sha256);

    // Convert the hash buffer to a hex string for display
    std::stringstream ss;
    for (int i = 0; i < SHA256_DIGEST_LENGTH; i++) {
        ss << std::hex << std::setw(2) << std::setfill('0') << (int)hash[i];
    }
    return ss.str();
}

int main() {
    std::string filePath = "example.txt"; // Replace with your file path
    std::string hashHex = sha256_file(filePath.c_str());

    if (hashHex.empty()) {
        std::cerr << "Error: Could not open file." << std::endl;
    } else {
        std::cout << "SHA-256: " << hashHex << std::endl;
    }

    return 0;
}