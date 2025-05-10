#include "cmd_options.h"
#include "crypto_guard_ctx.h"
#include <fstream>
#include <iostream>
#include <print>
#include <stdexcept>
#include <string>

int main(int argc, char *argv[]) {
    try {
        CryptoGuard::ProgramOptions options;

        CryptoGuard::CryptoGuardCtx cryptoCtx;

        using COMMAND_TYPE = CryptoGuard::ProgramOptions::COMMAND_TYPE;
        if (not options.Parse(argc, argv))
            return 0;
        switch (options.GetCommand()) {
        case COMMAND_TYPE::ENCRYPT: {
            std::fstream input(options.GetInputFile());
            std::fstream output(options.GetOutputFile(), std::fstream::out);
            cryptoCtx.EncryptFile(input, output, options.GetPassword());
            break;
        }

        case COMMAND_TYPE::DECRYPT: {
            std::fstream input(options.GetInputFile());
            std::fstream output(options.GetOutputFile(), std::fstream::out);
            cryptoCtx.DecryptFile(input, output, options.GetPassword());
            break;
        }

        case COMMAND_TYPE::CHECKSUM: {
            std::fstream file(options.GetInputFile());
            std::print(std::cout, "Checksum of file: {} is {}", options.GetInputFile(),
                       cryptoCtx.CalculateChecksum(file));
            break;
        }

        default:
            throw std::runtime_error{"Unsupported command"};
        }

    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return 1;
    }

    return 0;
}