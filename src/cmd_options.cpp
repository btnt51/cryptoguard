#include "cmd_options.h"
#include <iostream>

namespace CryptoGuard {

ProgramOptions::ProgramOptions() : desc_("Allowed options") {
    desc_.add_options()("help",
                        "produce help message")("command", boost::program_options::value<std::string>(),
                                                "[mandatory field] possible values: encrypt, decrypt, checksum")(
        "input,i", boost::program_options::value<std::string>(), "[mandatory field] input file")(
        "output,o", boost::program_options::value<std::string>(), "[mandatory field] output file")(
        "password,p", boost::program_options::value<std::string>(), "[mandatory field] <PASSWORD>");
}

ProgramOptions::~ProgramOptions() = default;

bool ProgramOptions::Parse(int argc, char *argv[]) {
    try {
        if (argc < 2 or not argv) {
            throw std::runtime_error("");
        }
        boost::program_options::variables_map vm;
        boost::program_options::store(boost::program_options::parse_command_line(argc, argv, desc_), vm);
        boost::program_options::notify(vm);
        if (vm.contains("help")) {
            std::cout << desc_ << std::endl;
            return false;
        }

        if (vm.contains("command") and not vm["command"].as<std::string>().empty())
            command_ = commandMapping_.at(vm["command"].as<std::string>());
        else
            throw std::runtime_error("Must specify command");

        if (vm.contains("input") and not vm["input"].as<std::string>().empty())
            inputFile_ = vm["input"].as<std::string>();
        else
            throw std::runtime_error("Must be provided an input file");

        switch (command_) {
        case COMMAND_TYPE::ENCRYPT:
        case COMMAND_TYPE::DECRYPT: {
            if (vm.contains("output") and not vm["output"].as<std::string>().empty())
                outputFile_ = vm["output"].as<std::string>();
            else
                throw std::runtime_error("For command type: encrypt/decrypt must be provided an output file");

            if (vm.contains("password") and not vm["password"].as<std::string>().empty())
                password_ = vm["password"].as<std::string>();
            else
                throw std::runtime_error("For command type: encrypt/decrypt must be provided a password");

            return true;
        }
        case COMMAND_TYPE::CHECKSUM: {
            ;
            return true;
        }
        default:
            std::print(std::cerr, "Error: Unknown command\n");
            return false;
        }
    } catch (const std::exception &e) {
        std::print(std::cerr, "Error: {}\n", e.what());
        return false;
    }

    return true;
}

}  // namespace CryptoGuard