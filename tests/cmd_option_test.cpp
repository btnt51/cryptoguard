#include "cmd_options.h"
#include <gtest/gtest.h>

struct dataForTest {
    bool parseResult;
    CryptoGuard::ProgramOptions::COMMAND_TYPE command;
    std::string inputFile;
    std::string outputFile;
    std::string password;
    std::string error_msg;
};

struct testParams {
    std::vector<const char *> argv;
    dataForTest expected;
};

class TestProgramOptionsWithoutError : public testing::TestWithParam<testParams> {};

class TestProgramOptionsWithError : public testing::TestWithParam<testParams> {};

INSTANTIATE_TEST_SUITE_P(
    CommandLineOptions, TestProgramOptionsWithoutError,
    ::testing::Values(testParams{{"program", "--command", "encrypt", "--input", "input.file", "--output", "output.file",
                                  "--password", "1234"},
                                 dataForTest{true, CryptoGuard::ProgramOptions::COMMAND_TYPE::ENCRYPT, "input.file",
                                             "output.file", "1234"}},
                      testParams{{"program", "--command", "decrypt", "--input", "input.file", "--output", "output.file",
                                  "--password", "1234"},
                                 dataForTest{true, CryptoGuard::ProgramOptions::COMMAND_TYPE::DECRYPT, "input.file",
                                             "output.file", "1234"}},
                      testParams{
                          {"program", "--command", "checksum", "--input", "input.file"},
                          dataForTest{true, CryptoGuard::ProgramOptions::COMMAND_TYPE::CHECKSUM, "input.file"}}));

INSTANTIATE_TEST_SUITE_P(
    CommandLineOptions, TestProgramOptionsWithError,
    ::testing::Values(
        testParams{{"program", "--command", "encrypt", "--output", "output.file", "--password", "1234"},
                   dataForTest{.parseResult = false, .error_msg = "Error: Must be provided an input file\n"}},
        testParams{
            {"program", "--command", "decrypt", "--input", "input.file", "--password", "1234"},
            dataForTest{.parseResult = false,
                        .error_msg = "Error: For command type: encrypt/decrypt must be provided an output file\n"}},
        testParams{{"program", "--command", "decrypt", "--input", "input.file", "--output", "output.file"},
                   dataForTest{.parseResult = false,
                               .error_msg = "Error: For command type: encrypt/decrypt must be provided a password\n"}},
        testParams{{"program", "--command", "checksum"},
                   dataForTest{.parseResult = false, .error_msg = "Error: Must be provided an input file\n"}}));

TEST_P(TestProgramOptionsWithoutError, SimpleCheck) {
    CryptoGuard::ProgramOptions po;

    const auto &param = TestProgramOptionsWithoutError::GetParam();
    int argc = static_cast<int>(param.argv.size());
    std::vector<char *> argv_copy;
    for (const char *arg : param.argv) {
        argv_copy.push_back(const_cast<char *>(arg));
    }
    dataForTest data;
    data.parseResult = po.Parse(argc, argv_copy.data());
    data.command = po.GetCommand();
    data.inputFile = po.GetInputFile();
    data.outputFile = po.GetOutputFile();
    data.password = po.GetPassword();
    ASSERT_TRUE(data.parseResult);
    ASSERT_EQ(data.command, param.expected.command);
    ASSERT_EQ(data.inputFile, param.expected.inputFile);
    ASSERT_EQ(data.outputFile, param.expected.outputFile);
    ASSERT_EQ(data.password, param.expected.password);
}

TEST_P(TestProgramOptionsWithError, Exception) {
    CryptoGuard::ProgramOptions po;
    testing::internal::CaptureStderr();

    const auto &param = TestProgramOptionsWithoutError::GetParam();
    int argc = static_cast<int>(param.argv.size());
    std::vector<char *> argv_copy;
    for (const char *arg : param.argv) {
        argv_copy.push_back(const_cast<char *>(arg));
    }
    dataForTest data;
    data.parseResult = po.Parse(argc, argv_copy.data());
    ASSERT_FALSE(data.parseResult);
    auto errorLog = testing::internal::GetCapturedStderr();
    ASSERT_EQ(errorLog, param.expected.error_msg);
}

TEST(TestProgramOptions, Help) {
    CryptoGuard::ProgramOptions po;
    testing::internal::CaptureStdout();

    std::vector<char *> argv{"program", "--help"};
    int argc = static_cast<int>(argv.size());
    std::vector<char *> argv_copy;
    for (const char *arg : argv) {
        argv_copy.push_back(const_cast<char *>(arg));
    }
    dataForTest data;
    data.parseResult = po.Parse(argc, argv_copy.data());
    ASSERT_FALSE(data.parseResult);
    auto errorLog = testing::internal::GetCapturedStdout();
    constexpr std::string_view help =
        "Allowed options:\n  --help                produce help message\n  --command arg         [mandatory field] "
        "possible values: encrypt, decrypt, \n                        checksum\n  -i [ --input ] arg    [mandatory "
        "field] input file\n  -o [ --output ] arg   [mandatory field] output file\n  -p [ --password ] arg [mandatory "
        "field] <PASSWORD>\n\n";
    ASSERT_EQ(errorLog, help);
}
