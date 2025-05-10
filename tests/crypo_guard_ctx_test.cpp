#include <gtest/gtest.h>
#include <openssl/evp.h>
#include <sstream>

#include "crypto_guard_ctx.h"

using namespace CryptoGuard;

struct EncryptDecryptTestCase {
    std::string input;
    std::string password;
};

class CryptoGuardParamTest : public ::testing::TestWithParam<EncryptDecryptTestCase> {};

INSTANTIATE_TEST_SUITE_P(
    BasicEncryptionTests, CryptoGuardParamTest,
    ::testing::Values(EncryptDecryptTestCase{"Hello, OpenSSL!", "12345678"}, EncryptDecryptTestCase{"", "empty"},
                      EncryptDecryptTestCase{"Another input block with 1024 chars: " + std::string(1000, 'A'),
                                             "longpass"}));

TEST_P(CryptoGuardParamTest, EncryptThenDecryptRestoresOriginalText) {
    CryptoGuardCtx ctx;
    const auto &param = GetParam();

    std::stringstream in(param.input);
    std::stringstream encrypted;
    std::stringstream decrypted;

    ctx.EncryptFile(in, encrypted, param.password);

    encrypted.seekg(0);
    ctx.DecryptFile(encrypted, decrypted, param.password);

    EXPECT_EQ(param.input, decrypted.str());
}

TEST(CryptoGuardCtxTest, DecryptWithWrongPasswordFails) {
    CryptoGuardCtx ctx;
    std::string data = "Secret message";
    std::string password = "correct";
    std::string wrongPassword = "wrong";

    std::stringstream in(data);
    std::stringstream encrypted;
    std::stringstream decrypted;

    ctx.EncryptFile(in, encrypted, password);
    encrypted.seekg(0);

    ASSERT_THROW(ctx.DecryptFile(encrypted, decrypted, wrongPassword), std::runtime_error);
}

TEST(CryptoGuardCtxTest, InputStreamFailbit) {
    CryptoGuardCtx ctx;
    std::string data = "Secret message";
    std::string password = "correct";

    std::stringstream in(data);
    std::stringstream decrypted;
    in.setstate(std::ios_base::failbit);

    ASSERT_THROW(ctx.EncryptFile(in, decrypted, password), std::runtime_error);
}

TEST(CryptoGuardCtxTest, OutputStreamFailbit) {
    CryptoGuardCtx ctx;
    std::string data = "Secret message";
    std::string password = "correct";

    std::stringstream in(data);
    std::stringstream decrypted;
    decrypted.setstate(std::ios_base::failbit);

    ASSERT_THROW(ctx.EncryptFile(in, decrypted, password), std::runtime_error);
}

TEST(CryptoGuardCtxTest, CalculateChecksumSameInputSameHash) {
    CryptoGuardCtx ctx;
    std::string input = "some data";

    std::stringstream stream1(input);
    std::stringstream stream2(input);

    std::string hash1 = ctx.CalculateChecksum(stream1);
    std::string hash2 = ctx.CalculateChecksum(stream2);

    EXPECT_EQ(hash1, hash2);
}

TEST(CryptoGuardCtxTest, CalculateChecksumDifferentInputDifferentHash) {
    CryptoGuardCtx ctx;

    std::stringstream stream1("data 1");
    std::stringstream stream2("data 2");

    std::string hash1 = ctx.CalculateChecksum(stream1);
    std::string hash2 = ctx.CalculateChecksum(stream2);

    EXPECT_NE(hash1, hash2);
}