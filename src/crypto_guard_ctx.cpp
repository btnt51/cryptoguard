#include "crypto_guard_ctx.h"

#include <functional>
#include <iomanip>
#include <openssl/err.h>
#include <openssl/evp.h>
#include <openssl/types.h>

#include <iostream>
#include <memory>
#include <sstream>
#include <vector>

namespace CryptoGuard {

struct AesCipherParams {
    AesCipherParams() = default;
    static constexpr size_t KEY_SIZE = 32;         // AES-256 key size
    static constexpr size_t IV_SIZE = 16;          // AES block size (IV length)
    const EVP_CIPHER *cipher = EVP_aes_256_cbc();  // Cipher algorithm  // Cipher algorithm

    int encrypt;                              // 1 for encryption, 0 for decryption
    std::array<unsigned char, IV_SIZE> iv;    // Initialization vector
    std::array<unsigned char, KEY_SIZE> key;  // Encryption key
};

struct EVPCIPHERContextDeleter {
    void operator()(EVP_CIPHER_CTX *c) const noexcept { EVP_CIPHER_CTX_free(c); }
};

using EVP_CIPHER_CTX_PTR = std::unique_ptr<EVP_CIPHER_CTX, EVPCIPHERContextDeleter>;
class CryptoGuardCtx::Impl {
public:
    Impl();
    ~Impl();

    void EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) const;

    std::streamsize GetFileSize(std::iostream &inStream) const;

    void DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) const;

    std::string CalculateChecksum(std::iostream &inStream) const;

private:
    [[nodiscard]] AesCipherParams CreateChiperParamsFromPassword(std::string_view password) const;

    [[nodiscard]] EVP_CIPHER_CTX_PTR CreateEVP_CIPHER_CTX_PTR(std::string_view password, bool encryption = true) const;

    bool CheckStream(const std::iostream &Stream, const std::string &StreamName) const;
    void process_stream(std::iostream &inStream, std::iostream &outStream, std::string_view password,
                        bool encryption) const;

    std::runtime_error generateExceptionFromOpenSSL(const std::string &msg) const;

    void
    ProcessInstream(std::iostream &inStream,
                    const std::function<void(std::vector<uint8_t> &, const std::streamsize bytesRead)> &func) const;
};

CryptoGuardCtx::CryptoGuardCtx() : pImpl_{std::make_unique<Impl>()} {}

CryptoGuardCtx::Impl::Impl() {
    OpenSSL_add_all_algorithms();
    ERR_clear_error();
}

CryptoGuardCtx::Impl::~Impl() { EVP_cleanup(); }

void CryptoGuardCtx::Impl::EncryptFile(std::iostream &inStream, std::iostream &outStream,
                                       std::string_view password) const {
    try {
        if (not CheckStream(inStream, "input")) {
            throw std::runtime_error("CheckStream failed while checking input");
        }
        if (not CheckStream(outStream, "output")) {
            throw std::runtime_error("CheckStream failed while output input");
        }
        process_stream(inStream, outStream, password, true);
    } catch (const std::exception &e) {
        throw;
    }
}

std::streamsize CryptoGuardCtx::Impl::GetFileSize(std::iostream &inStream) const {
    inStream.seekg(0, std::ios::end);
    const std::streamsize sizeOfFile = inStream.tellg();
    inStream.seekg(0, std::ios::beg);
    return sizeOfFile;
}

void CryptoGuardCtx::Impl::process_stream(std::iostream &inStream, std::iostream &outStream,
                                          const std::string_view password, const bool encryption) const {
    try {
        const std::string logFunctionName = encryption ? "Encrypt" : "Decrypt";
        const auto ctx = CreateEVP_CIPHER_CTX_PTR(password, encryption);

        int outLen = 0;
        std::vector<std::uint8_t> outBuf(1024 + EVP_MAX_BLOCK_LENGTH);
        outStream.exceptions(std::ios::failbit | std::ios::badbit);

        ProcessInstream(inStream, [&](const std::vector<std::uint8_t> &buffer, const std::streamsize bytesRead) {
            if (not EVP_CipherUpdate(ctx.get(), outBuf.data(), &outLen, buffer.data(), static_cast<int>(bytesRead))) {
                throw generateExceptionFromOpenSSL("EVP_CipherUpdate failed at " + logFunctionName + " :");
            }
            outStream.write(reinterpret_cast<char *>(outBuf.data()), outLen);
        });

        if (not EVP_CipherFinal_ex(ctx.get(), outBuf.data(), &outLen)) {
            throw generateExceptionFromOpenSSL("EVP_CipherUpdate failed at " + logFunctionName + " :");
        }
        outStream.write(reinterpret_cast<char *>(outBuf.data()), outLen);
    } catch (const std::exception &e) {
        throw;
    }
}

std::runtime_error CryptoGuardCtx::Impl::generateExceptionFromOpenSSL(const std::string &msg) const {
    const auto errorCode = ERR_get_error();
    const std::string errorMessage = ERR_error_string(errorCode, nullptr);
    return std::runtime_error(msg + errorMessage);
}

void CryptoGuardCtx::Impl::ProcessInstream(
    std::iostream &inStream,
    const std::function<void(std::vector<std::uint8_t> &, const std::streamsize bytesRead)> &func) const {
    auto currentSizeOfFile = GetFileSize(inStream);
    inStream.exceptions(std::ios::failbit | std::ios::badbit);
    std::vector<std::uint8_t> buffer(1024);
    while (inStream and currentSizeOfFile > 0) {
        inStream.read(reinterpret_cast<char *>(buffer.data()),
                      currentSizeOfFile > buffer.size() ? buffer.size() : currentSizeOfFile);
        if (const std::streamsize bytesRead = inStream.gcount(); bytesRead > 0) {
            func(buffer, bytesRead);
            currentSizeOfFile -= bytesRead;
        }
    }
}

void CryptoGuardCtx::Impl::DecryptFile(std::iostream &inStream, std::iostream &outStream,
                                       const std::string_view password) const {

    try {
        if (not CheckStream(inStream, "input")) {
            throw std::runtime_error("CheckStream failed while checking input");
        }
        if (not CheckStream(outStream, "output")) {
            throw std::runtime_error("CheckStream failed while output input");
        }
        process_stream(inStream, outStream, password, false);
    } catch (const std::exception &e) {
        throw;
    }
}

struct EVP_MD_CTX_DELETER {
    void operator()(EVP_MD_CTX *c) const noexcept { EVP_MD_CTX_free(c); }
};
using EVP_MD_CTX_PTR = std::unique_ptr<EVP_MD_CTX, EVP_MD_CTX_DELETER>;

std::string CryptoGuardCtx::Impl::CalculateChecksum(std::iostream &inStream) const {
    try {
        EVP_MD_CTX_PTR context(EVP_MD_CTX_new());
        if (!context) {
            throw generateExceptionFromOpenSSL("Failed to create EVP_MD_CTX at CalculateChecksum: ");
        }

        if (1 != EVP_DigestInit_ex(context.get(), EVP_sha256(), nullptr)) {
            throw generateExceptionFromOpenSSL("Failed to initialize EVP_Digest at CalculateChecksum: ");
        }
        ProcessInstream(inStream, [&](std::vector<uint8_t> &buffer, const std::streamsize bytesRead) {
            if (not EVP_DigestUpdate(context.get(), buffer.data(), static_cast<int>(bytesRead))) {
                throw generateExceptionFromOpenSSL("Failed to update EVP_Digest at CalculateChecksum: ");
            }
        });

        unsigned char hash[EVP_MAX_MD_SIZE];
        unsigned int hash_length = 0;
        if (not EVP_DigestFinal(context.get(), hash, &hash_length)) {
            throw generateExceptionFromOpenSSL("Failed to finalize EVP_DigestFinal while calculating checksum: ");
        }
        std::stringstream res;
        for (int i = 0; i < hash_length; i++) {
            res << std::hex << std::setw(2) << std::setfill('0') << static_cast<int>(hash[i]);
        }
        return res.str();
    } catch (const std::exception &[[maybe_unused]] e) {
        throw;
    }
}

AesCipherParams CryptoGuardCtx::Impl::CreateChiperParamsFromPassword(std::string_view password) const {
    AesCipherParams params;
    constexpr std::array<unsigned char, 8> salt = {'1', '2', '3', '4', '5', '6', '7', '8'};

    if (0 == EVP_BytesToKey(params.cipher, EVP_sha256(), salt.data(),
                            reinterpret_cast<const unsigned char *>(password.data()), static_cast<int>(password.size()),
                            1, params.key.data(), params.iv.data())) {
        throw generateExceptionFromOpenSSL("Failed to create a key from password: ");
    }

    return params;
}

EVP_CIPHER_CTX_PTR CryptoGuardCtx::Impl::CreateEVP_CIPHER_CTX_PTR(const std::string_view password,
                                                                  const bool encryption) const {
    auto params = CreateChiperParamsFromPassword(password);
    params.encrypt = encryption;
    const std::string logFunctionName = encryption ? "encrypt" : "decrypt";
    EVP_CIPHER_CTX_PTR ctx(EVP_CIPHER_CTX_new());
    if (!ctx) {
        throw generateExceptionFromOpenSSL("Failed to create EVP_CIPHER_CTX at " + logFunctionName + ": ");
    }

    if (1 !=
        EVP_CipherInit_ex(ctx.get(), params.cipher, nullptr, params.key.data(), params.iv.data(), params.encrypt)) {
        throw generateExceptionFromOpenSSL("EVP_CipherInit_ex failed at  " + logFunctionName + ": ");
    }
    return std::move(ctx);
}

bool CryptoGuardCtx::Impl::CheckStream(const std::iostream &Stream, const std::string &StreamName) const {
    if (Stream)
        return true;

    if (Stream.bad())
        throw std::runtime_error("Non recoverable error at stream: " + StreamName);

    if (Stream.fail())
        throw std::runtime_error("Logical error at stream: " + StreamName);

    return false;
}

CryptoGuardCtx::~CryptoGuardCtx() = default;

void CryptoGuardCtx::EncryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) const {
    pImpl_->EncryptFile(inStream, outStream, password);
}

void CryptoGuardCtx::DecryptFile(std::iostream &inStream, std::iostream &outStream, std::string_view password) const {
    pImpl_->DecryptFile(inStream, outStream, password);
}

std::string CryptoGuardCtx::CalculateChecksum(std::iostream &inStream) const {
    return pImpl_->CalculateChecksum(inStream);
}
}  // namespace CryptoGuard