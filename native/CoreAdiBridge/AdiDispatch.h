#pragma once

#include <cstdint>
#include <string>
#include <vector>

struct AdiOtpResult {
    std::vector<uint8_t> machineId;
    std::vector<uint8_t> otp;
};

struct AdiStartProvisioningResult {
    std::vector<uint8_t> cpim;
    uint32_t session = 0;
};

class AdiDispatch {
public:
    explicit AdiDispatch(const std::wstring& coreAdiPath);
    ~AdiDispatch();

    AdiDispatch(const AdiDispatch&) = delete;
    AdiDispatch& operator=(const AdiDispatch&) = delete;

    void Configure(const std::string& provisioningPath, const std::string& androidId16);
    void Initialize();
    bool IsMachineProvisioned(int64_t dsId);
    AdiStartProvisioningResult StartProvisioning(int64_t dsId, const std::vector<uint8_t>& spim);
    void EndProvisioning(uint32_t session, const std::vector<uint8_t>& ptm, const std::vector<uint8_t>& tk);
    void DestroyProvisioningSession(uint32_t session);
    void SetIdmsRouting(int64_t dsId, uint64_t routingInfo);
    uint64_t GetIdmsRouting(int64_t dsId);
    AdiOtpResult RequestOtp(int64_t dsId);
    void DisposeBuffer(const void* ptr);

private:
    using DispatcherFn = int(__cdecl*)(uint32_t functionCode, void* parameters);

    struct CoreADIParameters {
        uint8_t* payload;
        uint32_t inputSize;
        uint32_t outputSize;
        uint32_t flags;
    };

    void* module_ = nullptr;
    DispatcherFn dispatcher_ = nullptr;

    int32_t DispatchAdiMessage(uint32_t magic, std::vector<uint8_t>& payload, uint32_t returnSize);
    static void WriteU32Be(std::vector<uint8_t>& buffer, uint32_t value);
    static void WriteU64Be(std::vector<uint8_t>& buffer, uint64_t value);
    static void WriteI64Be(std::vector<uint8_t>& buffer, int64_t value);
    static void WriteUsizedBe(std::vector<uint8_t>& buffer, uint64_t value);
    static int32_t ReadI32Be(const uint8_t* data);
    static std::vector<uint8_t> BuildPayload(const std::vector<uint8_t>& inner);
};
