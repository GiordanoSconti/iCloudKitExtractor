#include "AdiDispatch.h"

#include <Windows.h>

#include <cstring>
#include <stdexcept>

namespace {
constexpr uint32_t kMagicInitialize = 0x12db31c5;
constexpr uint32_t kMagicIsProvisioned = 0xb0eda7af;
constexpr uint32_t kMagicProvisioningStart = 0x716bd86c;
constexpr uint32_t kMagicProvisioningEnd = 0x0b2b3196;
constexpr uint32_t kMagicProvisioningDestroy = 0x55a637c0;
constexpr uint32_t kMagicSetRouting = 0x632b8d6e;
constexpr uint32_t kMagicGetRouting = 0x85fe63b0;
constexpr uint32_t kMagicRequestOtp = 0xcfe0b46a;
constexpr uint32_t kMagicStorageDispose = 0x3e58e7f9;
constexpr uint32_t kMagicSetProvisioningPath = 0xb23c691e;
constexpr uint32_t kMagicSetAndroidId = 0xc774d292;
constexpr uint32_t kMagicTearDown = 0x08c0fe9e;

constexpr int32_t kNotProvisioned = -45061;

std::string WideToUtf8(const std::wstring& value) {
    if (value.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size <= 1) return {};
    std::string out(static_cast<size_t>(size - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, &out[0], size, nullptr, nullptr);
    return out;
}
} // namespace

AdiDispatch::AdiDispatch(const std::wstring& coreAdiPath) {
    module_ = LoadLibraryW(coreAdiPath.c_str());
    if (!module_) {
        throw std::runtime_error("LoadLibrary CoreADI fallito: " + WideToUtf8(coreAdiPath));
    }

    dispatcher_ = reinterpret_cast<DispatcherFn>(GetProcAddress(static_cast<HMODULE>(module_), "vdfut768ig"));
    if (!dispatcher_) {
        FreeLibrary(static_cast<HMODULE>(module_));
        module_ = nullptr;
        throw std::runtime_error("Simbolo vdfut768ig non trovato in CoreADI.");
    }
}

AdiDispatch::~AdiDispatch() {
    if (dispatcher_) {
        try {
            std::vector<uint8_t> empty;
            DispatchAdiMessage(kMagicTearDown, empty, sizeof(int32_t));
        } catch (...) {
        }
    }
    if (module_) {
        FreeLibrary(static_cast<HMODULE>(module_));
        module_ = nullptr;
    }
}

void AdiDispatch::WriteU32Be(std::vector<uint8_t>& buffer, uint32_t value) {
    buffer.push_back(static_cast<uint8_t>((value >> 24) & 0xff));
    buffer.push_back(static_cast<uint8_t>((value >> 16) & 0xff));
    buffer.push_back(static_cast<uint8_t>((value >> 8) & 0xff));
    buffer.push_back(static_cast<uint8_t>(value & 0xff));
}

void AdiDispatch::WriteU64Be(std::vector<uint8_t>& buffer, uint64_t value) {
    WriteU32Be(buffer, static_cast<uint32_t>((value >> 32) & 0xffffffffu));
    WriteU32Be(buffer, static_cast<uint32_t>(value & 0xffffffffu));
}

void AdiDispatch::WriteI64Be(std::vector<uint8_t>& buffer, int64_t value) {
    WriteU64Be(buffer, static_cast<uint64_t>(value));
}

void AdiDispatch::WriteUsizedBe(std::vector<uint8_t>& buffer, uint64_t value) {
#if defined(_WIN64)
    WriteU64Be(buffer, value);
#else
    WriteU32Be(buffer, static_cast<uint32_t>(value));
#endif
}

int32_t AdiDispatch::ReadI32Be(const uint8_t* data) {
    return (static_cast<int32_t>(data[0]) << 24) |
           (static_cast<int32_t>(data[1]) << 16) |
           (static_cast<int32_t>(data[2]) << 8) |
           static_cast<int32_t>(data[3]);
}

std::vector<uint8_t> AdiDispatch::BuildPayload(const std::vector<uint8_t>& inner) {
    std::vector<uint8_t> payload;
    WriteU32Be(payload, 1);
    WriteU32Be(payload, 1);
    payload.insert(payload.end(), inner.begin(), inner.end());
    return payload;
}

int32_t AdiDispatch::DispatchAdiMessage(uint32_t magic, std::vector<uint8_t>& payload, uint32_t returnSize) {
    CoreADIParameters params {};
    params.payload = payload.data();
    params.inputSize = static_cast<uint32_t>(payload.size());
    params.outputSize = returnSize;
    params.flags = 0;

    const int status = dispatcher_(magic, &params);
    if (status < 0) {
        throw std::runtime_error("CoreADI errore " + std::to_string(status));
    }

    if (returnSize < sizeof(int32_t)) {
        return status;
    }
    return ReadI32Be(payload.data());
}

void AdiDispatch::Configure(const std::string& provisioningPath, const std::string& androidId16) {
    if (androidId16.size() != 16) {
        throw std::runtime_error("ADI identifier deve essere lungo 16 caratteri.");
    }

    Initialize();

    try {
        std::vector<uint8_t> pathMessage;
        WriteUsizedBe(pathMessage, reinterpret_cast<uint64_t>(provisioningPath.c_str()));
        auto pathPayload = BuildPayload(pathMessage);
        DispatchAdiMessage(kMagicSetProvisioningPath, pathPayload, sizeof(int32_t));

        std::vector<uint8_t> idMessage;
        WriteUsizedBe(idMessage, reinterpret_cast<uint64_t>(androidId16.data()));
        WriteU32Be(idMessage, static_cast<uint32_t>(androidId16.size()));
        auto idPayload = BuildPayload(idMessage);
        DispatchAdiMessage(kMagicSetAndroidId, idPayload, sizeof(int32_t));
    } catch (const std::runtime_error& ex) {
        const std::string what = ex.what();
        if (what.find("-45019") == std::string::npos) {
            throw;
        }
        // CoreADI Win32 nativo: SetProvisioningPath/SetAndroidId non esistono (solo Initialize).
    }
}

void AdiDispatch::Initialize() {
    std::vector<uint8_t> empty;
    auto payload = BuildPayload(empty);
    DispatchAdiMessage(kMagicInitialize, payload, sizeof(int32_t));
}

bool AdiDispatch::IsMachineProvisioned(int64_t dsId) {
    std::vector<uint8_t> message;
    WriteI64Be(message, dsId);
    auto payload = BuildPayload(message);
    try {
        const int32_t result = DispatchAdiMessage(kMagicIsProvisioned, payload, sizeof(int32_t));
        return result == 0;
    } catch (const std::runtime_error& ex) {
        if (std::string(ex.what()).find(std::to_string(kNotProvisioned)) != std::string::npos) {
            return false;
        }
        throw;
    }
}

AdiStartProvisioningResult AdiDispatch::StartProvisioning(int64_t dsId, const std::vector<uint8_t>& spim) {
    uint8_t* cpimRaw = nullptr;
    uint32_t cpimLen = 0;
    uint32_t session = 0;

    std::vector<uint8_t> message;
    WriteI64Be(message, dsId);
    WriteUsizedBe(message, reinterpret_cast<uint64_t>(spim.data()));
    WriteU32Be(message, static_cast<uint32_t>(spim.size()));
    WriteUsizedBe(message, reinterpret_cast<uint64_t>(&cpimRaw));
    WriteUsizedBe(message, reinterpret_cast<uint64_t>(&cpimLen));
    WriteUsizedBe(message, reinterpret_cast<uint64_t>(&session));

    auto payload = BuildPayload(message);
    DispatchAdiMessage(kMagicProvisioningStart, payload, sizeof(int32_t));

    AdiStartProvisioningResult result;
    result.session = session;
    if (cpimRaw && cpimLen > 0) {
        result.cpim.assign(cpimRaw, cpimRaw + cpimLen);
        DisposeBuffer(cpimRaw);
    }
    return result;
}

void AdiDispatch::EndProvisioning(uint32_t session, const std::vector<uint8_t>& ptm, const std::vector<uint8_t>& tk) {
    std::vector<uint8_t> message;
    WriteU32Be(message, session);
    WriteUsizedBe(message, reinterpret_cast<uint64_t>(ptm.data()));
    WriteU32Be(message, static_cast<uint32_t>(ptm.size()));
    WriteUsizedBe(message, reinterpret_cast<uint64_t>(tk.data()));
    WriteU32Be(message, static_cast<uint32_t>(tk.size()));

    auto payload = BuildPayload(message);
    DispatchAdiMessage(kMagicProvisioningEnd, payload, sizeof(int32_t));
}

void AdiDispatch::DestroyProvisioningSession(uint32_t session) {
    std::vector<uint8_t> message;
    WriteU32Be(message, session);
    auto payload = BuildPayload(message);
    DispatchAdiMessage(kMagicProvisioningDestroy, payload, sizeof(int32_t));
}

void AdiDispatch::SetIdmsRouting(int64_t dsId, uint64_t routingInfo) {
    std::vector<uint8_t> message;
    WriteI64Be(message, dsId);
    WriteU64Be(message, routingInfo);
    auto payload = BuildPayload(message);
    DispatchAdiMessage(kMagicSetRouting, payload, sizeof(int32_t));
}

uint64_t AdiDispatch::GetIdmsRouting(int64_t dsId) {
    uint64_t routing = 0;
    std::vector<uint8_t> message;
    WriteI64Be(message, dsId);
    WriteUsizedBe(message, reinterpret_cast<uint64_t>(&routing));
    auto payload = BuildPayload(message);
    DispatchAdiMessage(kMagicGetRouting, payload, sizeof(int32_t));
    return routing;
}

AdiOtpResult AdiDispatch::RequestOtp(int64_t dsId) {
    uint8_t* midRaw = nullptr;
    uint32_t midLen = 0;
    uint8_t* otpRaw = nullptr;
    uint32_t otpLen = 0;

    std::vector<uint8_t> message;
    WriteI64Be(message, dsId);
    WriteUsizedBe(message, reinterpret_cast<uint64_t>(&midRaw));
    WriteUsizedBe(message, reinterpret_cast<uint64_t>(&midLen));
    WriteUsizedBe(message, reinterpret_cast<uint64_t>(&otpRaw));
    WriteUsizedBe(message, reinterpret_cast<uint64_t>(&otpLen));

    auto payload = BuildPayload(message);
    DispatchAdiMessage(kMagicRequestOtp, payload, sizeof(int32_t));

    AdiOtpResult result;
    if (midRaw && midLen > 0) {
        result.machineId.assign(midRaw, midRaw + midLen);
        DisposeBuffer(midRaw);
    }
    if (otpRaw && otpLen > 0) {
        result.otp.assign(otpRaw, otpRaw + otpLen);
        DisposeBuffer(otpRaw);
    }
    return result;
}

void AdiDispatch::DisposeBuffer(const void* ptr) {
    if (!ptr) return;
    std::vector<uint8_t> message;
    WriteUsizedBe(message, reinterpret_cast<uint64_t>(ptr));
    auto payload = BuildPayload(message);
    try {
        DispatchAdiMessage(kMagicStorageDispose, payload, sizeof(int32_t));
    } catch (...) {
    }
}
