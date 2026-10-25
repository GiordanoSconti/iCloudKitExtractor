#include "AdiDispatch.h"

#include <Windows.h>
#include <shellapi.h>

#include <cstdlib>
#include <ctime>
#include <iostream>
#include <map>
#include <sstream>
#include <string>
#include <vector>

namespace objc {
    using id = void*;
    using getClassFunc = id(__cdecl*)(const char* name);
    using msgSendFunc = id(__cdecl*)(id self);
    using sel_registerNameFunc = id(__cdecl*)(const char* sel);

    getClassFunc getClass = nullptr;
    msgSendFunc msgSendPtr = nullptr;
    sel_registerNameFunc sel_registerName = nullptr;

    template<typename... Types>
    id msgSend(id self, Types... args) {
        return ((id(*)(id, Types...))msgSendPtr)(self, args...);
    }
}

static std::vector<uint8_t> Base64Decode(const std::string& input);

static std::string JsonEscape(const std::string& value) {
    std::string out;
    out.reserve(value.size() + 8);
    for (unsigned char c : value) {
        switch (c) {
        case '\\': out += "\\\\"; break;
        case '"': out += "\\\""; break;
        case '\b': out += "\\b"; break;
        case '\f': out += "\\f"; break;
        case '\n': out += "\\n"; break;
        case '\r': out += "\\r"; break;
        case '\t': out += "\\t"; break;
        default:
            if (c < 0x20) {
                char hex[7];
                snprintf(hex, sizeof(hex), "\\u%04x", c);
                out += hex;
            } else {
                out += static_cast<char>(c);
            }
        }
    }
    return out;
}

static std::string Base64Encode(const std::vector<uint8_t>& data) {
    static const char* alphabet = "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    std::string out;
    out.reserve(((data.size() + 2) / 3) * 4);
    for (size_t i = 0; i < data.size(); i += 3) {
        const uint32_t b0 = data[i];
        const uint32_t b1 = i + 1 < data.size() ? data[i + 1] : 0;
        const uint32_t b2 = i + 2 < data.size() ? data[i + 2] : 0;
        const uint32_t triple = (b0 << 16) | (b1 << 8) | b2;
        out.push_back(alphabet[(triple >> 18) & 0x3f]);
        out.push_back(alphabet[(triple >> 12) & 0x3f]);
        out.push_back(i + 1 < data.size() ? alphabet[(triple >> 6) & 0x3f] : '=');
        out.push_back(i + 2 < data.size() ? alphabet[triple & 0x3f] : '=');
    }
    return out;
}

static std::wstring Utf8ToWide(const std::string& value) {
    if (value.empty()) return L"";
    const int len = MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, nullptr, 0);
    if (len <= 1) return L"";
    std::wstring out(static_cast<size_t>(len - 1), L'\0');
    MultiByteToWideChar(CP_UTF8, 0, value.c_str(), -1, &out[0], len);
    return out;
}

static std::string WideToUtf8(const std::wstring& value) {
    if (value.empty()) return {};
    const int size = WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, nullptr, 0, nullptr, nullptr);
    if (size <= 1) return {};
    std::string out(static_cast<size_t>(size - 1), '\0');
    WideCharToMultiByte(CP_UTF8, 0, value.c_str(), -1, &out[0], size, nullptr, nullptr);
    return out;
}

static std::wstring JoinPath(const std::wstring& base, const wchar_t* leaf) {
    if (base.empty()) return leaf;
    if (base.back() == L'\\' || base.back() == L'/') return base + leaf;
    return base + L"\\" + leaf;
}

static std::wstring ResolveCoreAdiDll(const std::wstring& runtimeDir) {
    const wchar_t* candidates[] = { L"CoreADI64.dll", L"coreadi64.dll", L"CoreADI.dll", L"coreadi.dll" };
    for (const wchar_t* name : candidates) {
        const std::wstring path = JoinPath(runtimeDir, name);
        if (GetFileAttributesW(path.c_str()) != INVALID_FILE_ATTRIBUTES) return path;
    }
    throw std::runtime_error("CoreADI64.dll non trovato nella runtime directory.");
}

static void PrintErrorJson(const std::string& message) {
    std::cout << "{\"ok\":false,\"error\":\"" << JsonEscape(message) << "\"}" << std::endl;
}

static void PrintOkJson(const std::string& extraFields = "") {
    if (extraFields.empty()) std::cout << "{\"ok\":true}" << std::endl;
    else std::cout << "{\"ok\":true," << extraFields << "}" << std::endl;
}

static std::map<std::string, std::string> ParseArgs(int argc, char** argv) {
    std::map<std::string, std::string> args;
    for (int i = 1; i < argc; ++i) {
        const std::string key = argv[i];
        if (key.rfind("--", 0) != 0) continue;
        if (i + 1 >= argc) break;
        const std::string next = argv[i + 1];
        if (next.rfind("--", 0) == 0) continue;
        args[key] = next;
        ++i;
    }
    return args;
}

static const char* NSStringCString(objc::id nsString) {
    if (!nsString) return "";
    objc::id cString = objc::sel_registerName("cString");
    objc::id usingSel = objc::sel_registerName("using:");
    return static_cast<const char*>(objc::msgSend(nsString, cString, usingSel, static_cast<unsigned long>(4)));
}

static objc::id NSStringFromUtf8(const char* text) {
    objc::id NSString = objc::getClass("NSString");
    objc::id stringWithUTF8String = objc::sel_registerName("stringWithUTF8String:");
    return objc::msgSend(NSString, stringWithUTF8String, text);
}

static objc::id DictionaryValue(objc::id dictionary, const char* keyUtf8) {
    if (!dictionary) return nullptr;
    objc::id key = NSStringFromUtf8(keyUtf8);
    objc::id objectForKey = objc::sel_registerName("objectForKey:");
    return objc::msgSend(dictionary, objectForKey, key);
}

static std::wstring GetWideCommandLineArg(const wchar_t* name) {
    int argc = 0;
    LPWSTR* argvW = CommandLineToArgvW(GetCommandLineW(), &argc);
    std::wstring value;
    if (argvW) {
        for (int i = 1; i < argc; ++i) {
            if (_wcsicmp(argvW[i], name) == 0 && i + 1 < argc) {
                value = argvW[i + 1];
                break;
            }
        }
        LocalFree(argvW);
    }
    return value;
}

static std::wstring ExpandEnvironmentPath(const std::wstring& path) {
    if (path.empty()) return path;
    const DWORD needed = ExpandEnvironmentStringsW(path.c_str(), nullptr, 0);
    if (needed == 0) return path;
    std::wstring out(static_cast<size_t>(needed - 1), L'\0');
    ExpandEnvironmentStringsW(path.c_str(), &out[0], needed);
    return out;
}

static std::wstring ResolvePathArg(const std::map<std::string, std::string>& args, const char* utf8Key, const wchar_t* wideKey) {
    const std::wstring wide = GetWideCommandLineArg(wideKey);
    if (!wide.empty()) return ExpandEnvironmentPath(wide);
    const auto it = args.find(utf8Key);
    if (it == args.end()) return L"";
    return ExpandEnvironmentPath(Utf8ToWide(it->second));
}

static HINSTANCE LoadLibraryInDir(const std::wstring& dir, const wchar_t* name) {
    const std::wstring path = JoinPath(dir, name);
    return LoadLibraryW(path.c_str());
}

static std::string LastLoadError(const std::wstring& path) {
    const DWORD err = GetLastError();
    std::ostringstream out;
    out << WideToUtf8(path) << " (Win32=" << err << ")";
    return out.str();
}

static void RunAosKitOtp(std::wstring supportDir) {
    supportDir = ExpandEnvironmentPath(supportDir);
    if (supportDir.empty()) {
        throw std::runtime_error("support-dir vuota.");
    }

    SetDllDirectoryW(supportDir.c_str());

    std::vector<HINSTANCE> loaded;
    const wchar_t* preloadOrder[] = {
        L"zlib1.dll",
        L"pthreadVC2.dll",
        L"icudt62.dll",
        L"libicuuc.dll",
        L"libicuin.dll",
        L"libxml2.dll",
        L"libdispatch.dll",
        L"objc.dll"
    };

    HINSTANCE objcLib = nullptr;
    for (const wchar_t* dep : preloadOrder) {
        HINSTANCE mod = LoadLibraryInDir(supportDir, dep);
        if (!mod) continue;
        loaded.push_back(mod);
        if (_wcsicmp(dep, L"objc.dll") == 0) objcLib = mod;
    }

    if (!objcLib) {
        throw std::runtime_error(
            "objc.dll non caricabile: " + LastLoadError(JoinPath(supportDir, L"objc.dll")));
    }

    objc::getClass = reinterpret_cast<objc::getClassFunc>(GetProcAddress(objcLib, "objc_getClass"));
    objc::msgSendPtr = reinterpret_cast<objc::msgSendFunc>(GetProcAddress(objcLib, "objc_msgSend"));
    objc::sel_registerName = reinterpret_cast<objc::sel_registerNameFunc>(GetProcAddress(objcLib, "sel_registerName"));
    if (!objc::getClass || !objc::msgSendPtr || !objc::sel_registerName) {
        throw std::runtime_error("Simboli objc mancanti.");
    }

    HINSTANCE foundation = LoadLibraryInDir(supportDir, L"CoreFoundation.dll");
    if (!foundation) foundation = LoadLibraryInDir(supportDir, L"Foundation.dll");
    if (!foundation) {
        throw std::runtime_error(
            "CoreFoundation non caricabile: " + LastLoadError(JoinPath(supportDir, L"CoreFoundation.dll")));
    }
    loaded.push_back(foundation);

    HINSTANCE aosKit = LoadLibraryInDir(supportDir, L"AOSKit.dll");
    if (!aosKit) {
        throw std::runtime_error(
            "AOSKit.dll non caricabile: " + LastLoadError(JoinPath(supportDir, L"AOSKit.dll")));
    }
    loaded.push_back(aosKit);

    objc::id aosUtilities = objc::getClass("AOSUtilities");
    if (!aosUtilities) throw std::runtime_error("Classe AOSUtilities non disponibile.");

    objc::id dsidString = NSStringFromUtf8("-2");
    objc::id retrieveOTPHeadersForDSID = objc::sel_registerName("retrieveOTPHeadersForDSID:");
    objc::id headers = objc::msgSend(aosUtilities, retrieveOTPHeadersForDSID, dsidString);
    if (!headers) throw std::runtime_error("retrieveOTPHeadersForDSID ha restituito null.");

    const char* md = NSStringCString(DictionaryValue(headers, "X-Apple-I-MD"));
    const char* mdM = NSStringCString(DictionaryValue(headers, "X-Apple-I-MD-M"));
    const char* mdRinfo = NSStringCString(DictionaryValue(headers, "X-Apple-I-MD-RINFO"));
    if (!md || !md[0] || !mdM || !mdM[0]) {
        throw std::runtime_error("Header X-Apple-I-MD o X-Apple-I-MD-M mancanti.");
    }

    char clientTime[32] = {};
    const std::time_t unixTime = std::time(nullptr);
    std::tm gm {};
    gmtime_s(&gm, &unixTime);
    std::strftime(clientTime, sizeof(clientTime), "%Y-%m-%dT%H:%M:%SZ", &gm);

    std::ostringstream fields;
    fields << "\"X-Apple-I-MD\":\"" << JsonEscape(md) << "\""
           << ",\"X-Apple-I-MD-M\":\"" << JsonEscape(mdM) << "\""
           << ",\"X-Apple-I-MD-RINFO\":\"" << JsonEscape(mdRinfo ? mdRinfo : "") << "\""
           << ",\"X-Apple-I-ClientTime\":\"" << clientTime << "\"";
    PrintOkJson(fields.str());

    for (auto it = loaded.rbegin(); it != loaded.rend(); ++it) {
        if (*it) FreeLibrary(*it);
    }
    SetDllDirectoryW(nullptr);
}

int main(int argc, char** argv) {
    try {
        const auto args = ParseArgs(argc, argv);
        const auto commandIt = args.find("--command");
        if (commandIt == args.end()) {
            PrintErrorJson("Argomento --command richiesto.");
            return 1;
        }

        const std::string command = commandIt->second;

        if (command == "aoskit-otp") {
            const std::wstring supportDir = ResolvePathArg(args, "--support-dir", L"--support-dir");
            if (supportDir.empty()) {
                PrintErrorJson("aoskit-otp richiede --support-dir.");
                return 1;
            }
            RunAosKitOtp(supportDir);
            return 0;
        }

        const std::wstring runtimeDir = ResolvePathArg(args, "--runtime", L"--runtime");
        const std::wstring provisionDir = ResolvePathArg(args, "--provision", L"--provision");
        const auto adiIdIt = args.find("--adi-id");
        if (runtimeDir.empty() || provisionDir.empty() || adiIdIt == args.end()) {
            PrintErrorJson("Argomenti richiesti: --runtime --provision --adi-id");
            return 1;
        }

        const std::string adiId = adiIdIt->second;
        const int64_t dsId = args.find("--dsid") != args.end()
            ? std::strtoll(args.at("--dsid").c_str(), nullptr, 10) : -2;

        int provisionLen = WideCharToMultiByte(CP_UTF8, 0, provisionDir.c_str(), -1, nullptr, 0, nullptr, nullptr);
        std::string provisionUtf8(static_cast<size_t>(provisionLen > 0 ? provisionLen - 1 : 0), '\0');
        if (provisionLen > 1) {
            WideCharToMultiByte(CP_UTF8, 0, provisionDir.c_str(), -1, &provisionUtf8[0], provisionLen, nullptr, nullptr);
        }

        AdiDispatch adi(ResolveCoreAdiDll(runtimeDir));
        adi.Configure(provisionUtf8, adiId);

        if (command == "is-provisioned") {
            const bool provisioned = adi.IsMachineProvisioned(dsId);
            PrintOkJson(std::string("\"provisioned\":") + (provisioned ? "true" : "false"));
            return 0;
        }

        if (command == "start-provisioning") {
            if (args.find("--spim") == args.end()) throw std::runtime_error("start-provisioning richiede --spim");
            const auto spim = Base64Decode(args.at("--spim"));
            const auto result = adi.StartProvisioning(dsId, spim);
            std::ostringstream fields;
            fields << "\"session\":" << result.session
                   << ",\"cpim\":\"" << JsonEscape(Base64Encode(result.cpim)) << "\"";
            PrintOkJson(fields.str());
            return 0;
        }

        if (command == "end-provisioning") {
            if (args.find("--session") == args.end() || args.find("--ptm") == args.end() || args.find("--tk") == args.end()) {
                throw std::runtime_error("end-provisioning richiede --session --ptm --tk");
            }
            const uint32_t session = static_cast<uint32_t>(std::strtoul(args.at("--session").c_str(), nullptr, 10));
            const auto ptm = Base64Decode(args.at("--ptm"));
            const auto tk = Base64Decode(args.at("--tk"));
            adi.EndProvisioning(session, ptm, tk);
            PrintOkJson();
            return 0;
        }

        if (command == "destroy-session") {
            if (args.find("--session") == args.end()) throw std::runtime_error("destroy-session richiede --session");
            const uint32_t session = static_cast<uint32_t>(std::strtoul(args.at("--session").c_str(), nullptr, 10));
            adi.DestroyProvisioningSession(session);
            PrintOkJson();
            return 0;
        }

        if (command == "set-routing") {
            if (args.find("--routing") == args.end()) throw std::runtime_error("set-routing richiede --routing");
            const uint64_t routing = std::strtoull(args.at("--routing").c_str(), nullptr, 10);
            adi.SetIdmsRouting(dsId, routing);
            PrintOkJson();
            return 0;
        }

        if (command == "request-otp") {
            const auto otp = adi.RequestOtp(dsId);
            const auto routing = adi.GetIdmsRouting(dsId);
            std::ostringstream fields;
            fields << "\"X-Apple-I-MD\":\"" << JsonEscape(Base64Encode(otp.otp)) << "\""
                   << ",\"X-Apple-I-MD-M\":\"" << JsonEscape(Base64Encode(otp.machineId)) << "\""
                   << ",\"X-Apple-I-MD-RINFO\":\"" << routing << "\"";
            PrintOkJson(fields.str());
            return 0;
        }

        PrintErrorJson("Comando sconosciuto: " + command);
        return 2;
    } catch (const std::exception& ex) {
        PrintErrorJson(ex.what());
        return 3;
    }
}

static std::vector<uint8_t> Base64Decode(const std::string& input) {
    auto decodeChar = [](char c) -> int {
        if (c >= 'A' && c <= 'Z') return c - 'A';
        if (c >= 'a' && c <= 'z') return c - 'a' + 26;
        if (c >= '0' && c <= '9') return c - '0' + 52;
        if (c == '+') return 62;
        if (c == '/') return 63;
        return -1;
    };

    std::vector<uint8_t> out;
    int val = 0;
    int valb = -8;
    for (char c : input) {
        if (c == '=' || c == '\r' || c == '\n' || c == ' ' || c == '\t') continue;
        const int decoded = decodeChar(c);
        if (decoded < 0) continue;
        val = (val << 6) + decoded;
        valb += 6;
        if (valb >= 0) {
            out.push_back(static_cast<uint8_t>((val >> valb) & 0xff));
            valb -= 8;
        }
    }
    return out;
}
