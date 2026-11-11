/*
 * Native Absinthe / NAC validation-data for macOS (Apple Silicon / Intel).
 * Calls NACInit / NACKeyEstablishment / NACSign inside identityservicesd
 * (same approach as Beeper mac-registration-provider).
 *
 * Build:
 *   clang -arch arm64 -O2 -framework Foundation -framework CoreFoundation \
 *     -o absinthe_nac absinthe_nac.c
 *
 * Usage:
 *   ./absinthe_nac --json
 *   ./absinthe_nac --json --offsets 0x10080cd50,0x100803720,0xSIGN
 */
#include <CoreFoundation/CoreFoundation.h>
#include <dlfcn.h>
#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>
#include <unistd.h>
#include <sys/stat.h>
#include <sys/utsname.h>

static const char *kIdsPath =
    "/System/Library/PrivateFrameworks/IDS.framework/"
    "identityservicesd.app/Contents/MacOS/identityservicesd";

static const char *kRefSym = "IDSProtoKeyTransparencyTrustedServiceReadFrom";
static const uint64_t kRefFileVA = 0x1002aef94ULL; /* macOS 27.2 / build 26B123 arm64e */

/* Discovered for sha256(identityservicesd)=cb97f17d… on macOS 27.2 arm64e */
static uint64_t gInitVA = 0x10080cd50ULL;
static uint64_t gKeyVA  = 0x100803720ULL;
static uint64_t gSignVA = 0; /* filled by discovery or --offsets */

typedef int (*nac_init_fn)(const void *cert, int cert_len,
                           void **out_ctx, void **out_req, int *out_req_len);
typedef int (*nac_key_fn)(void *ctx, const void *resp, int resp_len);
typedef int (*nac_sign_fn)(void *ctx, const void *unk, int unk_len,
                           void **out_data, int *out_len);

static void *gHandle;
static void *gRef;
static uintptr_t gSlide;
static nac_init_fn gInit;
static nac_key_fn gKey;
static nac_sign_fn gSign;

static void *va_to_ptr(uint64_t file_va) {
    return (void *)(gSlide + (uintptr_t)file_va);
}

static int load_ids(void) {
    gHandle = dlopen(kIdsPath, RTLD_LAZY);
    if (!gHandle) {
        fprintf(stderr, "dlopen identityservicesd: %s\n", dlerror());
        return -1;
    }
    gRef = dlsym(gHandle, kRefSym);
    if (!gRef) {
        fprintf(stderr, "dlsym %s: %s\n", kRefSym, dlerror());
        return -1;
    }
    gSlide = (uintptr_t)gRef - (uintptr_t)kRefFileVA;
    gInit = (nac_init_fn)va_to_ptr(gInitVA);
    gKey  = (nac_key_fn)va_to_ptr(gKeyVA);
    if (gSignVA)
        gSign = (nac_sign_fn)va_to_ptr(gSignVA);
    fprintf(stderr, "Absinthe: slide=0x%lx init=%p key=%p sign=%p\n",
            (unsigned long)gSlide, (void *)gInit, (void *)gKey, (void *)gSign);
    return 0;
}

/* --- minimal HTTP via CFNetwork (plist GET/POST) --- */

static CFDataRef http_exchange(CFStringRef url, CFDataRef body, CFStringRef method) {
    CFURLRef cfurl = CFURLCreateWithString(kCFAllocatorDefault, url, NULL);
    CFHTTPMessageRef req = CFHTTPMessageCreateRequest(
        kCFAllocatorDefault, method, cfurl, kCFHTTPVersion1_1);
    CFRelease(cfurl);
    CFHTTPMessageSetHeaderFieldValue(req, CFSTR("User-Agent"),
        CFSTR("com.apple.invitation-registration [macOS,27.2,26B123,Mac16,10]"));
    if (body) {
        CFHTTPMessageSetHeaderFieldValue(req, CFSTR("Content-Type"),
            CFSTR("application/x-apple-plist"));
        CFHTTPMessageSetBody(req, body);
    }

    CFReadStreamRef stream = CFReadStreamCreateForHTTPRequest(kCFAllocatorDefault, req);
    CFRelease(req);
    if (!CFReadStreamOpen(stream)) {
        CFRelease(stream);
        return NULL;
    }
    CFMutableDataRef out = CFDataCreateMutable(kCFAllocatorDefault, 0);
    UInt8 buf[4096];
    while (1) {
        CFIndex n = CFReadStreamRead(stream, buf, sizeof(buf));
        if (n < 0) { CFRelease(out); out = NULL; break; }
        if (n == 0) break;
        CFDataAppendBytes(out, buf, n);
    }
    CFReadStreamClose(stream);
    CFRelease(stream);
    return out;
}

static int fetch_cert(uint8_t **out, int *out_len) {
    CFDataRef resp = http_exchange(
        CFSTR("http://static.ess.apple.com/identity/validation/cert-1.0.plist"),
        NULL, CFSTR("GET"));
    if (!resp) return -1;
    CFPropertyListRef pl = CFPropertyListCreateWithData(
        kCFAllocatorDefault, resp, kCFPropertyListImmutable, NULL, NULL);
    CFRelease(resp);
    if (!pl || CFGetTypeID(pl) != CFDictionaryGetTypeID()) {
        if (pl) CFRelease(pl);
        return -2;
    }
    CFDataRef cert = CFDictionaryGetValue((CFDictionaryRef)pl, CFSTR("cert"));
    if (!cert || CFGetTypeID(cert) != CFDataGetTypeID()) {
        CFRelease(pl);
        return -3;
    }
    *out_len = (int)CFDataGetLength(cert);
    *out = (uint8_t *)malloc((size_t)*out_len);
    memcpy(*out, CFDataGetBytePtr(cert), (size_t)*out_len);
    CFRelease(pl);
    return 0;
}

static int initialize_validation(const void *req, int req_len,
                                 uint8_t **session, int *session_len) {
    CFDataRef reqData = CFDataCreate(kCFAllocatorDefault, req, req_len);
    CFMutableDictionaryRef dict = CFDictionaryCreateMutable(
        kCFAllocatorDefault, 1, &kCFTypeDictionaryKeyCallBacks, &kCFTypeDictionaryValueCallBacks);
    CFDictionarySetValue(dict, CFSTR("session-info-request"), reqData);
    CFRelease(reqData);
    CFErrorRef err = NULL;
    CFDataRef body = CFPropertyListCreateData(
        kCFAllocatorDefault, dict, kCFPropertyListXMLFormat_v1_0, 0, &err);
    CFRelease(dict);
    if (!body) return -1;

    CFDataRef resp = http_exchange(
        CFSTR("https://identity.ess.apple.com/WebObjects/TDIdentityService.woa/wa/initializeValidation"),
        body, CFSTR("POST"));
    CFRelease(body);
    if (!resp) return -2;

    CFPropertyListRef pl = CFPropertyListCreateWithData(
        kCFAllocatorDefault, resp, kCFPropertyListImmutable, NULL, NULL);
    CFRelease(resp);
    if (!pl || CFGetTypeID(pl) != CFDictionaryGetTypeID()) {
        if (pl) CFRelease(pl);
        return -3;
    }
    CFDataRef info = CFDictionaryGetValue((CFDictionaryRef)pl, CFSTR("session-info"));
    if (!info || CFGetTypeID(info) != CFDataGetTypeID()) {
        CFRelease(pl);
        return -4;
    }
    *session_len = (int)CFDataGetLength(info);
    *session = (uint8_t *)malloc((size_t)*session_len);
    memcpy(*session, CFDataGetBytePtr(info), (size_t)*session_len);
    CFRelease(pl);
    return 0;
}

static char *b64_encode(const uint8_t *data, int len) {
    static const char tbl[] =
        "ABCDEFGHIJKLMNOPQRSTUVWXYZabcdefghijklmnopqrstuvwxyz0123456789+/";
    int out_len = 4 * ((len + 2) / 3);
    char *out = (char *)malloc((size_t)out_len + 1);
    int i = 0, j = 0;
    while (i < len) {
        uint32_t v = (uint32_t)data[i++] << 16;
        if (i < len) v |= (uint32_t)data[i++] << 8;
        if (i < len) v |= (uint32_t)data[i++];
        out[j++] = tbl[(v >> 18) & 63];
        out[j++] = tbl[(v >> 12) & 63];
        out[j++] = (i > len + 1) ? '=' : tbl[(v >> 6) & 63];
        out[j++] = (i > len) ? '=' : tbl[v & 63];
        /* fix padding logic */
    }
    /* redo properly */
    free(out);
    out = (char *)malloc((size_t)out_len + 1);
    j = 0;
    for (i = 0; i < len; i += 3) {
        int rem = len - i;
        uint32_t v = ((uint32_t)data[i]) << 16;
        if (rem > 1) v |= ((uint32_t)data[i + 1]) << 8;
        if (rem > 2) v |= (uint32_t)data[i + 2];
        out[j++] = tbl[(v >> 18) & 63];
        out[j++] = tbl[(v >> 12) & 63];
        out[j++] = (rem > 1) ? tbl[(v >> 6) & 63] : '=';
        out[j++] = (rem > 2) ? tbl[v & 63] : '=';
    }
    out[j] = 0;
    return out;
}

/* Try to discover NACSign: after KeyEst, call candidate as Sign(ctx,NULL,0,&out,&len). */
static int discover_sign(void *ctx) {
    /* Candidates: PACIBSP entries before KeyEst (Sign is typically earliest of the trio). */
    static const uint64_t cands[] = {
        0x1007d0000ULL, /* placeholder range scanned below via external list */
    };
    (void)cands;
    (void)ctx;
    return -1;
}

static int try_sign_va(void *ctx, uint64_t va, uint8_t **out, int *out_len) {
    nac_sign_fn fn = (nac_sign_fn)va_to_ptr(va);
    void *data = NULL;
    int len = 0;
    int rc = fn(ctx, NULL, 0, &data, &len);
    if (rc == 0 && data && len > 32) {
        *out = (uint8_t *)malloc((size_t)len);
        memcpy(*out, data, (size_t)len);
        *out_len = len;
        gSignVA = va;
        gSign = fn;
        return 0;
    }
    return rc == 0 ? -1 : rc;
}

static int read_sign_list(const char *path, uint64_t **out, int *n) {
    FILE *f = fopen(path, "r");
    if (!f) return -1;
    uint64_t *arr = NULL;
    int cap = 0, count = 0;
    char line[128];
    while (fgets(line, sizeof(line), f)) {
        char *end = NULL;
        uint64_t v = strtoull(line, &end, 0);
        if (end == line) continue;
        if (count >= cap) {
            cap = cap ? cap * 2 : 64;
            arr = (uint64_t *)realloc(arr, sizeof(uint64_t) * (size_t)cap);
        }
        arr[count++] = v;
    }
    fclose(f);
    *out = arr;
    *n = count;
    return 0;
}

static void print_json(const uint8_t *data, int len, const char *serial, const char *source) {
    char *b64 = b64_encode(data, len);
    printf("{\"ok\":true,\"validation_data_b64\":\"%s\",\"length\":%d,"
           "\"serial\":%s%s%s,\"source\":\"%s\","
           "\"offsets\":{\"init\":\"0x%llx\",\"key\":\"0x%llx\",\"sign\":\"0x%llx\"}}\n",
           b64, len,
           serial ? "\"" : "null", serial ? serial : "", serial ? "\"" : "",
           source,
           (unsigned long long)gInitVA,
           (unsigned long long)gKeyVA,
           (unsigned long long)gSignVA);
    free(b64);
}

static void usage(const char *argv0) {
    fprintf(stderr,
        "Usage: %s [--json] [--offsets init,key,sign] [--sign-list path]\n"
        "Native Absinthe NAC via identityservicesd (macOS).\n", argv0);
}

int main(int argc, char **argv) {
    int want_json = 0;
    const char *sign_list = NULL;
    for (int i = 1; i < argc; i++) {
        if (!strcmp(argv[i], "--json")) want_json = 1;
        else if (!strcmp(argv[i], "--help") || !strcmp(argv[i], "-h")) {
            usage(argv[0]); return 0;
        } else if (!strcmp(argv[i], "--offsets") && i + 1 < argc) {
            char *s = argv[++i];
            gInitVA = strtoull(s, &s, 0);
            if (*s == ',') gKeyVA = strtoull(s + 1, &s, 0);
            if (*s == ',') gSignVA = strtoull(s + 1, &s, 0);
        } else if (!strcmp(argv[i], "--sign-list") && i + 1 < argc) {
            sign_list = argv[++i];
        } else {
            usage(argv[0]); return 2;
        }
    }

    if (load_ids() != 0) return 1;

    /* Sanity: NACInit(NULL) → -44023 */
    {
        void *c = NULL, *r = NULL; int rl = 0;
        int rc = gInit(NULL, 0, &c, &r, &rl);
        if (rc != -44023) {
            fprintf(stderr, "NACInit sanity unexpected rc=%d (want -44023). Offsets wrong for this OS?\n", rc);
            return 3;
        }
        fprintf(stderr, "NACInit sanity OK (-44023)\n");
    }

    uint8_t *cert = NULL; int cert_len = 0;
    if (fetch_cert(&cert, &cert_len) != 0) {
        fprintf(stderr, "fetch cert failed\n");
        return 4;
    }
    fprintf(stderr, "cert %d B\n", cert_len);

    void *ctx = NULL, *req = NULL; int req_len = 0;
    int rc = gInit(cert, cert_len, &ctx, &req, &req_len);
    free(cert);
    if (rc != 0 || !ctx || !req || req_len <= 0) {
        fprintf(stderr, "NACInit failed rc=%d\n", rc);
        return 5;
    }
    fprintf(stderr, "NACInit OK request %d B\n", req_len);

    uint8_t *session = NULL; int session_len = 0;
    if (initialize_validation(req, req_len, &session, &session_len) != 0) {
        fprintf(stderr, "initializeValidation failed\n");
        return 6;
    }
    fprintf(stderr, "initializeValidation OK session %d B\n", session_len);

    rc = gKey(ctx, session, session_len);
    free(session);
    if (rc != 0) {
        fprintf(stderr, "NACKeyEstablishment failed rc=%d\n", rc);
        return 7;
    }
    fprintf(stderr, "NACKeyEstablishment OK\n");

    uint8_t *val = NULL; int val_len = 0;
    if (gSignVA) {
        rc = try_sign_va(ctx, gSignVA, &val, &val_len);
        if (rc != 0) {
            fprintf(stderr, "NACSign failed rc=%d\n", rc);
            return 8;
        }
    } else {
        uint64_t *list = NULL; int n = 0;
        if (!sign_list || read_sign_list(sign_list, &list, &n) != 0) {
            fprintf(stderr, "NACSign offset unknown. Pass --offsets init,key,sign or --sign-list.\n");
            return 9;
        }
        int found = 0;
        for (int i = 0; i < n; i++) {
            if (try_sign_va(ctx, list[i], &val, &val_len) == 0) {
                fprintf(stderr, "NACSign discovered at 0x%llx (%d B)\n",
                        (unsigned long long)list[i], val_len);
                found = 1;
                break;
            }
        }
        free(list);
        if (!found) {
            fprintf(stderr, "NACSign not found in candidate list\n");
            return 10;
        }
    }

    fprintf(stderr, "validation-data %d B\n", val_len);
    if (want_json) {
        /* serial via IOKit would be nice; leave null for now */
        print_json(val, val_len, NULL, "absinthe-native");
    } else {
        char *b64 = b64_encode(val, val_len);
        puts(b64);
        free(b64);
    }
    free(val);
    return 0;
}
