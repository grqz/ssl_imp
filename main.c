#ifdef _WIN32
#ifndef WIN32_LEAN_AND_MEAN
#define WIN32_LEAN_AND_MEAN
#endif

#include <windows.h>
#include <WinSock2.h>
#include <Ws2tcpip.h>

typedef SOCKET platform_socket;
#define GET_SOCKET_ERROR() WSAGetLastError()
#define SOCKFD_CLOSE(sock) closesocket(sock)
#define SOCKFD_INVALID INVALID_SOCKET
#define SOCKFD_IS_INVALID(sock) sock == INVALID_SOCKET
#define SOCKET_CLEANUP() WSACleanup()
#else
#ifndef _POSIX_C_SOURCE
#define _POSIX_C_SOURCE 200112L
#endif

#include <arpa/inet.h>
#include <netinet/in.h>
#include <sys/types.h>
#include <sys/socket.h>
#include <netdb.h>
#include <unistd.h>


typedef int platform_socket;
#define GET_SOCKET_ERROR() errno
#define SOCKFD_CLOSE(sock) close(sock)
#define SOCKFD_INVALID -1
#define SOCKFD_IS_INVALID(sock) ((sock) < 0)
#define SOCKET_CLEANUP()
#endif

#ifdef _MSC_VER
#define _compiler_ALWAYS_INLINE __forceinline
#elif defined(__clang__) || defined(__GNUC__)
#define _compiler_ALWAYS_INLINE __attribute__((always_inline))
#else
#define _compiler_ALWAYS_INLINE
#endif

#include <openssl/ssl.h>
#include <openssl/err.h>
#include <openssl/rand.h>

#include <stdio.h>
#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <errno.h>
#include <limits.h>
#include <inttypes.h>

static inline _compiler_ALWAYS_INLINE
const uint8_t **_pkt_internal_check_ppu8c(const uint8_t **p) { return p; }
#define DEFINE_CAST(Type) \
    static inline _compiler_ALWAYS_INLINE \
    Type _pkt_internal_cast_##Type(Type x) { return x; }
DEFINE_CAST(uint8_t)
DEFINE_CAST(uint16_t)
DEFINE_CAST(uint32_t)
DEFINE_CAST(uint64_t)
#define _pkt_internal_pu8c(p) (*_pkt_internal_check_ppu8c(p))
#define _pkt_internal_cast(Type, x) (_pkt_internal_cast_##Type(x))
#define PKT_GETU8(p) _pkt_internal_cast(uint8_t, *(_pkt_internal_pu8c(p)++))
#define PKT_GETU16(p) _pkt_internal_cast(uint16_t, ((uint16_t)PKT_GETU8(p) << 8) + PKT_GETU8(p))

typedef struct tls_1_3_alps_cfg_st {
    const uint8_t *proto;  // the protocol ALPN string, e.g., { 'h', '2' }
    size_t proto_len;  // the protocol string length, e.g., 2 for h2
    const uint8_t *settings;
    size_t settings_len;
} TLS13_ALPS_CFG;

typedef struct tls_1_3_alps_add_arg_st {
    size_t cfg_size;
    TLS13_ALPS_CFG *cfgs;
} TLS13_ALPS_ADD_ARG;

typedef struct alps_store_st {
    const uint8_t *data;
    size_t len;
} ALPS_STORE;

/* returns true if the error is fatal (SSL_shutdown MUST NOT be called),
 * false if shutdown is safe to attempt
 */
static inline
unsigned char handle_ossl_err(SSL *ssl, int *pres, const char *desc) {
    int res = *pres;
    int errc = SSL_get_error(ssl, res);
    // TODO: make this more informative
    fprintf(stderr, "Error code from %s: SSL error %d, return value %d\n", desc, errc, res);
    *pres = errc;
    if (errc == SSL_ERROR_SSL) {
        ERR_print_errors_fp(stderr);
        return 1;
    }
    else if (errc == SSL_ERROR_SYSCALL) {
        fprintf(stderr, "SSL_ERROR_SYSCALL, socket error: %d\n", GET_SOCKET_ERROR());
        return 1;
    }
    return 0;
}

static const size_t exdata_size_table[] = {
    sizeof(ALPS_STORE),
    #define EXDATA_ID_SSL_ALPSDATA 0
};

static int exdata_idx[sizeof(exdata_size_table) - 1];

static inline
void _osslcb_exdata_new(
    void *parent, void *ptr, CRYPTO_EX_DATA *ad,
    int idx, long argl, void *argp
) {
    void *store = calloc(1, exdata_size_table[argl]);
    SSL_set_ex_data(parent, idx, store);
}

static inline
void _osslcb_exdata_free(
    void *parent, void *ptr, CRYPTO_EX_DATA *ad,
    int idx, long argl, void *argp
) {
    free(ptr);
}

static inline
int _osslcb_exdata_dup(
    CRYPTO_EX_DATA *to, const CRYPTO_EX_DATA *from,
    void **from_d, int idx, long argl, void *argp
) {
    void *store = malloc(exdata_size_table[argl]);
    if (!store)
        return 0;
    memcpy(store, *from_d, exdata_size_table[argl]);
    *from_d = store;
    return 1;
}

FILE *sslkeylogfile = NULL;
unsigned char keylogfile_err = 0;
static inline
void _osslcb_keylog_func(const SSL *ssl, const char *line) {
    if (!sslkeylogfile) {
        if (keylogfile_err) return;
        const char *filename = getenv("SSLKEYLOGFILE");
        if (!filename) {
            keylogfile_err = 1;
            return;
        }
        // append binary to avoid windows from automatically replacing \n with \r\n
        sslkeylogfile = fopen(filename, "ab");
        if (!sslkeylogfile) {
            keylogfile_err = 1;
            perror("fopen SSLKEYLOGFILE");
            return;
        }
        fprintf(stderr, "Opened SSLKEYLOGFILE @ %s!\n", filename);
    }
    fputs(line, sslkeylogfile);
    fputc('\n', sslkeylogfile);
    fprintf(stderr, "SSLKEYLOG: %s\n", line);
}

#ifndef TLSEXT_TYPE_application_settings
#define TLSEXT_TYPE_application_settings 17613
#endif

#ifndef TLSEXT_TYPE_encrypted_client_hello
#define TLSEXT_TYPE_encrypted_client_hello 65037
#endif

static const unsigned char h2_alpn[2] = "h2";
static const unsigned char invalidh2_alpn[9] = "hINVALID2";

static inline
void _x_SSL_get0_peer_application_settings(
    const SSL *ssl,
    const uint8_t **out_data,
    size_t *out_len
) {
    ALPS_STORE *palps_store = SSL_get_ex_data(ssl, exdata_idx[EXDATA_ID_SSL_ALPSDATA]);
    if (!palps_store) {
        *out_len = 0;
        return;
    } else {
        *out_data = palps_store->data;
        *out_len = palps_store->len;
    }
}
static inline
int _x_SSL_has_application_settings(const SSL *ssl) {
    return !!SSL_get_ex_data(ssl, exdata_idx[EXDATA_ID_SSL_ALPSDATA]);
}

static inline
int _osslcb_custom_ext_add_cb_ex(
    SSL *s, unsigned int ext_type,
    unsigned int context,
    const unsigned char **out,
    size_t *outlen, X509 *x,
    size_t chainidx, int *al,
    void *add_arg
) {
    switch (ext_type)
    {
    case TLSEXT_TYPE_application_settings:;
        const TLS13_ALPS_ADD_ARG *palps_add_arg = add_arg;
        if (context & SSL_EXT_CLIENT_HELLO) {
            const size_t cfgs_size = palps_add_arg->cfg_size;
            const TLS13_ALPS_CFG *cfgs = palps_add_arg->cfgs;
            unsigned char *ptr;
            uint16_t msg_size;
            {
                size_t supported_protos_size = cfgs_size;
                for (size_t i = 0; i < cfgs_size; ++i)
                    supported_protos_size += cfgs[i].proto_len;
                if (supported_protos_size > UINT16_MAX) {
                    fprintf(stderr, "Supported Protocols too large\n");
                    return *al = SSL_AD_INTERNAL_ERROR, -1;
                }
                msg_size = (uint16_t)supported_protos_size;
                *out = ptr = (unsigned char *)malloc(*outlen = supported_protos_size + 2);
                if (!ptr) {
                    fprintf(stderr, "malloc failure\n");
                    return *al = SSL_AD_INTERNAL_ERROR, -1;
                }
            }
            *(uint16_t *)ptr = htons(msg_size); ptr += 2;  // payload len
            for (size_t i = 0; i < cfgs_size; ++i) {
                const TLS13_ALPS_CFG *current_cfg = (cfgs + i);
                if (current_cfg->proto_len > UINT8_MAX) {
                    fprintf(stderr, "Protocol Name too long\n");
                    return *al = SSL_AD_INTERNAL_ERROR, -1;
                }
                *(ptr++) = (uint8_t)current_cfg->proto_len;
                memcpy(ptr, current_cfg->proto, current_cfg->proto_len);
                ptr += current_cfg->proto_len;
            }
#ifndef NDEBUG
            if (ptr - *out - *outlen != 0) {
                fprintf(stderr, "Error serialising ALPS-CH: allocated %zu, used %zu\n", *outlen, ptr - *out);
                free((unsigned char *)*out);
                return *al = SSL_AD_INTERNAL_ERROR, -1;
            }
#endif
            return 1;
        }
        else return *al = SSL_AD_INTERNAL_ERROR, -1;
    case TLSEXT_TYPE_encrypted_client_hello:;
        const uint16_t n_enc = 32;  // precondition: n_enc
        const uint16_t n_tag = 16;
        const uint8_t maximum_name_length = 255;  // ECHConfig.maximum_name_length

        unsigned char extlen_and_cfg_id[2];
        if (RAND_bytes(extlen_and_cfg_id, 2) != 1) {
            fprintf(stderr, "RAND_bytes failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
            return *al = SSL_AD_INTERNAL_ERROR, -1;
        }

        // 105 is the minimum CH, plus 32 for some misc extensions, and a random 0~31 length for some other extensions
        const uint16_t ich_snipadded_len = 105 + 32 + (extlen_and_cfg_id[0] & 31) + maximum_name_length + 9;
        const uint16_t payld_size = ich_snipadded_len + 31 - ((ich_snipadded_len - 1) % 32) + n_tag;

        unsigned char *ptr = malloc(*outlen = 10 + n_enc + payld_size);
        *out = ptr;
        if (ptr == NULL) {
            fprintf(stderr, "malloc failure\n");
            return *al = SSL_AD_INTERNAL_ERROR, -1;
        }
        /*
            enum { outer(0), inner(1) } ECHClientHelloType;
            struct {
            ECHClientHelloType type;
            select (ECHClientHello.type) {
                case outer:
                    HpkeSymmetricCipherSuite cipher_suite;
                    uint8 config_id;
                    opaque enc<0..2^16-1>;
                    opaque payload<1..2^16-1>;
                case inner:
                    Empty;
            };
            } ECHClientHello;
         */
        *(ptr++) = 0x00;  // outer
        *(ptr++) = 0x00; *(ptr++) = 0x01;  // cipher_suite.kdf_id = HKDF_SHA256
        *(ptr++) = 0x00; *(ptr++) = 0x01;  // cipher_suite.aead_id = AES_128_GCM
        *(ptr++) = extlen_and_cfg_id[1];  // config_id
        *(uint16_t *)ptr = htons(n_enc); ptr += 2;  // enc len
        if (RAND_bytes(ptr, n_enc) != 1) {  // enc
            fprintf(stderr, "RAND_bytes failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
            free((unsigned char *)*out);
            return *al = SSL_AD_INTERNAL_ERROR, -1;
        }
        ptr += n_enc;
        *(uint16_t *)ptr = htons(payld_size); ptr += 2;  // payload len
        if (RAND_bytes(ptr, payld_size) != 1) {  // payload
            fprintf(stderr, "RAND_bytes failed: %s\n", ERR_error_string(ERR_get_error(), NULL));
            free((unsigned char *)*out);
            return *al = SSL_AD_INTERNAL_ERROR, -1;
        }

#ifndef NDEBUG
        if (ptr - *out + payld_size - *outlen != 0) {
            fprintf(stderr, "Error serialising ECH: expected ech_size %zu, got %zu\n", *outlen, ptr - *out + payld_size);
            free((unsigned char *)*out);
            return *al = SSL_AD_INTERNAL_ERROR, -1;
        }
#endif
        // fallthrough magic comment
        // fall through
    case 0x0a0a:;  // GREASE
        return 1;
    default:;
        return *al = SSL_AD_INTERNAL_ERROR, -1;
    }
}

static inline
void _osslcb_custom_ext_free_cb_ex(
    SSL *s, unsigned int ext_type,
    unsigned int context,
    const unsigned char *out,
    void *add_arg
) {
    switch (ext_type)
    {
    case TLSEXT_TYPE_application_settings:;
        // fallthrough magic comment
        // fall through
    case TLSEXT_TYPE_encrypted_client_hello:;
        free((unsigned char *)out);
        // fallthrough magic comment
        // fall through
    case 0x0a0a:;
        // fallthrough magic comment
        // fall through
    default:;
        return;
    }
}

static inline
int _osslcb_custom_ext_parse_cb_ex(
    SSL *s, unsigned int ext_type,
    unsigned int context,
    const unsigned char *in,
    size_t inlen, X509 *x,
    size_t chainidx, int *al,
    void *parse_arg
) {
    switch (ext_type)
    {
    case 0x0a0a:;  // GREASE
        return 1;  // success
    case TLSEXT_TYPE_encrypted_client_hello:;
        // check the extension syntactically and abort the connection
        // with a "decode_error" alert if it is invalid
        if (context & SSL_EXT_TLS1_3_HELLO_RETRY_REQUEST) {
            // HRR
            /**struct {
             *     opaque confirmation[8];
             * } ECHHelloRetryRequest;
             */
            if (inlen != 8)
                return *al = SSL_AD_DECODE_ERROR, -1;
            return 1;
        }
        else if (context & SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS) {
            // Server EE
            /**struct {
             *     ECHConfigList retry_configs;
             * } ECHEncryptedExtensions;
             * ECHConfig ECHConfigList<4..2^16-1>;
             */
            // End of packet. Must not be dereferenced
            const unsigned char *pend = in + inlen;

            if (inlen < 2)
                return *al = SSL_AD_DECODE_ERROR, -1;
            uint16_t len_echcfg = PKT_GETU16(&in);
            if (len_echcfg + sizeof(uint16_t) - inlen != 0)
                return *al = SSL_AD_DECODE_ERROR, -1;
            fprintf(stderr,
                "Received ECH Server EncryptedExtensions, length %" PRIu16 "\n",
                len_echcfg);
            do {
                /**struct {
                 *     uint16 version;
                 *     uint16 length;
                 *     select (ECHConfig.version) {
                 *         case 0xfe0d: ECHConfigContents contents;
                 *     }
                 *  } ECHConfig;
                 */
                if (pend - in < 4)
                    return *al = SSL_AD_DECODE_ERROR, -1;
                uint16_t version = PKT_GETU16(&in);
                uint16_t length = PKT_GETU16(&in);
                fprintf(stderr,
                    "ECHConfig common: version %" PRIu16 ", length %" PRIu16 "\n",
                    version, length);
                if (version == TLSEXT_TYPE_encrypted_client_hello) {
                    /**struct {
                     *     HpkeKeyConfig key_config;
                     *     uint8 maximum_name_length;
                     *     opaque public_name<1..255>;
                     *     ECHConfigExtension extensions<0..2^16-1>;
                     * } ECHConfigContents;  // 17 bytes minimum
                     */
                    if (pend - in < 17)
                        return *al = SSL_AD_DECODE_ERROR, -1;
                    /**struct {
                     *     uint8 config_id;
                     *     HpkeKemId kem_id;
                     *     HpkePublicKey public_key;
                     *     HpkeSymmetricCipherSuite cipher_suites<4..2^16-4>;
                     * } HpkeKeyConfig;  // 12 bytes minimum
                     *
                     * opaque HpkePublicKey<1..2^16-1>;
                     * uint16 HpkeKemId;              // Defined in RFC9180
                     * struct {
                     *     HpkeKdfId kdf_id;
                     *     HpkeAeadId aead_id;
                     * } HpkeSymmetricCipherSuite;  // 4 bytes minimum
                     * uint16 HpkeKdfId;              // Defined in RFC9180
                     * uint16 HpkeAeadId;             // Defined in RFC9180
                     */
                    uint8_t kcfg_config_id = PKT_GETU8(&in);
                    uint16_t kcfg_kem_id = PKT_GETU16(&in);

                    uint16_t kcfg_pubkey_len = PKT_GETU16(&in);
                    if (!kcfg_pubkey_len)
                        return *al = SSL_AD_DECODE_ERROR, -1;
                    in += kcfg_pubkey_len;  // opaque pubkey
                    if (pend - in < 11)
                        return *al = SSL_AD_DECODE_ERROR, -1;

                    uint16_t kcfg_cs_len = PKT_GETU16(&in);
                    if (kcfg_cs_len & 3 || !kcfg_cs_len)
                        return *al = SSL_AD_DECODE_ERROR, -1;
                    in += kcfg_cs_len;
                    if (pend - in < 5)
                        return *al = SSL_AD_DECODE_ERROR, -1;

                    fprintf(stderr,
                        "ECHConfigContents.key_config = { .config_id=%" PRIu8 ", .kem_id=%" PRIu16
                        ", .public_key=<%" PRIu16 " bytes opaque>, .cipher_suites=<%" PRIu16 " cipher suites> }\n",
                        kcfg_config_id, kcfg_kem_id, kcfg_pubkey_len, kcfg_cs_len >> 2);

                    uint8_t maximum_name_length = PKT_GETU8(&in);

                    uint8_t public_name_len = PKT_GETU8(&in);
                    if (!public_name_len)  // 1..255
                        return *al = SSL_AD_DECODE_ERROR, -1;
                    in += public_name_len;
                    if (pend - in < 2)
                        return *al = SSL_AD_DECODE_ERROR, -1;

                    uint16_t extensions_len = PKT_GETU16(&in);

                    fprintf(stderr,
                        "ECHConfigContents: { .maximum_name_length=%" PRIu8 ", .public_name=<%" PRIu8 " bytes opaque>, .extensions=<%" PRIu16 " bytes> }\n",
                        maximum_name_length, public_name_len, extensions_len);
                    if (extensions_len) {
                        /**struct {
                         *     ECHConfigExtensionType type;
                         *     opaque data<0..2^16-1>;
                         * } ECHConfigExtension;  // 4 bytes minimum
                         * uint16 ECHConfigExtensionType; // Defined in Section 11.3
                         */
                        if (pend - in < 4)
                            return *al = SSL_AD_DECODE_ERROR, -1;
                        uint16_t echext_type = PKT_GETU16(&in);
                        uint16_t echext_data_len = PKT_GETU16(&in);
                        in += echext_data_len;
                        if (pend < in)
                            return *al = SSL_AD_DECODE_ERROR, -1;
                        fprintf(stderr,
                            "ECHConfigExtension: { .type=%" PRIu16 ", .data=<%" PRIu16 " bytes opaque> }\n",
                            echext_type, echext_data_len);
                    }
                }
            } while (in < pend);
            if (in != pend)
                return *al = SSL_AD_DECODE_ERROR, -1;

            return 1;
        }
        else
            return *al = SSL_AD_UNEXPECTED_MESSAGE, -1;
    case TLSEXT_TYPE_application_settings:;
        if (context & SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS) {
            ALPS_STORE *palps_store = SSL_get_ex_data(s, exdata_idx[EXDATA_ID_SSL_ALPSDATA]);
            palps_store->len = inlen;
            palps_store->data = in;
            fputs(
                "WARNING: Server encrypted extensions received, "
                "but we cannot send ours due to limitations of OpenSSL! "
                "Try using an invalid ALPN for negotiation!\n", stderr);
            return 1;
        }
        // fallthrough magic comment
        // fall through
    default:;
        *al = SSL_AD_UNEXPECTED_MESSAGE;
        return 0;
    }
}

#define REQUEST_VSN_MINOR "0"

#define REQUEST_HOSTNAME "tls.browserleaks.com"
#define REQUEST_PATH "/json"

// #define REQUEST_VSN_MINOR "1"
// #define REQUEST_HOSTNAME "www.nytimes.com"
// #define REQUEST_PATH "/2023/12/02/business/air-traffic-controllers-safety.html"

int main(void) {
    fputs("start\n", stderr);

    exdata_idx[EXDATA_ID_SSL_ALPSDATA] = SSL_get_ex_new_index(
        EXDATA_ID_SSL_ALPSDATA, NULL,
        _osslcb_exdata_new, _osslcb_exdata_dup, _osslcb_exdata_free);

    const char hn[] = REQUEST_HOSTNAME;

    const char httpreq[] =
        "GET " REQUEST_PATH " HTTP/1." REQUEST_VSN_MINOR "\r\n"
        "Host: " REQUEST_HOSTNAME "\r\n"
        // "Accept: text/html,application/xhtml+xml,application/xml;q=0.9,image/avif,image/webp,image/apng,*/*;q=0.8,application/signed-exchange;v=b3;q=0.7\r\n"
        // "Accept-Encoding: gzip, deflate, br, zstd\r\n"
        "Accept-Language: en-US,en;q=0.9\r\n"
        "Cache-Control: no-cache\r\n"
        "Pragma: no-cache\r\n"
        "Priority: u=0, i\r\n"
        "Sec-Ch-Ua: \"Not;A=Brand\";v=\"99\", \"Google Chrome\";v=\"139\", \"Chromium\";v=\"139\"\r\n"
        "Sec-ch-ua-mobile: ?0\r\n"
        "Sec-ch-ua-platform: \"Windows\"\r\n"
        "Sec-Fetch-Dest: document\r\n"
        "Sec-Fetch-Mode: navigate\r\n"
        "Sec-Fetch-Site: none\r\n"
        "Sec-Fetch-User: ?1\r\n"
        "Upgrade-Insecure-Requests: 1\r\n"
        "User-Agent: Mozilla/5.0 (Windows NT 10.0; Win64; x64) AppleWebKit/537.36 (KHTML, like Gecko) Chrome/139.0.0.0 Safari/537.36\r\n"
        "\r\n";


    const int httpreq_size = sizeof(httpreq) - 1;
    int ret = 2;

#ifdef _WIN32
    {
        WSADATA wsa;
        int res = WSAStartup(MAKEWORD(2, 2), &wsa);
        if (res != 0) {
            fprintf(stderr, "WSAStartup failed with %d", res);
            return 1;
        }
    }
#endif
    platform_socket sock = SOCKFD_INVALID;
    struct sockaddr_storage addr;
    size_t addrlen;
    {
        struct addrinfo *ai_result;
        int res = getaddrinfo(hn, "443", NULL, &ai_result);
        if (res != 0) {
            fprintf(stderr, "Error resolving hostname: %s(%#x)", gai_strerror(res), res);
            ret = 1;
            goto free_wsa;
        }
        if (ai_result == 0) {
            fputs("Error resolving hostname: Unexpeced NULL ai_result", stderr);
            ret = 1;
            goto free_wsa;
        }
        for (struct addrinfo *it = ai_result; it != NULL; it = it->ai_next) {
            sock = socket(it->ai_family, it->ai_socktype, it->ai_protocol);
            if (SOCKFD_IS_INVALID(sock)) continue;

            addrlen = it->ai_addrlen;
            memcpy(&addr, it->ai_addr, addrlen);
            break;
        }
        freeaddrinfo(ai_result);
    }
    if (SOCKFD_IS_INVALID(sock)) {
        fputs("Failed to create a socket from getaddrinfo result\n", stderr);
        ret = 1;
        goto free_wsa;
    }
    
    SSL_CTX *ssl_ctx = SSL_CTX_new(TLS_client_method());
    if (ssl_ctx == NULL) {
        fputs("Error creating SSL_CTX object:\n", stderr);
        ERR_print_errors_fp(stderr);
        ret = 1;
        goto free_sock;
    }

    // Configure SSL_CTX
    SSL_CTX_set_keylog_callback(ssl_ctx, _osslcb_keylog_func);

    if (!SSL_CTX_set_min_proto_version(ssl_ctx, TLS1_2_VERSION))
        fputs("Warning: SSL_CTX_set_min_proto_version failed\n", stderr);
    if (!SSL_CTX_set_max_proto_version(ssl_ctx, TLS1_3_VERSION))
        fputs("Warning: SSL_CTX_set_max_proto_version failed\n", stderr);

    // TLS 1.3 ciphersuites
    if (!SSL_CTX_set_ciphersuites(ssl_ctx, "TLS_AES_128_GCM_SHA256:TLS_AES_256_GCM_SHA384:TLS_CHACHA20_POLY1305_SHA256"))
        fputs("Warning: SSL_CTX_set_ciphersuites failed\n", stderr);
    // TLS 1.2 and lower cipher list
    if (!SSL_CTX_set_cipher_list(ssl_ctx, "TLS_ECDHE_ECDSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_RSA_WITH_AES_128_GCM_SHA256:TLS_ECDHE_ECDSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_RSA_WITH_AES_256_GCM_SHA384:TLS_ECDHE_ECDSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_CHACHA20_POLY1305_SHA256:TLS_ECDHE_RSA_WITH_AES_128_CBC_SHA:TLS_ECDHE_RSA_WITH_AES_256_CBC_SHA:TLS_RSA_WITH_AES_128_GCM_SHA256:TLS_RSA_WITH_AES_256_GCM_SHA384:TLS_RSA_WITH_AES_128_CBC_SHA:TLS_RSA_WITH_AES_256_CBC_SHA"))
        fputs("Warning: SSL_CTX_set_cipher_list failed\n", stderr);

    SSL_CTX_clear_options(ssl_ctx, SSL_OP_LEGACY_EC_POINT_FORMATS);
    SSL_CTX_set_options(ssl_ctx, SSL_OP_NO_ENCRYPT_THEN_MAC);
    if (!SSL_CTX_set1_groups_list(ssl_ctx, "*X25519MLKEM768:*X25519:secp256r1:secp384r1"))
        fputs("Warning: SSL_CTX_set1_groups_list failed\n", stderr);

    if (!SSL_CTX_set1_sigalgs_list(ssl_ctx, "ecdsa_secp256r1_sha256:rsa_pss_rsae_sha256:rsa_pkcs1_sha256:ecdsa_secp384r1_sha384:rsa_pss_rsae_sha384:rsa_pkcs1_sha384:rsa_pss_rsae_sha512:rsa_pkcs1_sha512"))
        fputs("Warning: SSL_CTX_set1_sigalgs_list failed\n", stderr);

    // Requires OpenSSL to be built with brotli
    int algs[] = {TLSEXT_comp_cert_brotli};
    if (!SSL_CTX_set1_cert_comp_preference(ssl_ctx, algs, 1))
        fputs("Warning: SSL_CTX_set1_cert_comp_preference failed\n", stderr);

    if (!SSL_CTX_set_tlsext_status_type(ssl_ctx, TLSEXT_STATUSTYPE_ocsp))
        fputs("Warning: SSL_CTX_set_tlsext_status_type failed\n", stderr);

    unsigned char alpn[] = {
        9, 'h', 'I', 'N', 'V', 'A', 'L', 'I', 'D', '2',
        8, 'h', 't', 't', 'p', '/', '1', '.', *REQUEST_VSN_MINOR,
    };
    /* SSL_CTX_set_alpn_protos returns 0 for success! */
    if (SSL_CTX_set_alpn_protos(ssl_ctx, alpn, sizeof(alpn)))
        fputs("Warning: SSL_CTX_set_alpn_protos failed\n", stderr);

    if (!SSL_CTX_enable_ct(ssl_ctx, SSL_CT_VALIDATION_PERMISSIVE))
        fputs("Warning: SSL_CTX_enable_ct failed\n", stderr);

    // TODO: shuffle GREASE, ALPS, ECH
    if (!SSL_CTX_add_custom_ext(
            ssl_ctx, 0x0a0a,
            SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_SERVER_HELLO | SSL_EXT_TLS_IMPLEMENTATION_ONLY | SSL_EXT_TLS1_3_ONLY,
            _osslcb_custom_ext_add_cb_ex, _osslcb_custom_ext_free_cb_ex, NULL,
            _osslcb_custom_ext_parse_cb_ex, NULL))
        fputs("Warning: SSL_CTX_add_custom_ext failed for GREASE(0a0a)\n", stderr);

    TLS13_ALPS_CFG h2cfg = {
        .proto=invalidh2_alpn,
        .proto_len=sizeof(invalidh2_alpn),
        .settings=NULL,
        .settings_len=0
    };
    TLS13_ALPS_ADD_ARG alps_add_arg = {
        .cfg_size=1,
        .cfgs=&h2cfg
    };
    if (!SSL_CTX_add_custom_ext(
            ssl_ctx, TLSEXT_TYPE_application_settings,
            SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS | SSL_EXT_TLS_IMPLEMENTATION_ONLY | SSL_EXT_TLS1_3_ONLY,
            _osslcb_custom_ext_add_cb_ex, _osslcb_custom_ext_free_cb_ex, &alps_add_arg,
            _osslcb_custom_ext_parse_cb_ex, NULL))
        fputs("Warning: SSL_CTX_add_custom_ext failed for ALPS\n", stderr);

    if (!SSL_CTX_add_custom_ext(
            ssl_ctx, TLSEXT_TYPE_encrypted_client_hello,
            SSL_EXT_CLIENT_HELLO | SSL_EXT_TLS1_3_HELLO_RETRY_REQUEST | SSL_EXT_TLS1_3_ENCRYPTED_EXTENSIONS | SSL_EXT_TLS_IMPLEMENTATION_ONLY | SSL_EXT_TLS1_3_ONLY,
            _osslcb_custom_ext_add_cb_ex, _osslcb_custom_ext_free_cb_ex, NULL,
            _osslcb_custom_ext_parse_cb_ex, NULL))
        fputs("Warning: SSL_CTX_add_custom_ext failed for ECH\n", stderr);

    // General traffic fingerprint:
    // Ciphersuites:
    // missing GREASE 3a3a at the beginning
    // Extensions:
    // [DONE] missing GREASE 19018(4a4a), beginning
    // supported_groups 10(a)
    // - missing GREASE aaaa, beginning
    // [DONE] missing ALPS 17613(44cd)
    // - 0003026832
    // key_share 51(33)
    // - missing GREASE aaaa, beginning
    // missing GREASE 6682(1a1a), end
    //
    // Implementation progress:
    // GREASE: https://github.com/openssl/openssl/issues/9660
    // Full ALPS is impossible, use a dummy ALPN

    SSL *ssl = SSL_new(ssl_ctx);
    if (ssl == NULL) {
        fputs("Error creating SSL object:\n", stderr);
        ERR_print_errors_fp(stderr);
        ret = 1;
        goto free_ssl_ctx;
    }
    if (!SSL_set_tlsext_host_name(ssl, hn))
        fputs("Warning: SSL_set_tlsext_host_name failed\n", stderr);
    if (!SSL_set_fd(ssl, (int)sock)) {
        fputs("Error setting SSL fd:\n", stderr);
        ERR_print_errors_fp(stderr);
        ret = 1;
        goto free_ssl;
    }

    if (addrlen > INT_MAX) {
        fputs("Resolved address too long to connect\n", stderr);
        ret = 1;
        goto free_ssl;
    }
    int res = connect(sock, (const struct sockaddr *)&addr, (int)addrlen);
    if (res != 0) {
        fprintf(stderr, "connect failure: %d\n", GET_SOCKET_ERROR());
        ret = 1;
        goto free_ssl;
    }

    res = SSL_connect(ssl);
    if (res <= 0) {
        (void)handle_ossl_err(ssl, &res, "SSL_connect");
        ret = 1;
        goto free_ssl;
    }

    res = SSL_write(ssl, httpreq, httpreq_size);
    if (res <= 0) {
        ret = 1;
        if (handle_ossl_err(ssl, &res, "SSL_write"))
            goto free_ssl;
        goto free_sslconn;
    }

    char buf[1024];
    while (1) {
        res = SSL_read(ssl, buf, sizeof(buf));
        if (res > 0) {
            fwrite(buf, 1, res, stdout);
        } else {
            putchar('\n');
            if (handle_ossl_err(ssl, &res, "SSL_read")) {
                ret = 1;
                goto free_ssl;
            }
            ret = res != SSL_ERROR_ZERO_RETURN;
            goto free_sslconn;
        }
    }
free_sslconn:;
    SSL_shutdown(ssl);
free_ssl:;
    SSL_free(ssl);
free_ssl_ctx:;
    SSL_CTX_free(ssl_ctx);
free_sock:;
    SOCKFD_CLOSE(sock);
free_wsa:;
    SOCKET_CLEANUP();
    return ret;
}
