/* Servidor TLS 1.3 mínimo sobre la biblioteca NSS (Mozilla), con PSK externa y SIN certificado.
 * Existe porque `selfserv` de NSS no aplica la PSK externa en el servidor (la autentica por certificado aunque se le dé una PSK): así se contrasta NUESTRO CLIENTE PSK
 * con una implementación de TLS 1.3 distinta de OpenSSL y de GnuTLS que además trae el híbrido X25519MLKEM768. Es un ayudante de PRUEBA, no un servicio.
 *
 *   nss_psk_server <puerto> <psk-hex> <etiqueta> <hibrido|x25519> <conexiones> <base-NSS> <apodo-del-certificado>
 * (NSS no ofrece suites TLS 1.3 sin un certificado configurado, así que se le da uno; lo que se prueba es que ELIGE la PSK, no el certificado.)
 * Por conexión imprime una línea JSON con lo que NSS negoció; lee 4 bytes y devuelve esos 4 bytes invertidos. */
#include <stdio.h>
#include <stdlib.h>
#include <string.h>
#include <nspr.h>
#include <prio.h>
#include <prnetdb.h>
#include <nss.h>
#include <ssl.h>
#include <sslexp.h>
#include <sslproto.h>
#include <pk11pub.h>
#include <cert.h>
#include <keyhi.h>

static int hexval(char c) { return c >= '0' && c <= '9' ? c - '0' : c >= 'a' && c <= 'f' ? c - 'a' + 10 : c >= 'A' && c <= 'F' ? c - 'A' + 10 : -1; }

int main(int argc, char **argv) {
    if (argc < 8) { fprintf(stderr, "uso: %s puerto psk-hex etiqueta hibrido|x25519 conexiones base-NSS apodo\n", argv[0]); return 2; }
    int port = atoi(argv[1]), conns = atoi(argv[5]);
    size_t hl = strlen(argv[2]);
    unsigned char key[256];
    if (hl % 2 || hl / 2 > sizeof key) return 2;
    for (size_t i = 0; i < hl / 2; i++) { int a = hexval(argv[2][2 * i]), b = hexval(argv[2][2 * i + 1]); if (a < 0 || b < 0) return 2; key[i] = (unsigned char)(a * 16 + b); }
    SSLNamedGroup group = strcmp(argv[4], "hibrido") == 0 ? ssl_grp_kem_mlkem768x25519 : ssl_grp_ec_curve25519;

    if (NSS_Init(argv[6]) != SECSuccess || NSS_SetDomesticPolicy() != SECSuccess) { fprintf(stderr, "NSS no inicia\n"); return 3; }
    CERTCertificate *cert = CERT_FindCertByNickname(CERT_GetDefaultCertDB(), argv[7]);
    SECKEYPrivateKey *pkey = cert ? PK11_FindKeyByAnyCert(cert, NULL) : NULL;
    if (!cert || !pkey) { fprintf(stderr, "sin certificado o clave en la base NSS\n"); return 3; }
    PRFileDesc *ls = PR_OpenTCPSocket(PR_AF_INET);
    PRNetAddr addr;
    PR_InitializeNetAddr(PR_IpAddrLoopback, (PRUint16)port, &addr);
    PRSocketOptionData opt = {PR_SockOpt_Reuseaddr, {.reuse_addr = PR_TRUE}};
    PR_SetSocketOption(ls, &opt);
    if (PR_Bind(ls, &addr) != PR_SUCCESS || PR_Listen(ls, 4) != PR_SUCCESS) { fprintf(stderr, "no se pudo escuchar\n"); return 4; }
    printf("READY\n"); fflush(stdout);

    for (int n = 0; n < conns; n++) {
        PRNetAddr peer;
        PRFileDesc *c = PR_Accept(ls, &peer, PR_SecondsToInterval(20));
        if (!c) break;
        PRFileDesc *ssl = SSL_ImportFD(NULL, c);
        SECStatus rv = ssl ? SECSuccess : SECFailure;
        SSLVersionRange vr = {SSL_LIBRARY_VERSION_TLS_1_3, SSL_LIBRARY_VERSION_TLS_1_3};
        if (rv == SECSuccess) rv = SSL_OptionSet(ssl, SSL_SECURITY, PR_TRUE);
        if (rv == SECSuccess) rv = SSL_OptionSet(ssl, SSL_HANDSHAKE_AS_SERVER, PR_TRUE);
        if (rv == SECSuccess) rv = SSL_ConfigServerCert(ssl, cert, pkey, NULL, 0);
        if (rv == SECSuccess) rv = SSL_VersionRangeSet(ssl, &vr);
        if (rv == SECSuccess) rv = SSL_NamedGroupConfig(ssl, &group, 1);
        if (rv == SECSuccess) {
            PK11SlotInfo *slot = PK11_GetInternalSlot();
            SECItem item = {siBuffer, key, (unsigned int)(hl / 2)};
            PK11SymKey *psk = PK11_ImportSymKey(slot, CKM_HKDF_DERIVE, PK11_OriginUnwrap, CKA_DERIVE, &item, NULL);
            rv = psk ? SSL_AddExternalPsk(ssl, psk, (const PRUint8 *)argv[3], (unsigned int)strlen(argv[3]), ssl_hash_sha256) : SECFailure;
            if (psk) PK11_FreeSymKey(psk);
            PK11_FreeSlot(slot);
        }
        if (rv == SECSuccess) rv = SSL_ResetHandshake(ssl, PR_TRUE);
        if (rv == SECSuccess) rv = SSL_ForceHandshake(ssl);
        if (rv != SECSuccess) {
            printf("{\"ok\": false, \"err\": %d}\n", PR_GetError()); fflush(stdout);
            if (ssl) PR_Close(ssl);
            continue;
        }
        SSLChannelInfo info;
        memset(&info, 0, sizeof info);
        SSL_GetChannelInfo(ssl, &info, sizeof info);
        char buf[4];
        int got = 0, r;
        while (got < 4 && (r = PR_Recv(ssl, buf + got, 4 - got, 0, PR_SecondsToInterval(10))) > 0) got += r;
        char out[4] = {buf[3], buf[2], buf[1], buf[0]};
        if (got == 4) PR_Send(ssl, out, 4, 0, PR_SecondsToInterval(10));
        printf("{\"ok\": true, \"version\": %d, \"group\": %d, \"suite\": %d, \"auth\": %d, \"kea\": %d, \"read\": %d}\n",
               info.protocolVersion, (int)info.keaGroup, info.cipherSuite, (int)info.authType, (int)info.keaType, got);
        fflush(stdout);
        PR_Shutdown(ssl, PR_SHUTDOWN_BOTH);
        PR_Close(ssl);
    }
    PR_Close(ls);
    NSS_Shutdown();
    return 0;
}
