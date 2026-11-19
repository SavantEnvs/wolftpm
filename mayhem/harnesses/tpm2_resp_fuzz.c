/* tpm2_resp_fuzz.c — libFuzzer harness for wolfTPM's CLIENT-side response parser.
 *
 * Surface: the bytes a TPM device sends back to the host. wolfTPM's public API
 * (TPM2_Init_ex + a HAL IO callback + TPM2_SetSessionAuth + any TPM2_* command)
 * parses that response in TPM2_ResponseProcess() (src/tpm2.c), which marks the
 * "first" response parameter and, when the session says the response is
 * encrypted, decrypts it in place inside the context's command/response buffer
 * (TPM2_ParamDec_CmdResponse, src/tpm2_param_enc.c).
 *
 * The response is NOT trusted input in this library's threat model: a faulty or
 * malicious/MITM'd TPM controls every byte of it. So this harness is an
 * emulated TPM behind the HAL callback: it answers the TIS register reads the
 * transport does (status / burst count / FIFO) and returns a fuzzer-controlled
 * TPM2_Unseal response. The fuzzer drives:
 *   data[0..1] — the response's first-parameter size field (the decrypt size)
 *   data[2..]  — the response parameter bytes
 *
 * The emulated TPM signs the response auth area with the session key, exactly
 * as a real TPM does (it holds the same session key), so the host's response
 * HMAC check passes and the parser reaches the parameter-decrypt step. Nothing
 * here weakens a check the library's callers make: every value the harness
 * fabricates is a value that arrives from the device on the wire.
 *
 * The context and the session array are heap-allocated so a write past the
 * context's response buffer is a clean ASan heap-buffer-overflow.
 */

#ifdef HAVE_CONFIG_H
    #include <config.h>
#endif

#include <wolftpm/tpm2.h>
#include <wolftpm/tpm2_packet.h>
#include <wolftpm/tpm2_param_enc.h>
#include <wolftpm/tpm2_tis.h>

#include <stdint.h>
#include <stddef.h>
#include <stdlib.h>
#include <string.h>

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size);

/* TIS register offsets (low 12 bits of the address; locality 0) — the same
 * layout src/tpm2_tis.c uses to build its addresses. */
#define REG_ACCESS      0x0000u
#define REG_INT_ENABLE  0x0008u
#define REG_INT_STATUS  0x0010u
#define REG_INTF_CAPS   0x0014u
#define REG_STS         0x0018u
#define REG_BURST       0x0019u
#define REG_FIFO        TPM_TIS_DATA_FIFO_OFFSET
#define REG_DID_VID     0x0F00u
#define REG_RID         0x0F04u

/* TIS access + status bits (the enums in src/tpm2_tis.c, which are file-local) */
#define ACCESS_VALID           0x80
#define ACCESS_ACTIVE_LOCALITY 0x20


#define STS_VALID         0x80
#define STS_COMMAND_READY 0x40
#define STS_GO            0x20
#define STS_DATA_AVAIL    0x10
#define STS_DATA_EXPECT   0x08

#define TPM_RESP_MAX   2048             /* stays under MAX_RESPONSE_SIZE */
#define PARAM_MAX      1024             /* response parameter bytes we emit */
#define NONCE_SZ       32               /* SHA2-256 nonce / HMAC size */

/* the current input */
static const uint8_t* g_in;
static size_t g_inSz;

/* the emulated TPM's command buffer (what the host wrote) */
static byte g_cmd[TPM_RESP_MAX];
static int g_cmdPos;
static int g_cmdSz;                     /* from the command header, once known */

/* the emulated TPM's response */
static byte g_resp[TPM_RESP_MAX];
static int g_respSz;
static int g_respPos;

static void put16(byte* b, int* p, UINT16 v)
{
    b[(*p)++] = (byte)(v >> 8); b[(*p)++] = (byte)(v & 0xFF);
}
static void put32(byte* b, int* p, UINT32 v)
{
    b[(*p)++] = (byte)(v >> 24); b[(*p)++] = (byte)(v >> 16);
    b[(*p)++] = (byte)(v >> 8);  b[(*p)++] = (byte)(v & 0xFF);
}

/* Build the response to the command the host just wrote. Called when the host
 * sets TPM_STS_GO ("execute"), so the session's nonceCaller is already set. */
static void build_response(TPM2_CTX* ctx)
{
    TPM2_AUTH_SESSION* s = &ctx->session[1];
    TPM2B_DIGEST hash;
    TPM2B_AUTH hmac;
    TPM2B_NONCE nonceTPM;
    TPM_CC cmdCode = 0;
    TPMA_SESSION attrs = TPMA_SESSION_continueSession | TPMA_SESSION_encrypt;
    UINT16 decParamSz;
    UINT32 paramSz;
    size_t payloadSz;
    int p = 0, sizePos, i;

    /* command code the host sent (bytes 6..9 of the command header) */
    if (g_cmdPos >= 10) {
        cmdCode = ((TPM_CC)g_cmd[6] << 24) | ((TPM_CC)g_cmd[7] << 16) |
                  ((TPM_CC)g_cmd[8] << 8)  | (TPM_CC)g_cmd[9];
    }

    decParamSz = (UINT16)(((UINT16)g_in[0] << 8) | g_in[1]);
    payloadSz = g_inSz - 2;
    if (payloadSz > PARAM_MAX) payloadSz = PARAM_MAX;
    paramSz = (UINT32)(sizeof(UINT16) + payloadSz);

    put16(g_resp, &p, TPM_ST_SESSIONS);         /* response tag */
    sizePos = p; put32(g_resp, &p, 0);          /* response size (below) */
    put32(g_resp, &p, TPM_RC_SUCCESS);          /* response code */

    /* parameter area: the first parameter's size field, then its bytes */
    put32(g_resp, &p, paramSz);
    put16(g_resp, &p, decParamSz);
    if (payloadSz > 0) {
        memcpy(&g_resp[p], g_in + 2, payloadSz);
        p += (int)payloadSz;
    }

    /* auth response 1 of 2 — the password session: no nonce, no HMAC */
    put16(g_resp, &p, 0);
    g_resp[p++] = TPMA_SESSION_continueSession;
    put16(g_resp, &p, 0);

    /* auth response 2 of 2 — the HMAC session, signed with the session key */
    memset(&nonceTPM, 0, sizeof(nonceTPM));
    nonceTPM.size = NONCE_SZ;
    for (i = 0; i < NONCE_SZ; i++) nonceTPM.buffer[i] = (byte)(0xA5 ^ i);
    put16(g_resp, &p, NONCE_SZ);
    memcpy(&g_resp[p], nonceTPM.buffer, NONCE_SZ); p += NONCE_SZ;
    g_resp[p++] = attrs;

    memset(&hash, 0, sizeof(hash));
    memset(&hmac, 0, sizeof(hmac));
    if (TPM2_CalcRpHash(s->authHash, cmdCode, &g_resp[TPM2_HEADER_SIZE +
            (int)sizeof(UINT32)], paramSz, &hash) == TPM_RC_SUCCESS) {
        (void)TPM2_CalcHmac(s->authHash, &s->auth, &hash, &nonceTPM,
            &s->nonceCaller, attrs, &hmac);
    }
    if (hmac.size > NONCE_SZ) hmac.size = NONCE_SZ;
    put16(g_resp, &p, hmac.size);
    if (hmac.size > 0) {
        memcpy(&g_resp[p], hmac.buffer, hmac.size);
        p += hmac.size;
    }

    g_resp[sizePos]     = (byte)((UINT32)p >> 24);
    g_resp[sizePos + 1] = (byte)((UINT32)p >> 16);
    g_resp[sizePos + 2] = (byte)((UINT32)p >> 8);
    g_resp[sizePos + 3] = (byte)((UINT32)p & 0xFF);

    g_respSz = p;
    g_respPos = 0;
}

/* The emulated TPM chip on the other end of the TIS bus. */
static int fake_tpm_io(TPM2_CTX* ctx, INT32 isRead, UINT32 addr,
    BYTE* xferBuf, UINT16 xferSz, void* userCtx)
{
    UINT32 reg = addr & 0xFFFu;
    int n;
    (void)userCtx;

    if (xferBuf == NULL || xferSz == 0)
        return TPM_RC_FAILURE;

    if (isRead == TPM_TIS_READ) {
        memset(xferBuf, 0, xferSz);
        switch (reg) {
            case REG_ACCESS:
                xferBuf[0] = ACCESS_ACTIVE_LOCALITY | ACCESS_VALID;
                break;
            case REG_STS:
                /* ready, status valid, a response waiting; DATA_EXPECT only
                 * while the host still owes us command bytes */
                xferBuf[0] = STS_VALID | STS_COMMAND_READY | STS_DATA_AVAIL;
                if (g_cmdSz > 0 && g_cmdPos < g_cmdSz)
                    xferBuf[0] |= STS_DATA_EXPECT;
                break;
            case REG_BURST:
                xferBuf[0] = 0xFF;      /* clamped to MAX_SPI_FRAMESIZE */
                if (xferSz > 1) xferBuf[1] = 0xFF;
                break;
            case REG_FIFO:
                n = g_respSz - g_respPos;
                if (n > (int)xferSz) n = (int)xferSz;
                if (n > 0) {
                    memcpy(xferBuf, &g_resp[g_respPos], (size_t)n);
                    g_respPos += n;
                }
                break;
            case REG_INTF_CAPS:
            case REG_DID_VID:
            case REG_RID:
            case REG_INT_STATUS:
            default:
                break;              /* zeros */
        }
        return TPM_RC_SUCCESS;
    }

    /* writes */
    switch (reg) {
        case REG_FIFO:
            n = (int)xferSz;
            if (g_cmdPos + n > (int)sizeof(g_cmd))
                n = (int)sizeof(g_cmd) - g_cmdPos;
            if (n > 0) {
                memcpy(&g_cmd[g_cmdPos], xferBuf, (size_t)n);
                g_cmdPos += n;
            }
            if (g_cmdSz == 0 && g_cmdPos >= 10) {
                g_cmdSz = (int)(((UINT32)g_cmd[2] << 24) |
                                ((UINT32)g_cmd[3] << 16) |
                                ((UINT32)g_cmd[4] << 8)  | (UINT32)g_cmd[5]);
                if (g_cmdSz < 0 || g_cmdSz > (int)sizeof(g_cmd))
                    g_cmdSz = g_cmdPos;
            }
            break;
        case REG_STS:
            if (xferBuf[0] & STS_GO)
                build_response(ctx);        /* "execute the command" */
            else if (xferBuf[0] & STS_COMMAND_READY) {
                g_cmdPos = 0; g_cmdSz = 0;  /* host is (re)arming the chip */
            }
            break;
        default:
            break;
    }
    return TPM_RC_SUCCESS;
}

int LLVMFuzzerTestOneInput(const uint8_t* data, size_t size)
{
    TPM2_CTX* ctx;
    TPM2_AUTH_SESSION* sess;
    Unseal_In in;
    Unseal_Out* out;

    /* the first two bytes are the response's first-parameter size field */
    if (size < 2)
        return -1;

    g_in = data; g_inSz = size;
    g_cmdPos = 0; g_cmdSz = 0; g_respSz = 0; g_respPos = 0;

    ctx  = (TPM2_CTX*)malloc(sizeof(TPM2_CTX));
    sess = (TPM2_AUTH_SESSION*)malloc(sizeof(TPM2_AUTH_SESSION) *
                                      MAX_SESSION_NUM);
    out  = (Unseal_Out*)malloc(sizeof(Unseal_Out));
    if (ctx == NULL || sess == NULL || out == NULL) {
        free(ctx); free(sess); free(out);
        return 0;
    }
    memset(sess, 0, sizeof(TPM2_AUTH_SESSION) * MAX_SESSION_NUM);
    memset(out, 0, sizeof(*out));

    /* timeoutTries 0: use the default locality, no chip-startup handshake */
    if (TPM2_Init_ex(ctx, fake_tpm_io, NULL, 0) == TPM_RC_SUCCESS) {
        /* A typical wolfTPM session set: password auth for the object, plus a
         * parameter-encryption HMAC session (what a caller asks for when it
         * wants the unsealed data encrypted on the bus). */
        sess[0].sessionHandle = TPM_RS_PW;
        sess[1].sessionHandle = HMAC_SESSION_FIRST;
        sess[1].sessionAttributes = TPMA_SESSION_continueSession |
                                    TPMA_SESSION_encrypt;
        sess[1].authHash = TPM_ALG_SHA256;
        sess[1].auth.size = NONCE_SZ;       /* session key (all zeros here) */
        sess[1].symmetric.algorithm = TPM_ALG_AES;
        sess[1].symmetric.keyBits.aes = 128;
        sess[1].symmetric.mode.aes = TPM_ALG_CFB;

        if (TPM2_SetSessionAuth(sess) == TPM_RC_SUCCESS) {
            memset(&in, 0, sizeof(in));
            in.itemHandle = TRANSIENT_FIRST;
            (void)TPM2_Unseal(&in, out);
        }
    }

    TPM2_Cleanup(ctx);
    free(out); free(sess); free(ctx);
    return 0;
}
