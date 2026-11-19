#!/usr/bin/env bash
#
# wolftpm/mayhem/build.sh — MINING branch (mine-5d826bf): build wolfTPM's libFuzzer harness for the
# CLIENT-side response parser as a sanitized target (+ a standalone reproducer).
#
# This branch mines the bug fixed upstream in 493e3359c79c ("Bound decrypt-parameter size in
# TPM2_ResponseProcess against OOB write"), so it ships ONE target — the one that reaches that code:
#   tpm2_resp_fuzz — wolfTPM's client-side TPM response parser: TPM2_ResponseProcess (src/tpm2.c)
#                    and the in-place response parameter decryption it drives
#                    (TPM2_ParamDec_CmdResponse, src/tpm2_param_enc.c). The harness
#                    (mayhem/harnesses/tpm2_resp_fuzz.c) is an emulated TPM behind the public HAL IO
#                    callback, so the fuzzer owns the bytes the device sends back.
# The live branch's fuzz_asn_cert / fwtpm_fuzz targets reach other code (the ASN.1 decoders, the
# firmware-TPM server) and are not built here (MINING.md step 3).
#
# wolfTPM depends on wolfSSL, so we clone+build+install wolfSSL first, then build wolfTPM against it
# (both WITH $SANITIZER_FLAGS so the fuzzed code — not just the harness — is instrumented), then the
# harness. The ASN.1 oracle that mayhem/test.sh runs uses the same two static libs.
#
# Build contract comes from the org base ENV: CC/CXX/SANITIZER_FLAGS/LIB_FUZZING_ENGINE/
# STANDALONE_FUZZ_MAIN/$OUT.
set -euo pipefail

# clang rejects SOURCE_DATE_EPOCH='' — must be unset or a valid integer.
[ -n "${SOURCE_DATE_EPOCH:-}" ] || unset SOURCE_DATE_EPOCH

# `=` (not `:=`) for SANITIZER_FLAGS so an explicit empty --build-arg builds with NO sanitizers.
: "${SANITIZER_FLAGS=-fsanitize=address,undefined -fno-sanitize-recover=all -fno-omit-frame-pointer -g}"
# DEBUG_FLAGS: DWARF ≤ 3 required (clang-19 defaults to DWARF 5; Mayhem triage needs < 4).
: "${DEBUG_FLAGS:=-g -gdwarf-3}"
export DEBUG_FLAGS
: "${CC:=clang}" ; : "${CXX:=clang++}" ; : "${LIB_FUZZING_ENGINE:=-fsanitize=fuzzer}"
: "${MAYHEM_JOBS:=$(nproc)}"
# Coverage instrumentation for the fuzzed code (libFuzzer needs -fsanitize=fuzzer-no-link on the
# library TUs; the engine flag adds the runtime when linking the target).
SANITIZER_FLAGS="$SANITIZER_FLAGS -fsanitize=fuzzer-no-link"
export SANITIZER_FLAGS CC CXX LIB_FUZZING_ENGINE MAYHEM_JOBS

SRC="${SRC:-$(cd "$(dirname "$0")/.." && pwd)}"
OUT="${OUT:-/mayhem}"
WORK="${WORK:-$SRC/mayhem-build}"
mkdir -p "$WORK" "$OUT"

HARNESS_DIR="$SRC/mayhem/harnesses"

# ── 1) Build wolfSSL (static, sanitized) with wolfTPM + keygen support, install to a prefix ────────
PREFIX="$WORK/wolfssl-install"
WOLFSSL_SRC="$WORK/wolfssl"
mkdir -p "$PREFIX"
if [ ! -d "$WOLFSSL_SRC/.git" ] && [ ! -f "$WOLFSSL_SRC/configure.ac" ]; then
  git clone --depth 1 https://github.com/wolfssl/wolfssl "$WOLFSSL_SRC"
fi

cd "$WOLFSSL_SRC"
./autogen.sh
# Build wolfSSL itself with the sanitizers so the dependency is instrumented too.
./configure \
    --prefix="$PREFIX" \
    --enable-static --disable-shared \
    --enable-wolftpm \
    --enable-pkcallbacks \
    --enable-keygen \
    --enable-certgen \
    --enable-certreq \
    --enable-certext \
    CC="$CC" \
    CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -DWC_RSA_NO_PADDING -DWOLFSSL_PUBLIC_MP" \
    LDFLAGS="$SANITIZER_FLAGS"
make -j"$MAYHEM_JOBS"
make install
export PKG_CONFIG_PATH="$PREFIX/lib/pkgconfig"

# ── 2) Build wolfTPM (static, sanitized) ───────────────────────────────────────────────────────────
# --enable-spi: the SPI/TIS transport (TPM2_TIS_SendCommand), i.e. a TPM chip on a bus reached
# through the application's HAL IO callback — what the harness emulates. Selecting a hardware path
# also turns off the software-TPM socket transport this configure enables by default on x86_64
# (WOLFTPM_SWTPM, which rejects a HAL callback outright); --disable-swtpm/--disable-fwtpm say so
# explicitly. --enable-advio picks the (isRead, addr) HAL callback form the harness implements.
cd "$SRC"
./autogen.sh
./configure \
    --prefix="$WORK/wolftpm-install" \
    --enable-static --disable-shared \
    --disable-examples \
    --enable-spi \
    --disable-swtpm \
    --disable-fwtpm \
    --enable-advio \
    CC="$CC" \
    CFLAGS="$SANITIZER_FLAGS $DEBUG_FLAGS -I$PREFIX/include" \
    LDFLAGS="$SANITIZER_FLAGS -L$PREFIX/lib"
make -j"$MAYHEM_JOBS"

LIBWOLFTPM="$SRC/src/.libs/libwolftpm.a"
LIBWOLFSSL="$PREFIX/lib/libwolfssl.a"
[ -f "$LIBWOLFTPM" ] || { echo "ERROR: $LIBWOLFTPM not built" >&2; exit 1; }

# Common include + link flags. wolfTPM headers live under $SRC (namespace 'wolftpm/...') and the
# generated options.h lands in $SRC; wolfSSL headers come from the install prefix.
INC="-I$SRC -I$PREFIX/include"
# WOLFTPM_ADV_IO is a library AM_CFLAGS define (--enable-advio), not in options.h, so the harness
# must be told too or it would see the other TPM2HalIoCb signature.
DEFS="-DWOLFTPM_ADV_IO"

# Leak detection off at build time (leaks are not the class this fleet fuzzes for); ASan+UBSan stay on.
$CXX $SANITIZER_FLAGS $DEBUG_FLAGS -c "$SRC/mayhem/lsan_off.cc" -o "$WORK/lsan_off.o"

# Standalone driver object (no libFuzzer runtime, reads one input file).
$CC $SANITIZER_FLAGS $DEBUG_FLAGS -c "$HARNESS_DIR/standalone_main.c" -o "$WORK/standalone_main.o"

# ── 3) tpm2_resp_fuzz — the response parser lives in libwolftpm.a; link the harness directly. ──────
$CC $SANITIZER_FLAGS $DEBUG_FLAGS $DEFS $INC \
    "$HARNESS_DIR/tpm2_resp_fuzz.c" $LIB_FUZZING_ENGINE "$WORK/lsan_off.o" \
    "$LIBWOLFTPM" "$LIBWOLFSSL" -lm \
    -o "$OUT/tpm2_resp_fuzz"
$CC $SANITIZER_FLAGS $DEBUG_FLAGS $DEFS $INC \
    "$HARNESS_DIR/tpm2_resp_fuzz.c" "$WORK/standalone_main.o" "$WORK/lsan_off.o" \
    "$LIBWOLFTPM" "$LIBWOLFSSL" -lm \
    -o "$OUT/tpm2_resp_fuzz-standalone"
echo "built tpm2_resp_fuzz (+ standalone)"

echo "build.sh complete:"
ls -la "$OUT/tpm2_resp_fuzz" "$OUT/tpm2_resp_fuzz-standalone" 2>&1 || true
