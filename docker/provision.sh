#!/usr/bin/env bash
# Provision a key in the KMS, export its public half, then run the
# benchmark against it.
#
# The Cosmian PKCS#11 module cannot do either of the first two steps itself:
# C_GenerateKeyPair is CKR_FUNCTION_NOT_SUPPORTED, so key creation must
# happen out-of-band via ckms/KMIP.
#
# CURVE selects which key type to provision: 'p256' (default) or 'ed25519'.
# As of Cosmian/kms 5.27.1 (and 5.26.0, 5.25.0), Ed25519 keys created via
# ckms/KMIP are invisible to the KMS's own PKCS#11 provider: the provider's
# key_algorithm_from_attributes only recognises AES/RSA/EC(ECDH), so it logs
# "Unsupported cryptographic algorithm: Ed25519" and silently skips the
# object. See https://github.com/Cosmian/kms/issues/1183. Until that is
# fixed upstream, only 'p256' works end-to-end against a real KMS over
# PKCS#11; 'ed25519' is kept for when the upstream bug is fixed.
set -euo pipefail

KMS_URL="${KMS_URL:-http://kms:9998}"
CURVE="${CURVE:-p256}"
KEY_ID="${KEY_ID:-bench-${CURVE}-key}"
# The provider only enumerates private keys carrying this KMIP tag.
KEY_TAG="${KEY_TAG:-disk-encryption}"
WORK_DIR="${WORK_DIR:-/work}"
PUB_DER="${WORK_DIR}/public_key.der"

case "${CURVE}" in
    p256) CKMS_CURVE="nist-p256" ;;
    ed25519) CKMS_CURVE="ed25519" ;;
    *) echo "unknown CURVE '${CURVE}' (expected 'p256' or 'ed25519')" >&2; exit 1 ;;
esac

mkdir -p "${WORK_DIR}" /root/.cosmian

# One config file serves both the CLI and the PKCS#11 provider.
cat > /root/.cosmian/ckms.toml <<EOF
[http_config]
server_url = "${KMS_URL}"
EOF
export CKMS_CONF=/root/.cosmian/ckms.toml

echo "==> Waiting for the KMS at ${KMS_URL}"
for _ in $(seq 1 60); do
    if curl -fsS "${KMS_URL}/version" >/dev/null 2>&1; then
        break
    fi
    sleep 2
done
curl -fsS "${KMS_URL}/version" >/dev/null \
    || { echo "KMS never became reachable at ${KMS_URL}" >&2; exit 1; }
echo "    KMS version $(curl -fsS "${KMS_URL}/version")"

echo "==> Creating the ${CURVE} key pair (id '${KEY_ID}', tag '${KEY_TAG}')"
if ckms ec keys create --curve "${CKMS_CURVE}" --tag "${KEY_TAG}" "${KEY_ID}" 2>&1; then
    echo "    created"
else
    # Re-running the stack must not be a hard error.
    echo "    key already exists, reusing it"
fi

# Cosmian names the public half '<private-id>_pk'.
PUB_ID="${KEY_ID}_pk"

echo "==> Exporting the public key '${PUB_ID}'"
exported=""
for format in pkcs8-der raw; do
    if ckms ec keys export --key-id "${PUB_ID}" --key-format "${format}" \
        "${PUB_DER}" >/dev/null 2>&1; then
        echo "    exported as ${format} ($(wc -c < "${PUB_DER}") bytes)"
        exported="${format}"
        break
    fi
done

if [ -z "${exported}" ]; then
    echo "    falling back to json-ttlv"
    ckms ec keys export --key-id "${PUB_ID}" "${WORK_DIR}/public_key.json"
    # Pull the hex key material out of the KMIP KeyValue and de-hex it.
    jq -r '.. | objects | select(has("KeyMaterial")) | .KeyMaterial
           | if type == "object" then (.ByteString // .Q // empty) else . end' \
        "${WORK_DIR}/public_key.json" | head -1 | tr -d '\n' | xxd -r -p > "${PUB_DER}"
    echo "    extracted $(wc -c < "${PUB_DER}") bytes"
fi

if [ ! -s "${PUB_DER}" ]; then
    echo "could not obtain the ${CURVE} public key" >&2
    exit 1
fi

echo "==> Running sign-tx"
exec sign-tx --key-id "${KEY_ID}" --public-key "${PUB_DER}" --curve "${CURVE}" "$@"
