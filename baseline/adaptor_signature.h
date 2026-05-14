#pragma once

#include <array>
#include <cstddef>
#include <cstdint>
#include <vector>

#include "signature.h"

extern "C" {
#include "pke.h"
}

// FAEST 128f (v2): SK = secpar(16) + IV(16) = 32, PK = IV(16) + OWF_output(16) = 32
static constexpr size_t ADAPTOR_SK_BYTES = 32;
static constexpr size_t ADAPTOR_PK_BYTES = 32;

struct adaptor_keypair_t {
    std::vector<uint8_t> pk;  // ADAPTOR_PK_BYTES
    std::vector<uint8_t> sk;  // ADAPTOR_SK_BYTES
};

// Pre-signature: FAEST sig + PKE seed (deterministically regenerates enc/dec keys)
struct pre_signature_t {
    std::vector<uint8_t> faest_sig;
    std::array<uint8_t, PKE_SEED_BYTES> seed;
};

// Full adaptor signature
struct adaptor_sig_t {
    std::vector<uint8_t> helium_pk;                     // keypair.second (plaintext || ciphertext)
    std::array<uint8_t, PKE_PUBLICKEYBYTES> enc_key;    // Kyber public key
    std::vector<uint8_t> faest_sig;
    std::vector<uint8_t> helium_sig;
};

// KeyGen: generate FAEST 128f keypair (apk, ask)
adaptor_keypair_t adaptor_keygen();

// preSign(ask, msg, helium_pk, instance) -> sigma_tilde
pre_signature_t adaptor_presign(
    const std::vector<uint8_t>& ask,
    const std::vector<uint8_t>& msg,
    const std::vector<uint8_t>& helium_pk,
    const signature_instance_t& instance);

// pVer(sigma_tilde, msg, apk, helium_pk, instance) -> bool
bool adaptor_pver(
    const pre_signature_t& sigma_tilde,
    const std::vector<uint8_t>& msg,
    const std::vector<uint8_t>& apk,
    const std::vector<uint8_t>& helium_pk,
    const signature_instance_t& instance);

// Adapt(apk, msg, sigma_tilde, helium_keypair, instance) -> sigma
// helium_keypair.first = AES key (secret), helium_keypair.second = plaintext||ciphertext
adaptor_sig_t adaptor_adapt(
    const std::vector<uint8_t>& apk,
    const std::vector<uint8_t>& msg,
    const pre_signature_t& sigma_tilde,
    const keypair_t& helium_keypair,
    const signature_instance_t& instance);

// Ver(apk, msg, sigma, instance) -> bool
bool adaptor_ver(
    const std::vector<uint8_t>& apk,
    const std::vector<uint8_t>& msg,
    const adaptor_sig_t& sigma,
    const signature_instance_t& instance);

// Ext(apk, msg, sigma_tilde, sigma, instance) -> AES key bytes (empty on failure)
std::vector<uint8_t> adaptor_ext(
    const std::vector<uint8_t>& apk,
    const std::vector<uint8_t>& msg,
    const pre_signature_t& sigma_tilde,
    const adaptor_sig_t& sigma,
    const signature_instance_t& instance);
