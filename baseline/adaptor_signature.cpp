#include "adaptor_signature.h"
#include "signature.h"

extern "C" {
#include "pke.h"
#include "randomness.h"
}

// FAEST headers (C++20 required)
#include "faest-arch-opt/faest.hpp"
#include "faest-arch-opt/faest_keys.hpp"
#include "faest-arch-opt/api.hpp"
#include "faest-arch-opt/parameters.hpp"

#include <cassert>
#include <cstring>

namespace {

using P = faest::v2::faest_128_f;

// Build the message FAEST signs over: msg || helium_pk || enc_key
static std::vector<uint8_t> build_faest_msg(
    const std::vector<uint8_t>& msg,
    const std::vector<uint8_t>& helium_pk,
    const uint8_t enc_key[PKE_PUBLICKEYBYTES])
{
    std::vector<uint8_t> m;
    m.reserve(msg.size() + helium_pk.size() + PKE_PUBLICKEYBYTES);
    m.insert(m.end(), msg.begin(), msg.end());
    m.insert(m.end(), helium_pk.begin(), helium_pk.end());
    m.insert(m.end(), enc_key, enc_key + PKE_PUBLICKEYBYTES);
    return m;
}

} // namespace

adaptor_keypair_t adaptor_keygen()
{
    adaptor_keypair_t kp;
    kp.pk.resize(faest::FAEST_PUBLIC_KEY_BYTES<P>);
    kp.sk.resize(faest::FAEST_SECRET_KEY_BYTES<P>);
    faest::faest_scheme<P>::crypto_sign_keypair(kp.pk.data(), kp.sk.data());
    return kp;
}

pre_signature_t adaptor_presign(
    const std::vector<uint8_t>& ask,
    const std::vector<uint8_t>& msg,
    const std::vector<uint8_t>& helium_pk,
    const signature_instance_t& /*instance*/)
{
    pre_signature_t sigma_tilde;

    // Derive PKE key pair deterministically from a fresh random seed
    rand_bytes(sigma_tilde.seed.data(), PKE_SEED_BYTES);

    uint8_t enc_key[PKE_PUBLICKEYBYTES];
    uint8_t dec_key[PKE_SECRETKEYBYTES];
    pke_keygen_seeded(enc_key, dec_key, sigma_tilde.seed.data());

    // FAEST signs msg || helium_pk || enc_key
    auto faest_msg = build_faest_msg(msg, helium_pk, enc_key);

    uint8_t rand_seed[P::secpar_bytes];
    rand_bytes(rand_seed, sizeof(rand_seed));

    sigma_tilde.faest_sig.resize(faest::FAEST_SIGNATURE_BYTES<P>);
    bool ok = faest::faest_sign<P>(
        sigma_tilde.faest_sig.data(),
        faest_msg.data(), faest_msg.size(),
        ask.data(),
        rand_seed, sizeof(rand_seed));
    assert(ok);
    (void)ok;

    return sigma_tilde;
}

bool adaptor_pver(
    const pre_signature_t& sigma_tilde,
    const std::vector<uint8_t>& msg,
    const std::vector<uint8_t>& apk,
    const std::vector<uint8_t>& helium_pk,
    const signature_instance_t& /*instance*/)
{
    uint8_t enc_key[PKE_PUBLICKEYBYTES];
    uint8_t dec_key[PKE_SECRETKEYBYTES];
    pke_keygen_seeded(enc_key, dec_key, sigma_tilde.seed.data());

    auto faest_msg = build_faest_msg(msg, helium_pk, enc_key);

    return faest::faest_verify<P>(
        sigma_tilde.faest_sig.data(),
        faest_msg.data(), faest_msg.size(),
        apk.data());
}

adaptor_sig_t adaptor_adapt(
    const std::vector<uint8_t>& /*apk*/,
    const std::vector<uint8_t>& msg,
    const pre_signature_t& sigma_tilde,
    const keypair_t& helium_keypair,
    const signature_instance_t& instance)
{
    adaptor_sig_t sigma;

    uint8_t enc_key[PKE_PUBLICKEYBYTES];
    uint8_t dec_key[PKE_SECRETKEYBYTES];
    pke_keygen_seeded(enc_key, dec_key, sigma_tilde.seed.data());

    std::memcpy(sigma.enc_key.data(), enc_key, PKE_PUBLICKEYBYTES);
    sigma.helium_pk  = helium_keypair.second;
    sigma.faest_sig  = sigma_tilde.faest_sig;

    sigma.helium_sig = helium_sign(
        instance, helium_keypair, enc_key,
        msg.data(), msg.size());

    return sigma;
}

bool adaptor_ver(
    const std::vector<uint8_t>& apk,
    const std::vector<uint8_t>& msg,
    const adaptor_sig_t& sigma,
    const signature_instance_t& instance)
{
    auto faest_msg = build_faest_msg(msg, sigma.helium_pk, sigma.enc_key.data());

    if (!faest::faest_verify<P>(
            sigma.faest_sig.data(),
            faest_msg.data(), faest_msg.size(),
            apk.data()))
        return false;

    return helium_verify(
        instance, sigma.helium_pk, sigma.helium_sig,
        sigma.enc_key.data(), msg.data(), msg.size());
}

std::vector<uint8_t> adaptor_ext(
    const std::vector<uint8_t>& apk,
    const std::vector<uint8_t>& msg,
    const pre_signature_t& sigma_tilde,
    const adaptor_sig_t& sigma,
    const signature_instance_t& instance)
{
    if (!adaptor_ver(apk, msg, sigma, instance))
        return {};

    uint8_t dec_key[PKE_SECRETKEYBYTES];
    {
        uint8_t enc_key[PKE_PUBLICKEYBYTES];
        pke_keygen_seeded(enc_key, dec_key, sigma_tilde.seed.data());
    }

    std::vector<uint8_t> ctext = helium_compress(instance, sigma.helium_sig);
    return helium_decrypt(instance, dec_key, ctext);
}
