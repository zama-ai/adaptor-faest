#define CATCH_CONFIG_MAIN
#include <catch2/catch.hpp>

#include "../adaptor_signature.h"
#include "../instances.h"
#include "../signature.h"

TEST_CASE("Adaptor signature round-trip", "[adaptor]") {
    const signature_instance_t& instance = instance_get(AES128_L1_Param1);
    const std::vector<uint8_t> msg = {
        't', 'e', 's', 't', 'm', 's', 'g'
    };

    // KeyGen
    adaptor_keypair_t kp = adaptor_keygen();
    REQUIRE(kp.pk.size() == ADAPTOR_PK_BYTES);
    REQUIRE(kp.sk.size() == ADAPTOR_SK_BYTES);

    // Generate Helium keypair (AES key + plaintext||ciphertext)
    keypair_t helium_keypair = helium_keygen(instance);
    const std::vector<uint8_t>& helium_pk = helium_keypair.second;

    // preSign
    pre_signature_t sigma_tilde = adaptor_presign(kp.sk, msg, helium_pk, instance);
    REQUIRE(sigma_tilde.faest_sig.size() > 0);

    // pVer
    REQUIRE(adaptor_pver(sigma_tilde, msg, kp.pk, helium_pk, instance));

    // pVer rejects wrong message
    std::vector<uint8_t> wrong_msg = {'w', 'r', 'o', 'n', 'g'};
    REQUIRE_FALSE(adaptor_pver(sigma_tilde, wrong_msg, kp.pk, helium_pk, instance));

    // Adapt
    adaptor_sig_t sigma = adaptor_adapt(kp.pk, msg, sigma_tilde, helium_keypair, instance);
    REQUIRE(sigma.helium_pk == helium_pk);
    REQUIRE(sigma.faest_sig == sigma_tilde.faest_sig);
    REQUIRE(sigma.helium_sig.size() > 0);

    // Ver
    REQUIRE(adaptor_ver(kp.pk, msg, sigma, instance));

    // Ver rejects wrong message
    REQUIRE_FALSE(adaptor_ver(kp.pk, wrong_msg, sigma, instance));

    // Ext: recover the AES key
    std::vector<uint8_t> extracted = adaptor_ext(kp.pk, msg, sigma_tilde, sigma, instance);
    REQUIRE(extracted == helium_keypair.first);
}
