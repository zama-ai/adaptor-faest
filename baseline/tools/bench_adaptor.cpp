#include "../adaptor_signature.h"
#include "../instances.h"
#include "bench_timing.h"
#include "bench_utils.h"

#include <cinttypes>
#include <cstdio>
#include <cstdlib>
#include <fstream>
#include <iostream>
#include <string>

// Detect SCALING_FACTOR: returns cycles/ms (perf counters) or 1000 (clock µs fallback).
static double detect_scaling_factor() {
    std::ifstream paranoid_f("/proc/sys/kernel/perf_event_paranoid");
    if (paranoid_f.is_open()) {
        int paranoid = 3;
        paranoid_f >> paranoid;
        if (paranoid <= 2) {
            std::ifstream freq_f("/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq");
            if (freq_f.is_open()) {
                uint64_t freq_khz = 0;
                freq_f >> freq_khz;
                if (freq_khz > 0)
                    return static_cast<double>(freq_khz); // cycles/ms = kHz
            }
        }
    }
    return 1000.0; // clock() fallback returns µs; 1 ms = 1000 µs
}

struct adaptor_timing_t {
    double keygen_ms, presign_ms, pver_ms, adapt_ms, ver_ms, ext_ms;
    uint64_t sigma_tilde_size, sigma_size;
};

static void print_timings(const std::vector<adaptor_timing_t>& timings) {
    adaptor_timing_t avg = {};
    printf("keygen_ms,presign_ms,pver_ms,adapt_ms,ver_ms,ext_ms,sigma_tilde_size,sigma_size\n");
    for (size_t i = 0; i < timings.size(); i++) {
        const auto& t = timings[i];
        printf("%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%" PRIu64 ",%" PRIu64 "\n",
               t.keygen_ms, t.presign_ms, t.pver_ms,
               t.adapt_ms, t.ver_ms, t.ext_ms,
               t.sigma_tilde_size, t.sigma_size);
        if (i > 0) {
            avg.keygen_ms      += t.keygen_ms;
            avg.presign_ms     += t.presign_ms;
            avg.pver_ms        += t.pver_ms;
            avg.adapt_ms       += t.adapt_ms;
            avg.ver_ms         += t.ver_ms;
            avg.ext_ms         += t.ext_ms;
            avg.sigma_tilde_size += t.sigma_tilde_size;
            avg.sigma_size     += t.sigma_size;
        }
    }
    uint64_t n = timings.size() - 1;
    printf("average of last %" PRIu64 " rows:\n", n);
    printf("%.4f,%.4f,%.4f,%.4f,%.4f,%.4f,%" PRIu64 ",%" PRIu64 "\n",
           avg.keygen_ms / n, avg.presign_ms / n, avg.pver_ms / n,
           avg.adapt_ms / n, avg.ver_ms / n, avg.ext_ms / n,
           avg.sigma_tilde_size / n, avg.sigma_size / n);
}

static int bench_adaptor(const bench_options_t* options) {
    static const uint8_t msg[] = {1, 2, 3, 4, 5, 6, 7, 8,
                                   9, 10, 11, 12, 13, 14, 15, 16};

    const signature_instance_t& instance = instance_get(options->params);
    printf("Instance: N=%u, tau=%u\n",
           instance.num_MPC_parties, instance.num_repetitions);

    double sf = detect_scaling_factor();

    timing_context_t ctx;
    if (!timing_init(&ctx)) {
        printf("Failed to initialize timing.\n");
        return -1;
    }

    std::vector<adaptor_timing_t> timings(options->iter);

    for (uint32_t i = 0; i < options->iter; ++i) {
        adaptor_timing_t& t = timings[i];

        // Generate Helium witness keypair (not timed)
        keypair_t helium_kp = helium_keygen(instance);
        const std::vector<uint8_t>& helium_pk = helium_kp.second;

        // KeyGen: FAEST keypair only
        uint64_t t0 = timing_read(&ctx);
        adaptor_keypair_t kp = adaptor_keygen();
        uint64_t t1 = timing_read(&ctx);
        t.keygen_ms = (t1 - t0) / sf;

        // preSign
        t0 = timing_read(&ctx);
        pre_signature_t sigma_tilde = adaptor_presign(
            kp.sk, {msg, msg + sizeof(msg)}, helium_pk, instance);
        t1 = timing_read(&ctx);
        t.presign_ms = (t1 - t0) / sf;
        t.sigma_tilde_size = sigma_tilde.faest_sig.size() + sigma_tilde.seed.size();

        // pVer
        t0 = timing_read(&ctx);
        bool pv = adaptor_pver(sigma_tilde, {msg, msg + sizeof(msg)}, kp.pk, helium_pk, instance);
        t1 = timing_read(&ctx);
        t.pver_ms = (t1 - t0) / sf;
        if (!pv) std::cerr << "pVer failed\n";

        // Adapt
        t0 = timing_read(&ctx);
        adaptor_sig_t sigma = adaptor_adapt(
            kp.pk, {msg, msg + sizeof(msg)}, sigma_tilde, helium_kp, instance);
        t1 = timing_read(&ctx);
        t.adapt_ms = (t1 - t0) / sf;
        t.sigma_size = sigma.helium_pk.size() + sigma.enc_key.size()
                     + sigma.faest_sig.size() + sigma.helium_sig.size();

        // Ver
        t0 = timing_read(&ctx);
        bool v = adaptor_ver(kp.pk, {msg, msg + sizeof(msg)}, sigma, instance);
        t1 = timing_read(&ctx);
        t.ver_ms = (t1 - t0) / sf;
        if (!v) std::cerr << "Ver failed\n";

        // Ext
        t0 = timing_read(&ctx);
        std::vector<uint8_t> extracted = adaptor_ext(
            kp.pk, {msg, msg + sizeof(msg)}, sigma_tilde, sigma, instance);
        t1 = timing_read(&ctx);
        t.ext_ms = (t1 - t0) / sf;
        if (extracted != helium_kp.first) std::cerr << "Ext failed\n";
    }

    timing_close(&ctx);
    print_timings(timings);
    return 0;
}

int main(int argc, char** argv) {
    bench_options_t opts = {PARAMETER_SET_INVALID, 0};
    if (!parse_args(&opts, argc, argv))
        return -1;
    return bench_adaptor(&opts);
}
