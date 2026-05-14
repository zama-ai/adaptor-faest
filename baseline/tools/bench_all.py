#!/usr/bin/env python3
import sys
import os

executable = "./bench_free"
parser = "./"
logfile = "bench_output.txt"
iterations = 101


# AES 128
# kappa, sboxes, N, Tau
aes128_parameters = [
    #(128, 200, 17, 31),
    #(128, 200, 19, 30),
    #(128, 200, 31, 26),
    #(128, 200, 57, 22),
    #(128, 200, 107, 19),
    #(128, 200, 139, 18),
    #(128, 200, 185, 17),
    (128, 200, 255, 16),
    #(128, 200, 371, 15),
    #(128, 200, 565, 14),
    #(128, 200, 921, 13),
    #(128, 200, 1625, 12),
    #(128, 200, 3183, 11),
    #(128, 200, 7131, 10),
]


def _detect_scaling_factor():
    # bench_timing uses perf HW cycle counters when perf_event_paranoid <= 2,
    # otherwise falls back to clock() which returns microseconds on Linux.
    try:
        paranoid = int(open("/proc/sys/kernel/perf_event_paranoid").read())
        if paranoid <= 2:
            # Output is in CPU cycles; cycles_per_ms = freq_kHz
            freq_khz = int(open(
                "/sys/devices/system/cpu/cpu0/cpufreq/cpuinfo_max_freq").read())
            return freq_khz
    except (OSError, ValueError):
        pass
    # clock() fallback: returns microseconds (CLOCKS_PER_SEC = 1e6 on Linux)
    return 1000


SCALING_FACTOR = _detect_scaling_factor()


def parse_bench(filename):
    with open(filename, "r") as f:
        content = f.read()

    testruns = content.split("Instance: ")
    if len(testruns) > 1:
        testruns.pop(0)

    for test in testruns:
        lines = test.splitlines()
        # first line is instance:
        lines.pop(0)
        # second line is header:
        lines.pop(0)
        # Drop the first line because it's always an outlier:
        lines.pop(0)
        # Remove last two lines which display the average:
        lines.pop()
        lines.pop()

        count = 0
        keygen, sign, ver, compress, decrypt, size = 0, 0, 0, 0, 0, 0

        for line in lines:
            if len(line.strip()) == 0:
                continue
            vals = line.strip().split(",")
            keygen   += int(vals[0])
            sign     += int(vals[1])
            ver      += int(vals[2])
            compress += int(vals[3])
            decrypt  += int(vals[4])
            size     += int(vals[5])
            count += 1

        keygen   = (keygen   / SCALING_FACTOR) / count
        sign     = (sign     / SCALING_FACTOR) / count
        ver      = (ver      / SCALING_FACTOR) / count
        compress = (compress / SCALING_FACTOR) / count
        decrypt  = (decrypt  / SCALING_FACTOR) / count
        size = float(size) / count
        print("{:.2f} & {:.2f} & {:.2f} & {:.2f} & {:.0f} \\\\".format(
            sign, ver, compress, decrypt, size))


print("Benchmarking parameters")
for kappa, sboxes, N, tau in aes128_parameters:
    command = "{executable} -i {iter} {kappa} {sboxes} {N} {tau} > {logfile}".format(
        executable=executable, iter=iterations, kappa=kappa/8, N=N, tau=tau, sboxes=sboxes, logfile=logfile)
    #print("running: ", command)
    ret = os.system(command)
    if os.WEXITSTATUS(ret) != 0:
        print("Failed to run {executable}".format(executable=executable))
    print("{kappa} & {N} & {tau} & ".format(kappa=kappa, N=N, tau=tau), end="")
    parse_bench(logfile)
