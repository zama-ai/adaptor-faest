#!/usr/bin/env python3
import os
import subprocess

executable = "./bench_adaptor"
logfile    = "bench_adaptor_output.txt"
iterations = 101

# (param_index, N, tau)
instances = [
    #(1,  16,  31),   # AES128_L1_Param1
    #(2,  57,  22),   # AES128_L1_Param2
    (3, 256,  16),   # AES128_L1_Param3
]


def parse_bench(filename):
    with open(filename) as f:
        content = f.read()

    # Strip the "Instance: ..." header line
    lines = [l for l in content.splitlines() if l.strip()]
    # Find the CSV header
    start = next(i for i, l in enumerate(lines) if l.startswith("keygen_ms"))
    data_lines = lines[start + 1:]

    # Drop first data row (warmup) and the trailing average lines
    data_lines = [l for l in data_lines if not l.startswith("average")]
    data_lines = data_lines[1:]  # skip warmup row

    count = 0
    keygen = presign = pver = adapt = ver = ext = 0.0
    st_size = s_size = 0

    for line in data_lines:
        if not line.strip():
            continue
        cols = line.strip().split(",")
        keygen  += float(cols[0])
        presign += float(cols[1])
        pver    += float(cols[2])
        adapt   += float(cols[3])
        ver     += float(cols[4])
        ext     += float(cols[5])
        st_size += int(cols[6])
        s_size  += int(cols[7])
        count   += 1

    keygen  /= count
    presign /= count
    pver    /= count
    adapt   /= count
    ver     /= count
    ext     /= count
    st_size //= count
    s_size  //= count

    return keygen, presign, pver, adapt, ver, ext, st_size, s_size


SCHEME      = r"\cite{RSA:CLTZ25} $+$ \cite{CiC:TakZav24}"
APK_BYTES   = 32   # ADAPTOR_PK_BYTES (FAEST 128f public key)
ASK_BYTES   = 32   # ADAPTOR_SK_BYTES (FAEST 128f secret key)

HEADER = (r"Scheme & $|\apk|$ & $|\ask|$ & $|\psig|$ & $|\asig|$ & "
          r"$\asGen$ & $\aspSig$ & $\aspVer$ & $\asAdapt$ & $\asVer$ & $\asExt$")

print("Benchmarking adaptor signature")
print(HEADER + r" \\ \midrule")
for param_idx, N, tau in instances:
    cmd = f"{executable} -i {iterations} {param_idx} > {logfile}"
    ret = os.system(cmd)
    if os.WEXITSTATUS(ret) != 0:
        print(f"Failed to run {executable} for param {param_idx}")
        continue

    keygen, presign, pver, adapt, ver, ext, st_size, s_size = parse_bench(logfile)
    print(f"{SCHEME} & {APK_BYTES} & {ASK_BYTES} & "
          f"{st_size} & {s_size} & "
          f"{keygen:.2f} & {presign:.2f} & {pver:.2f} & "
          f"{adapt:.2f} & {ver:.2f} & {ext:.2f} \\\\")
