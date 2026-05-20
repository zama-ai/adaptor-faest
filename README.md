# adaptor-faest

Adaptor signature based on FAEST v2.


## Prerequisite

A rust compiler, at the time of writing the projected is tested with `rustc
1.94.0`. For the best performance, use

```
RUSTFLAGS="-C target-cpu=native"
```

when building the project.


## Benchmark

The basic benchmark can be executed by running the following script.  If no
input arguments are given, the result will be written to the file
`bench-results.csv`.


```
./run-benchmarks.sh
```

## Profiling


Follow the instructions on https://github.com/flamegraph-rs/flamegraph to
install the dependencies. Then run the following command.


```
cargo flamegraph --freq 200 --bench adaptor -- --bench <benchmark_name> --profile-time 30
```

Where `<benchmark_name>` is one of the benchmarks, e.g., `standard_adaptor_faest128f/adapt`.

## License

This software is distributed under the BSD-3-Clause-Clear license.  This
license applies to the entire repo except for subfolders that have their own
license file. In such cases, the license file in the subfolder takes precedence.

