Simple eBPF program generator.

Uniformly samples eBPF instructions, uses rBPF to provide disassembly.

## Usage

Build the container and run it.
```bash
docker build -t ebpf_fuzzer .
docker run --privileged-it --rm ebpf_fuzzer /bin/bash
```

Inside the container, generate test programs:

```bash
/fuzz/ebpf_fuzzer/target/release/ebpf_fuzzer \
    --count 100 \
    --output /fuzz/output/%d.data \
    --min-size 3 \
    --max-size 30
```

Run the test programs through the eBPF conformance test suite:

```bash
/fuzz/bpf_conformance/build/bin/bpf_conformance_runner \
    --test_file_directory /fuzz/output/ \
    --plugin_path /fuzz/bpf_conformance/build/bin/libbpf_plugin
```
