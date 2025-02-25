FROM ubuntu:24.04

RUN apt-get update && apt-get install -y \
    libboost-dev \
    libboost-filesystem-dev \
    libboost-program-options-dev \
    libelf-dev \
    lcov \
    libbpf-dev \
    git \
    cmake \
    clang \
    curl

WORKDIR /fuzz

# Build bpf_conformance
RUN git clone --depth 1 https://github.com/Alan-Jowett/bpf_conformance.git --recurse-submodules && \
    cd bpf_conformance && \
    cmake -S . -B build && \
    cmake --build build

# Install rust
RUN curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh -s -- -y
ENV PATH="/root/.cargo/bin:${PATH}"

COPY ebpf_fuzzer /fuzz/ebpf_fuzzer

# Build ebpf_fuzzer and generate 100 programs
RUN cd ebpf_fuzzer && \
    cargo build --release && \
    ./target/release/ebpf_fuzzer \
        --count 100 \
        --output /fuzz/output/%d.data \
        --min-size 3 \
        --max-size 40

# Inside the container, run:

# ./bpf_conformance/build/bin/bpf_conformance_runner \
#     --test_file_directory /fuzz/output/ \
#     --plugin_path /fuzz/bpf_conformance/build/bin/libbpf_plugin
