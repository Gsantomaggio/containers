

build-aarch64:
	AYA_BUILD_EBPF=true CC=aarch64-linux-musl-gcc cargo build --package ebpf_rust_firewall --release \
  --target=aarch64-unknown-linux-musl \
  --config=target.aarch64-unknown-linux-musl.linker=\"aarch64-linux-musl-gcc\"
