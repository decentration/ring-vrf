# ---------- Stage 1: Build Rust for x86_64 ----------
    FROM rust:latest as builder
    WORKDIR /app
    COPY . .
    RUN cargo build --release
    
# ---------- Stage 2: Debian + Bun (x86_64)  ----------
    FROM debian:bookworm-slim
    WORKDIR /app
    RUN apt-get update && apt-get install -y curl ca-certificates unzip && rm -rf /var/lib/apt/lists/*
    RUN curl -fsSL https://bun.sh/install | bash
    ENV BUN_INSTALL=/root/.bun
    ENV PATH=$BUN_INSTALL/bin:$PATH
    RUN bun upgrade
    
    COPY --from=builder /app/target/release/libmy_ring_vrf.so /app/
    COPY data ./data
    COPY ./node/src/ring_vrf_ffi.ts /app/
    
    CMD ["bun", "run", "/app/ring_vrf_ffi.ts"]
    
    