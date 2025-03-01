
# ring-vrf FFI

This project provides a **C FFI** for Rust functions that perform the **Ring VRF** aggregator, signing, and verification steps using `ark-ec-vrfs` and `bandersnatch`.

This repo consists of:

- Rust api function wrapper for `ark-ec-vrfs` (src/ring_vrf_api.rs)
- A rust => C FFI wrapper (src/lib.rs)
- C => node.js FFI (/node)
- Node.js side bun:ffi


## Features

1. **Ring Aggregator**: Creates the "ring commitment" (144 bytes).
2. **Ring VRF Signing**: Produces an anonymous ring VRF proof from a secret key + ring of public keys.
3. **Ring VRF Verification**: Checks the ring VRF proof, returning a boolean success/failure, plus the 32‑byte VRF output on success.

## Install Dependencies

### Bun
For the node.js part of the ffi we use bun and bun:ffi. So we need to install these deps:


```bash
curl -fsSL https://bun.sh/install | bash
BUN_INSTALL=/root/.bun
PATH=$BUN_INSTALL/bin:$PATH
bun upgrade
bun install

```


## Building

1. **Compile** the library:
   ```bash
   cargo build --release
   ```
This produces target/release/libmy_ring_vrf.so (Linux) or .dylib (macOS).

## Macbook M1/M2

```
cargo build --release --target aarch64-apple-darwin
```

```
then in the 


## To Use

Use the functions within `ring_vrf_ffi.ts`, or just run ring_vrf_ffi.ts to run the initial test. 

```
bun ./node/src/ring_vrf_ffi.ts
```


## Docker

Build: 
```
docker build -t my-ring-vrf .
```

Run:
```
docker run my-ring-vrf      
```

## Testing the C FFI

### Compile the C test

```
# On Linux:
gcc test_ffi.c -o test_ffi \
    -L target/release \
    -lmy_ffi_vrf \
    -I /usr/include \
    -Wl,-rpath=target/release

# On macOS:
clang test_ffi.c -o test_ffi \
    -L target/release \
    -lmy_ffi_vrf \
    -Wl,-rpath,target/release
```

### Run:

```bash
./test_ffi
```

or to just test the aggregator

## TODO

- Improve how secret key is produced. currently it is designed to pass the JAM conformance test-vectors 
- Produce tests for sign and verify 
