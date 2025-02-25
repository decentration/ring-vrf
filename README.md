
# ring-vrf FFI

This project provides a **C FFI** for Rust functions that perform the **Ring VRF** aggregator, signing, and verification steps using `ark-ec-vrfs` and `bandersnatch`.

## Features

1. **Ring Aggregator**: Creates the "ring commitment" (often 144 bytes).
2. **Ring VRF Signing**: Produces an anonymous ring VRF proof from a secret key + ring of public keys.
3. **Ring VRF Verification**: Checks the ring VRF proof, returning a boolean success/failure, plus the 32‑byte VRF output on success.





## Building

1. **Compile** the library:
   ```bash
   cargo build --release
   ```
This produces target/release/libmy_ring_vrf.so (Linux) or .dylib (macOS).

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


