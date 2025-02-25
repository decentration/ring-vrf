#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// FFI function signatures from Rust library
extern uint8_t* ring_vrf_ffi_aggregator(
    const char* keys_str,
    int ring_size,
    const char* srs_path,
    int* out_len
);

extern void ring_vrf_ffi_free(uint8_t* ptr, int len);

int main() {
    // 1) Input data for the aggregator
    // space-separated bandersnatch pubkeys in hex
    const char* keys_str = 
        "5e465beb01dbafe160ce8216047f2155dd0569f058afd52dcea601025a8d161d "
        "3d5e5a51aab2b048f8686ecd79712a80e3265a114cc73f14bdb2a59233fb66d0 "
        "aa2b95f7572875b0d0f186552ae745ba8222fc0b5bd456554bfe51c68938f8bc "
        "7f6190116d118d643a98878e294ccf62b509e214299931aad8ff9764181a4e33 "
        "48e5fcdce10e0b64ec4eebd0d9211c7bac2f27ce54bca6f7776ff6fee86ab3e3 "
        "f16e5352840afb47e206b5c89f560f2611835855cf2e6ebad1acc9520a72591d";
    int ring_size = 6;
    const char* srs_path = "./data/zcash-srs-2-11-uncompressed.bin";

    // 2) Call aggregator function
    int out_len = 0;
    uint8_t* aggregator = ring_vrf_ffi_aggregator(keys_str, ring_size, srs_path, &out_len);
    if (!aggregator) {
        fprintf(stderr, "ERROR: aggregator returned NULL\n");
        return 1;
    }
    printf("Aggregator len=%d\n", out_len);

    // 3) Print aggregator as hex
    for (int i = 0; i < out_len; i++) {
        printf("%02x", aggregator[i]);
    }
    printf("\n");

    // 4) Free the pointer
    ring_vrf_ffi_free(aggregator, out_len);

    return 0;
}

void ring_vrf_ffi_free(uint8_t * ptr, int len)
{
}
