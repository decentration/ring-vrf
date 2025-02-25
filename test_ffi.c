#include <stdio.h>
#include <stdint.h>
#include <stdlib.h>
#include <string.h>

// The Rust FFI exports
// aggregator
extern uint8_t* ring_vrf_ffi_aggregator(
    const char* keys_str,
    int ring_size,
    const char* srs_path,
    int* out_len
);

// sign
extern uint8_t* ring_vrf_ffi_sign(
    const char* secret_hex,
    const char* keys_str,
    int ring_size,
    const char* srs_path,
    const uint8_t* input_data, int input_len,
    const uint8_t* aux_data,   int aux_len,
    int signer_idx,
    int* out_len
);

// verify
extern int ring_vrf_ffi_verify(
    const char* keys_str,
    int ring_size,
    const char* srs_path,
    const uint8_t* input_data, int input_len,
    const uint8_t* aux_data,   int aux_len,
    const uint8_t* sig_ptr,    int sig_len,
    uint8_t* out_vrf // 32 bytes
);

// free
extern void ring_vrf_ffi_free(uint8_t* ptr, int len);

int main() {
    // 1) aggregator test
    {
        const char* ring_keys =
            "5e465beb01dbafe160ce8216047f2155dd0569f058afd52dcea601025a8d161d "
            "3d5e5a51aab2b048f8686ecd79712a80e3265a114cc73f14bdb2a59233fb66d0 "
            "aa2b95f7572875b0d0f186552ae745ba8222fc0b5bd456554bfe51c68938f8bc "
            "7f6190116d118d643a98878e294ccf62b509e214299931aad8ff9764181a4e33 "
            "48e5fcdce10e0b64ec4eebd0d9211c7bac2f27ce54bca6f7776ff6fee86ab3e3 "
            "f16e5352840afb47e206b5c89f560f2611835855cf2e6ebad1acc9520a72591d";
        int ring_size = 6;
        const char* srs_path = "./data/zcash-srs-2-11-uncompressed.bin";

        int out_len = 0;
        uint8_t* aggregator = ring_vrf_ffi_aggregator(
            ring_keys, ring_size, srs_path, &out_len
        );
        if (!aggregator) {
            fprintf(stderr, "[AGGREGATOR] Null pointer from ring_vrf_ffi_aggregator!\n");
            return 1;
        }
        printf("[AGGREGATOR] aggregator len=%d\n", out_len);
        // print hex
        for (int i = 0; i < out_len; i++) {
            printf("%02x", aggregator[i]);
        }
        printf("\n");
        // free
        ring_vrf_ffi_free(aggregator, out_len);
    }

    // 2) ring VRF sign test
    {
   
        const char* ring_keys =
            "5e465beb01dbafe160ce8216047f2155dd0569f058afd52dcea601025a8d161d "
            "3d5e5a51aab2b048f8686ecd79712a80e3265a114cc73f14bdb2a59233fb66d0 "
            "aa2b95f7572875b0d0f186552ae745ba8222fc0b5bd456554bfe51c68938f8bc "
            "7f6190116d118d643a98878e294ccf62b509e214299931aad8ff9764181a4e33 "
            "48e5fcdce10e0b64ec4eebd0d9211c7bac2f27ce54bca6f7776ff6fee86ab3e3 "
            "f16e5352840afb47e206b5c89f560f2611835855cf2e6ebad1acc9520a72591d";
        int ring_size = 6;
        const char* srs_path = "./data/zcash-srs-2-11-uncompressed.bin";

       // dummy example:
        const char* secret_hex = "ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff";

        // VRF input
        const uint8_t input_data[] = { 'f','o','o' };
        int input_len = 3;
        // aux data
        const uint8_t aux_data[] = { 'b','a','r' };
        int aux_len = 3;
        int signer_idx = 2; // 3rd key in the ring

        int out_len = 0;
        uint8_t* sig_bytes = ring_vrf_ffi_sign(
            secret_hex,
            ring_keys,
            ring_size,
            srs_path,
            input_data, input_len,
            aux_data, aux_len,
            signer_idx,
            &out_len
        );
        if (!sig_bytes) {
            fprintf(stderr, "[SIGN] Null pointer from ring_vrf_ffi_sign!\n");
            return 1;
        }
        printf("[SIGN] ring VRF signature len=%d\n", out_len);
        for (int i = 0; i < out_len; i++) {
            printf("%02x", sig_bytes[i]);
        }
        printf("\n");

        // 3) ring VRF verify
        // because no secret key expect FAIL
        {
            uint8_t out_vrf[32];
            memset(out_vrf, 0, 32);

            int ret = ring_vrf_ffi_verify(
                ring_keys,
                ring_size,
                srs_path,
                input_data, input_len,
                aux_data, aux_len,
                sig_bytes, out_len,
                out_vrf
            );
            if (ret == 1) {
                printf("[VERIFY] success! VRF output = ");
                for (int i = 0; i < 32; i++) {
                    printf("%02x", out_vrf[i]);
                }
                printf("\n");
            } else {
                fprintf(stderr, "[VERIFY] fail!\n");
            }
        }

        // free the sig bytes
        ring_vrf_ffi_free(sig_bytes, out_len);
    }

    printf("All ring VRF steps done.\n");
    return 0;
}
