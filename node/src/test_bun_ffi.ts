import { dlopen, FFIType, suffix, CString, ptr, toArrayBuffer } from "bun:ffi";
import { existsSync } from "fs";

const libPath = `libmy_ring_vrf.so`;
// const fileUrl = import.meta.resolve("./libmy_ring_vrf.so"); 
// const path = new URL(fileUrl).pathname; 


console.log("Loading library from:", libPath, existsSync(libPath) ? "(found)" : "(missing)");

const {
  symbols,
  close
} = dlopen(libPath, {
  ring_vrf_ffi_aggregator: {
    returns: FFIType.ptr,
    // The aggregator function signature is (const char* keys, int ring_size, const char* srs, int* out_len)
    args: ["buffer", "i32", "buffer", "ptr"],
  },
  ring_vrf_ffi_free: {
    returns: FFIType.void,
    // free(pointer, int length)
    args: ["ptr", "i32"],
  },
 
  
  // ring_vrf_ffi_sign: {...},
  // ring_vrf_ffi_verify: {...},
});


try {

  const ringKeysStr = [
    "5e465beb01dbafe160ce8216047f2155dd0569f058afd52dcea601025a8d161d",
    "3d5e5a51aab2b048f8686ecd79712a80e3265a114cc73f14bdb2a59233fb66d0",
    "aa2b95f7572875b0d0f186552ae745ba8222fc0b5bd456554bfe51c68938f8bc",
    "7f6190116d118d643a98878e294ccf62b509e214299931aad8ff9764181a4e33",
    "48e5fcdce10e0b64ec4eebd0d9211c7bac2f27ce54bca6f7776ff6fee86ab3e3",
    "f16e5352840afb47e206b5c89f560f2611835855cf2e6ebad1acc9520a72591d",
  ].join(" ");
  const ringSize = 6;
  // The SRS in Docker at /app/data
  const srsPathStr = "/app/data/zcash-srs-2-11-uncompressed.bin";

  // store out_len in a small Int32Array
  const outLenBuf = new Int32Array(1);

  // convert ringKeys to a buffer
  const ringKeysBuf = Buffer.from(ringKeysStr, "utf-8");
  const srsPathBuf  = Buffer.from(srsPathStr + "\0", "utf8");

  // 1) Call aggregator
  const ptrOut = symbols.ring_vrf_ffi_aggregator(
    ringKeysBuf, 
    ringSize, 
    srsPathBuf, 
    ptr(outLenBuf)
  );  if (!ptrOut) {
    throw new Error("ring_vrf_ffi_aggregator returned null pointer");
  }

  // read the length
  const length = outLenBuf[0];
  console.log("aggregator returned pointer, length =", length);

  // 2) Convert pointer -> ArrayBuffer
  const abuf = toArrayBuffer(ptrOut, 0, length);

  // 3) Copy it into a new typed array
  const finalBytes = new Uint8Array(abuf.slice(0, length));

  // 4) free the pointer
  symbols.ring_vrf_ffi_free(ptrOut, length);

  // finalBytes is safe to log or iterate
  console.log("aggregator bytes (hex) =", [...finalBytes]
    .map(b => b.toString(16).padStart(2,"0"))
    .join("")
  );

} catch (err) {
  console.error("Error:", err);
} finally {

  close();
  console.log("Done aggregator test with Bun FFI");
}
