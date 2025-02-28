import { dlopen, FFIType, ptr, toArrayBuffer, suffix } from "bun:ffi";
import { existsSync } from "fs";

const libPath = `libmy_ring_vrf.${suffix}`;

console.log("Loading library from:", libPath, existsSync(libPath) ? "(found)" : "(missing)");

const {
  symbols,
  close
} = dlopen(libPath, {
  // aggregator 
  ring_vrf_ffi_aggregator: {
    returns: FFIType.ptr,
    args: ["buffer", "i32", "buffer", "ptr"],
  },
  // sign 
  ring_vrf_ffi_sign: {
    returns: FFIType.ptr,
    args: [
      "buffer", // secretHex
      "buffer", // ringKeys
      "i32",    // ringSize
      "buffer", // srsPath
      "buffer", "i32", // inputData + length
      "buffer", "i32", // auxData + length
      "i32",          // signerIdx
      "ptr"           // outLen
    ]
  },
  // verify
  ring_vrf_ffi_verify: {
    returns: FFIType.i32,
    args: [
      "buffer", "i32", "buffer",
      "buffer","i32",
      "buffer","i32",
      "buffer","i32",
      "buffer" // outVrf(32)
    ]
  },
  // free => free(pointer, int)
  ring_vrf_ffi_free: {
    returns: FFIType.void,
    args: ["ptr", "i32"],
  },
});

// Helper to build a null-terminated Buffer from a JS string
function toNullTerminatedBuffer(str: string): Buffer {
  return Buffer.from(str + "\0", "utf-8");
}

// aggregator wrapper
export function aggregator(ringKeys: string, ringSize: number, srsPath: string): Uint8Array {
  // 1) Build null-terminated buffers for ringKeys + srsPath
  const ringKeysBuf = toNullTerminatedBuffer(ringKeys);
  const srsBuf      = toNullTerminatedBuffer(srsPath);

  // out_len as int*
  const outLenBuf = new Int32Array(1);

  // 2) call aggregator
  const ptrOut = symbols.ring_vrf_ffi_aggregator(
    ringKeysBuf,
    ringSize,
    srsBuf,
    ptr(outLenBuf)
  );
  if (!ptrOut) throw new Error("aggregator returned null pointer");

  // read length
  const length = outLenBuf[0];
  // read pointer => array buffer
  const abuf = toArrayBuffer(ptrOut, 0, length);
  const finalBytes = new Uint8Array(abuf.slice(0, length));

  // 3) free pointer
  symbols.ring_vrf_ffi_free(ptrOut, length);

  return finalBytes;
}

/** sign wrapper */
export function ringVrfSign(
  secretHex: string,
  ringKeys: string,
  ringSize: number,
  srsPath: string,
  inputData: Uint8Array,
  auxData: Uint8Array,
  signerIdx: number
): Uint8Array {
  // 1) Convert strings => null-terminated buffers
  const secretBuf   = toNullTerminatedBuffer(secretHex);
  const ringKeysBuf = toNullTerminatedBuffer(ringKeys);
  const srsBuf      = toNullTerminatedBuffer(srsPath);

  const outLenBuf = new Int32Array(1);

  // 2) call sign
  const ptrOut = symbols.ring_vrf_ffi_sign(
    secretBuf,   // secret
    ringKeysBuf, // ring keys
    ringSize,
    srsBuf,      // srs
    inputData, inputData.length, // input data
    auxData,   auxData.length,   // aux data
    signerIdx,
    ptr(outLenBuf)
  );
  if (!ptrOut) throw new Error("sign returned null pointer");

  const length = outLenBuf[0];
  const abuf = toArrayBuffer(ptrOut, 0, length);
  const finalBytes = new Uint8Array(abuf.slice(0, length));

  // 3) free pointer
  symbols.ring_vrf_ffi_free(ptrOut, length);

  return finalBytes;
}

/** verify wrapper => returns { ok, vrfOutput(32) } */
export function ringVrfVerify(
  ringKeys: string,
  ringSize: number,
  srsPath: string,
  inputData: Uint8Array,
  auxData: Uint8Array,
  signature: Uint8Array
): { ok: boolean; vrfOutput: Uint8Array } {
  const ringKeysBuf = toNullTerminatedBuffer(ringKeys);
  const srsBuf      = toNullTerminatedBuffer(srsPath);

  // store the VRF output in a 32-byte buffer
  const outVrfBuf = new Uint8Array(32);

  // call verify
  const ret = symbols.ring_vrf_ffi_verify(
    ringKeysBuf,
    ringSize,
    srsBuf,
    inputData,   inputData.length,
    auxData,     auxData.length,
    signature,   signature.length,
    outVrfBuf
  );
  const ok = (ret === 1);

  return { ok, vrfOutput: outVrfBuf };
}

if (import.meta.main) {
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
    const srsPath = "/app/data/zcash-srs-2-11-uncompressed.bin";

    const result = aggregator(ringKeysStr, ringSize, srsPath);
    console.log("Aggregator length =", result.length);
    console.log("Aggregator bytes (hex) =", Buffer.from(result).toString("hex"));
  } catch (err) {
    console.error("Error:", err);
  } finally {
    close();
  }
}
