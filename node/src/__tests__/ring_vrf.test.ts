// import path from 'path';
// import fs from 'fs';

// // Import the aggregator, sign, verify, from your FFI library file
// import { aggregator, ringVrfSign, ringVrfVerify } from '../index';

// describe('Ring VRF FFI Tests (C-style output)', () => {
//   it('runs aggregator -> sign -> verify, printing similar messages to the C code', () => {
//     // 1) aggregator test
//     {
//       const ringKeys = [
//         '5e465beb01dbafe160ce8216047f2155dd0569f058afd52dcea601025a8d161d',
//         '3d5e5a51aab2b048f8686ecd79712a80e3265a114cc73f14bdb2a59233fb66d0',
//         'aa2b95f7572875b0d0f186552ae745ba8222fc0b5bd456554bfe51c68938f8bc',
//         '7f6190116d118d643a98878e294ccf62b509e214299931aad8ff9764181a4e33',
//         '48e5fcdce10e0b64ec4eebd0d9211c7bac2f27ce54bca6f7776ff6fee86ab3e3',
//         'f16e5352840afb47e206b5c89f560f2611835855cf2e6ebad1acc9520a72591d',
//       ].join(' ');

//       const ringSize = 6;
//       // If your file is at <projectRoot>/data/zcash-srs-2-11-uncompressed.bin:
//       const srsPath = path.join(__dirname, '../../../data/zcash-srs-2-11-uncompressed.bin');

//       const aggregatorBuf = aggregator(ringKeys, ringSize, srsPath);
//       console.log(`[AGGREGATOR] aggregator len=${aggregatorBuf.length}`);

//       // Print hex
//       const aggregatorHex = Buffer.from(aggregatorBuf).toString('hex');
//       console.log(aggregatorHex);
//     }

//     // 2) ring VRF sign test
//     {
//       const ringKeys = [
//         '5e465beb01dbafe160ce8216047f2155dd0569f058afd52dcea601025a8d161d',
//         '3d5e5a51aab2b048f8686ecd79712a80e3265a114cc73f14bdb2a59233fb66d0',
//         'aa2b95f7572875b0d0f186552ae745ba8222fc0b5bd456554bfe51c68938f8bc',
//         '7f6190116d118d643a98878e294ccf62b509e214299931aad8ff9764181a4e33',
//         '48e5fcdce10e0b64ec4eebd0d9211c7bac2f27ce54bca6f7776ff6fee86ab3e3',
//         'f16e5352840afb47e206b5c89f560f2611835855cf2e6ebad1acc9520a72591d',
//       ].join(' ');

//       const ringSize = 6;
//       const srsPath = path.join(__dirname, '../../../data/zcash-srs-2-11-uncompressed.bin');

//       // Dummy secret for demonstration
//       const secretHex = 'ffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffffff';

//       // VRF input + aux data
//       const inputData = Buffer.from('foo');
//       const auxData = Buffer.from('bar');
//       const signerIdx = 2; // 3rd key

//       const sigBytes = ringVrfSign(secretHex, ringKeys, ringSize, srsPath, inputData, auxData, signerIdx);
//       console.log(`[SIGN] ring VRF signature len=${sigBytes.length}`);

//       // Print signature in hex
//       const sigHex = sigBytes.toString('hex');
//       console.log(sigHex);

//       // 3) ring VRF verify
//       {
//         const { ok, vrfOutput } = ringVrfVerify(ringKeys, ringSize, srsPath, inputData, auxData, sigBytes);
//         if (ok) {
//           console.log('[VERIFY] success! VRF output =', vrfOutput.toString('hex'));
//         } else {
//           console.error('[VERIFY] fail!');
//         }
//       }
//     }

//     console.log('All ring VRF steps done.');
//   });
// });
