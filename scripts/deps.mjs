// Node implementations of the engine's crypto and network dependencies.
import { verifyMessage } from 'ethers';

export const nodeDeps = {
  fetch: globalThis.fetch,
  recover: (msg, sig) => verifyMessage(msg, sig),
  // The browser goes through prompt20.com's pass-through for these two (they send no CORS
  // headers). Node calls the vendors directly.
  tdxUrl: 'https://cloud-api.phala.network/api/v1/attestations/verify',
  gpuUrl: 'https://nras.attestation.nvidia.com/v3/attest/gpu',
};
