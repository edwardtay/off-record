// Node implementations of the engine's crypto and network dependencies.

const PCS = 'https://api.trustedservices.intel.com';
/** Intel's public collateral endpoints. The page's pass-through (serve.mjs, nginx) maps to the same URLs. */
export function intelUrl(kind, arg = '') {
  if (kind === 'tcb' && /^[0-9A-Fa-f]{12}$/.test(arg)) return `${PCS}/tdx/certification/v4/tcb?fmspc=${arg}`;
  if (kind === 'qe' && !arg) return `${PCS}/tdx/certification/v4/qe/identity`;
  if (kind === 'pckcrl' && /^(platform|processor)$/.test(arg)) return `${PCS}/sgx/certification/v4/pckcrl?ca=${arg}&encoding=der`;
  if (kind === 'rootcrl' && !arg) return 'https://certificates.trustedservices.intel.com/IntelSGXRootCA.der';
  return null;
}

export const nodeDeps = {
  fetch: globalThis.fetch,
  // The browser goes through prompt20.com's pass-through for these (they send no CORS headers).
  // Node calls Intel's PCS and NVIDIA directly.
  pcsUrl: (kind, arg) => intelUrl(kind, arg),
  gpuUrl: 'https://nras.attestation.nvidia.com/v3/attest/gpu',
};
