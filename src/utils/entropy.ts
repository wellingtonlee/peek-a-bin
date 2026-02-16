export function computeEntropyBlocks(bytes: Uint8Array, blockSize = 256): number[] {
  const blocks: number[] = [];
  for (let i = 0; i < bytes.length; i += blockSize) {
    const end = Math.min(i + blockSize, bytes.length);
    const freq = new Uint32Array(256);
    for (let j = i; j < end; j++) freq[bytes[j]]++;
    const len = end - i;
    let entropy = 0;
    for (let k = 0; k < 256; k++) {
      if (freq[k] === 0) continue;
      const p = freq[k] / len;
      entropy -= p * Math.log2(p);
    }
    blocks.push(entropy);
  }
  return blocks;
}

export function computeSectionEntropy(bytes: Uint8Array): number {
  if (bytes.length === 0) return 0;
  const freq = new Uint32Array(256);
  for (let i = 0; i < bytes.length; i++) freq[bytes[i]]++;
  let entropy = 0;
  for (let k = 0; k < 256; k++) {
    if (freq[k] === 0) continue;
    const p = freq[k] / bytes.length;
    entropy -= p * Math.log2(p);
  }
  return entropy;
}

export interface EntropyClassification {
  label: string;
  color: string;
}

export function classifyEntropy(avgEntropy: number): EntropyClassification {
  if (avgEntropy < 1.0) return { label: "empty", color: "text-gray-500" };
  if (avgEntropy < 4.0) return { label: "low - data/code", color: "text-green-400" };
  if (avgEntropy < 6.5) return { label: "normal - code", color: "text-blue-400" };
  if (avgEntropy < 7.5) return { label: "high - compressed?", color: "text-yellow-400" };
  return { label: "very high - packed/encrypted?", color: "text-red-400" };
}
