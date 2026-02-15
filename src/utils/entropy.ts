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
