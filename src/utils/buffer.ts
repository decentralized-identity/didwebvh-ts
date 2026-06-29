export const concatBuffers = (...buffers: Uint8Array[]): Uint8Array => {
  const totalLength = buffers.reduce((acc, buf) => acc + buf.length, 0);

  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const buffer of buffers) {
    result.set(buffer, offset);
    offset += buffer.length;
  }

  return result;
};
