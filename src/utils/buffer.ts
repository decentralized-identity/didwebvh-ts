import { config } from '../config';

// Helper to convert bytes to hex string
const bytesToHex = (bytes: Uint8Array): string => {
  return Array.from(bytes)
    .map((b) => b.toString(16).padStart(2, '0'))
    .join('');
};

// Helper to convert hex string to bytes
const hexToBytes = (hex: string): Uint8Array => {
  if (hex.length % 2 !== 0) {
    throw new Error('Hex string must have an even number of characters');
  }
  const bytes = new Uint8Array(hex.length / 2);
  for (let i = 0; i < hex.length; i += 2) {
    bytes[i / 2] = parseInt(hex.slice(i, i + 2), 16);
  }
  return bytes;
};

// Buffer polyfill for browser environments
export const createBuffer = (input: string, encoding?: BufferEncoding): Uint8Array => {
  if (!config.isBrowser) {
    return Buffer.from(input, encoding);
  }

  // Handle base64 encoding specifically
  if (encoding === 'base64') {
    const binaryString = atob(input);
    return new Uint8Array(binaryString.length).map((_, i) => binaryString.charCodeAt(i));
  }

  // Default to UTF-8 encoding
  return new TextEncoder().encode(input);
};

export const bufferToString = (buffer: Uint8Array, encoding?: BufferEncoding): string => {
  if (!config.isBrowser) {
    return Buffer.from(buffer).toString(encoding);
  }

  // Handle hex encoding specifically
  if (encoding === 'hex') {
    return bytesToHex(buffer);
  }

  // Handle base64 encoding specifically
  if (encoding === 'base64') {
    const binary = String.fromCharCode(...buffer);
    return btoa(binary);
  }

  // Default to UTF-8 encoding
  return new TextDecoder().decode(buffer);
};

export const concatBuffers = (...buffers: Uint8Array[]): Uint8Array => {
  if (!config.isBrowser) {
    return Buffer.concat(buffers);
  }

  // Calculate total length
  const totalLength = buffers.reduce((acc, buf) => acc + buf.length, 0);

  // Create new array and copy all buffers into it
  const result = new Uint8Array(totalLength);
  let offset = 0;
  for (const buffer of buffers) {
    result.set(buffer, offset);
    offset += buffer.length;
  }

  return result;
};
