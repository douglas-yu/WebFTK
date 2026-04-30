/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export interface FileSignature {
  name: string;
  extension: string;
  hex: string[];
  offset: number;
}

// Common file signatures (Magic Bytes)
export const FILE_SIGNATURES: FileSignature[] = [
  { name: 'JPEG Image', extension: 'jpg', hex: ['FF', 'D8', 'FF'], offset: 0 },
  { name: 'PNG Image', extension: 'png', hex: ['89', '50', '4E', '47', '0D', '0A', '1A', '0A'], offset: 0 },
  { name: 'PDF Document', extension: 'pdf', hex: ['25', '50', '44', '46'], offset: 0 },
  { name: 'ZIP Archive', extension: 'zip', hex: ['50', '4B', '03', '04'], offset: 0 },
  { name: 'GIF Image', extension: 'gif', hex: ['47', '49', '46', '38'], offset: 0 },
  { name: 'Executable (Windows)', extension: 'exe', hex: ['4D', '5A'], offset: 0 },
  { name: 'MP4 Video', extension: 'mp4', hex: ['00', '00', '00', '18', '66', '74', '79', '70', '69', '73', '6F', '6D'], offset: 0 },
  { name: 'MP4 Video (v2)', extension: 'mp4', hex: ['00', '00', '00', '20', '66', '74', '79', '70', '69', '73', '6F', '6D'], offset: 0 },
  { name: 'QuickTime Video', extension: 'mov', hex: ['66', '74', '79', '70', '71', '74', '20', '20'], offset: 4 },
  { name: '7-Zip Archive', extension: '7z', hex: ['37', '7A', 'BC', 'AF', '27', '1C'], offset: 0 },
  { name: 'RAR Archive', extension: 'rar', hex: ['52', '61', '72', '21', '1A', '07'], offset: 0 },
  { name: 'SQLite Database', extension: 'sqlite', hex: ['53', '51', '4C', '69', '74', '65', '20', '66', '6F', '72', '6D', '61', '74', '20', '33'], offset: 0 },
  { name: 'Java Class', extension: 'class', hex: ['CA', 'FE', 'BA', 'BE'], offset: 0 },
  { name: 'RTF Document', extension: 'rtf', hex: ['7B', '5C', '72', '74', '66', '31'], offset: 0 },
  { name: 'MS Office (Old)', extension: 'doc', hex: ['D0', 'CF', '11', 'E0', 'A1', 'B1', '1A', 'E1'], offset: 0 },
];

export async function calculateHash(file: File, algorithm: 'SHA-256' | 'SHA-1'): Promise<string> {
  const arrayBuffer = await file.arrayBuffer();
  const hashBuffer = await crypto.subtle.digest(algorithm, arrayBuffer);
  const hashArray = Array.from(new Uint8Array(hashBuffer));
  return hashArray.map(b => b.toString(16).padStart(2, '0')).join('');
}

export async function getFileHead(file: File, length: number = 32): Promise<Uint8Array> {
  const blob = file.slice(0, length);
  const arrayBuffer = await blob.arrayBuffer();
  return new Uint8Array(arrayBuffer);
}

export function detectSignature(bytes: Uint8Array): FileSignature | null {
  for (const sig of FILE_SIGNATURES) {
    const sigBytes = sig.hex.map(h => parseInt(h, 16));
    let match = true;
    for (let i = 0; i < sigBytes.length; i++) {
      if (bytes[sig.offset + i] !== sigBytes[i]) {
        match = false;
        break;
      }
    }
    if (match) return sig;
  }
  return null;
}

export function bytesToHex(bytes: Uint8Array): string[] {
  return Array.from(bytes).map(b => b.toString(16).padStart(2, '0').toUpperCase());
}

export function formatBytes(bytes: number, decimals: number = 2): string {
  if (bytes === 0) return '0 Bytes';
  const k = 1024;
  const dm = decimals < 0 ? 0 : decimals;
  const sizes = ['Bytes', 'KB', 'MB', 'GB', 'TB'];
  const i = Math.floor(Math.log(bytes) / Math.log(k));
  return parseFloat((bytes / Math.pow(k, i)).toFixed(dm)) + ' ' + sizes[i];
}
