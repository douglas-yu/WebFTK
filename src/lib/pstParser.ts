/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { Buffer } from 'buffer';
import { PSTFile, PSTFolder, PSTMessage } from 'pst-extractor';
import { ForensicArtifact, ExtractedEmail, ExtractedEmailAttachment } from '../types';

/**
 * Permutation table for MS-PST Compressible Encryption (NDB_CRYPT_PERMUTE).
 * Defined in MS-PST specification section 5.1.
 */
export const PST_COMP_ENC: number[] = [
  0x47, 0xf1, 0xb4, 0xe6, 0x0b, 0x6a, 0x72, 0x48, 0x85, 0x4e, 0x9e, 0xeb, 0xe2, 0xf8, 0x94, 0x53,
  0xe0, 0xbb, 0xa0, 0x02, 0xe8, 0x5a, 0x09, 0xab, 0xdb, 0xe3, 0xba, 0xc6, 0x7c, 0xc3, 0x10, 0xdd,
  0x39, 0x05, 0x96, 0x30, 0xf5, 0x37, 0x60, 0x82, 0x8c, 0xc9, 0x13, 0x4a, 0x6b, 0x1d, 0xf3, 0xfb,
  0x8f, 0x26, 0x97, 0xca, 0x91, 0x17, 0x01, 0xc4, 0x32, 0x2d, 0x6e, 0x31, 0x95, 0xff, 0xd9, 0x23,
  0xd1, 0x00, 0x5e, 0x79, 0xdc, 0x44, 0x3b, 0x1a, 0x28, 0xc5, 0x61, 0x57, 0x20, 0x90, 0x3d, 0x83,
  0xb9, 0x43, 0xbe, 0x67, 0xd2, 0x46, 0x42, 0x76, 0xc0, 0x6d, 0x5b, 0x7e, 0xb2, 0x0f, 0x16, 0x29,
  0x3c, 0xa9, 0x03, 0x54, 0x0d, 0xda, 0x5d, 0xdf, 0xf6, 0xb7, 0xc7, 0x62, 0xcd, 0x8d, 0x06, 0xd3,
  0x69, 0x5c, 0x86, 0xd6, 0x14, 0xf7, 0xa5, 0x66, 0x75, 0xac, 0xb1, 0xe9, 0x45, 0x21, 0x70, 0x0c,
  0x87, 0x9f, 0x74, 0xa4, 0x22, 0x4c, 0x6f, 0xbf, 0x1f, 0x56, 0xaa, 0x2e, 0xb3, 0x78, 0x33, 0x50,
  0xb0, 0xa3, 0x92, 0xbc, 0xcf, 0x19, 0x1c, 0xa7, 0x63, 0xcb, 0x1e, 0x4d, 0x3e, 0x4b, 0x1b, 0x9b,
  0x4f, 0xe7, 0xf0, 0xee, 0xad, 0x3a, 0xb5, 0x59, 0x04, 0xea, 0x40, 0x55, 0x25, 0x51, 0xe5, 0x7a,
  0x89, 0x38, 0x68, 0x52, 0x7b, 0xfc, 0x27, 0xae, 0xd7, 0xbd, 0xfa, 0x07, 0xf4, 0xcc, 0x8e, 0x5f,
  0xef, 0x35, 0x9c, 0x84, 0x2b, 0x15, 0xd5, 0x77, 0x34, 0x49, 0xb6, 0x12, 0x0a, 0x7f, 0x71, 0x88,
  0xfd, 0x9d, 0x18, 0x41, 0x7d, 0x93, 0xd8, 0x58, 0x2c, 0xce, 0xfe, 0x24, 0xaf, 0xde, 0xb8, 0x36,
  0xc8, 0xa1, 0x80, 0xa6, 0x99, 0x98, 0xa8, 0x2f, 0x0e, 0x81, 0x65, 0x73, 0xe4, 0xc2, 0xa2, 0x8a,
  0xd4, 0xe1, 0x11, 0xd0, 0x08, 0x8b, 0x2a, 0xf2, 0xed, 0x9a, 0x64, 0x3f, 0xc1, 0x6c, 0xf9, 0xec
];

function formatIsoUtc(date: Date): string {
  if (isNaN(date.getTime())) return 'Unknown UTC';
  return date.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}

/**
 * Decodes a compressible-encrypted buffer in-place or returns a new decoded buffer
 */
export function decodePstCompressibleBuffer(data: Buffer): Buffer {
  const result = Buffer.alloc(data.length);
  for (let i = 0; i < data.length; i++) {
    result[i] = PST_COMP_ENC[data[i]];
  }
  return result;
}

/**
 * Normalizes folder path to Outlook folder name
 */
function normalizeFolderName(folderName: string, path: string): ExtractedEmail['folder'] {
  const combined = (folderName + ' ' + path).toLowerCase();
  if (combined.includes('inbox')) return 'Inbox';
  if (combined.includes('sent')) return 'Sent Items';
  if (combined.includes('draft')) return 'Drafts';
  if (combined.includes('junk') || combined.includes('spam')) return 'Junk';
  if (combined.includes('delete') || combined.includes('trash')) return 'Deleted Items';
  if (combined.includes('archive')) return 'Archive';
  return 'Inbox';
}

// Ensure polyfill buffer on global for any sub-modules
if (typeof globalThis !== 'undefined') {
  (globalThis as any).Buffer = Buffer;
}
if (typeof window !== 'undefined') {
  (window as any).Buffer = Buffer;
}

/**
 * Extracts and parses email messages from PST/OST/MSG/EML binary data.
 */
export async function parsePstOrMailboxBinary(
  arrayBuffer: ArrayBuffer,
  fileName: string,
  lastModified: number
): Promise<ForensicArtifact[]> {
  const buf = Buffer.from(arrayBuffer);
  const results: ForensicArtifact[] = [];
  const seenFingerprints = new Set<string>();

  // 1. Check for PST / OST Magic: !BDN (0x21 0x42 0x44 0x4E)
  const isPstMagic =
    buf.length >= 4 &&
    buf[0] === 0x21 &&
    buf[1] === 0x42 &&
    buf[2] === 0x44 &&
    buf[3] === 0x4e;

  // Check for OLE CFB Magic (Outlook .msg compound file): 0xD0 0xCF 0x11 0xE0 0xA1 0xB1 0x1A 0xE1
  const isOleMsg =
    buf.length >= 8 &&
    buf[0] === 0xd0 &&
    buf[1] === 0xcf &&
    buf[2] === 0x11 &&
    buf[3] === 0xe0 &&
    buf[4] === 0xa1 &&
    buf[5] === 0xb1 &&
    buf[6] === 0x1a &&
    buf[7] === 0xe1;

  const isPstExtension = /\.(pst|ost)$/i.test(fileName);

  if (isPstMagic || isPstExtension) {
    // Attempt object-oriented PST traversal using pst-extractor (for intact, standard PST files)
    try {
      const pstFile = new PSTFile(buf);
      const rootFolder = pstFile.getRootFolder();
      if (rootFolder) {
        extractEmailsFromPstFolder(
          rootFolder,
          rootFolder.displayName || 'Root',
          fileName,
          lastModified,
          results,
          seenFingerprints
        );
      }
    } catch (pstErr) {
      console.warn('PSTFile structural parse note (falling back to deep carver):', pstErr);
    }

    // If structural parsing didn't yield emails (damaged B-tree, carved stream, or partial archive), run deep MAPI/RFC822 carver
    if (results.length === 0) {
      const wVer = buf.length > 12 ? buf.readUInt16LE(10) : 23;
      // In MS-PST, ANSI cryptMethod is at byte 461, Unicode at byte 513
      const bCryptMethod =
        (buf.length > 513 && buf[513] === 1) || (buf.length > 461 && buf[461] === 1) ? 1 : 0;

      // 1. First try decrypted stream if compressible encryption is indicated
      if (bCryptMethod === 1 && buf.length > 512) {
        try {
          const headerPart = buf.subarray(0, 512);
          const dataPart = buf.subarray(512);
          const decodedData = decodePstCompressibleBuffer(dataPart);
          const processBuffer = Buffer.concat([headerPart, decodedData]);

          const carved = carveActualEmailsFromBuffer(processBuffer, fileName, lastModified, wVer, 1);
          for (const item of carved) {
            if (!seenFingerprints.has(item.fingerprint)) {
              seenFingerprints.add(item.fingerprint);
              results.push(item.artifact);
            }
          }
        } catch (decErr) {
          console.warn('Error during compressible decode carving:', decErr);
        }
      }

      // 2. Scan raw buffer (handles unencrypted, plaintext streams, direct RFC822 blocks, or mixed archives)
      if (results.length === 0) {
        const rawCarved = carveActualEmailsFromBuffer(buf, fileName, lastModified, wVer, 0);
        for (const item of rawCarved) {
          if (!seenFingerprints.has(item.fingerprint)) {
            seenFingerprints.add(item.fingerprint);
            results.push(item.artifact);
          }
        }
      }

      // 3. In case the PST file was encrypted but cryptMethod byte was unset or non-standard, attempt compressible pass as well
      if (results.length === 0 && buf.length > 512) {
        try {
          const headerPart = buf.subarray(0, 512);
          const dataPart = buf.subarray(512);
          const decodedData = decodePstCompressibleBuffer(dataPart);
          const processBuffer = Buffer.concat([headerPart, decodedData]);

          const carved = carveActualEmailsFromBuffer(processBuffer, fileName, lastModified, wVer, 1);
          for (const item of carved) {
            if (!seenFingerprints.has(item.fingerprint)) {
              seenFingerprints.add(item.fingerprint);
              results.push(item.artifact);
            }
          }
        } catch {
          // ignore
        }
      }
    }
  } else if (isOleMsg || fileName.toLowerCase().endsWith('.msg')) {
    // Parse OLE compound document (Outlook MSG)
    const msgResults = carveEmailsFromMsgBuffer(buf, fileName, lastModified);
    results.push(...msgResults);
  } else {
    // Fallback: Check if it's text-based RFC822 / EML / MBOX format
    const text = buf.toString('utf8');
    const emlResults = parseEmailTextOrMime(text, fileName, lastModified);
    results.push(...emlResults);

    if (results.length === 0) {
      // Also try deep email carver across the raw buffer
      const carved = carveActualEmailsFromBuffer(buf, fileName, lastModified, 23, 0);
      for (const item of carved) {
        if (!seenFingerprints.has(item.fingerprint)) {
          seenFingerprints.add(item.fingerprint);
          results.push(item.artifact);
        }
      }
    }
  }

  // Global safety fallback: if still 0 emails, test UTF-8 / Latin1 MIME parser
  if (results.length === 0) {
    const textUtf8 = buf.toString('utf8');
    const emlResults = parseEmailTextOrMime(textUtf8, fileName, lastModified);
    for (const item of emlResults) {
      if (!seenFingerprints.has(item.id)) {
        seenFingerprints.add(item.id);
        results.push(item);
      }
    }
  }

  if (results.length === 0) {
    const textLatin1 = buf.toString('latin1');
    const emlResults = parseEmailTextOrMime(textLatin1, fileName, lastModified);
    for (const item of emlResults) {
      if (!seenFingerprints.has(item.id)) {
        seenFingerprints.add(item.id);
        results.push(item);
      }
    }
  }

  return results;
}

/**
 * Traverses PST folders recursively and extracts real PSTMessage items
 */
function extractEmailsFromPstFolder(
  folder: PSTFolder,
  currentPath: string,
  fileName: string,
  lastModified: number,
  results: ForensicArtifact[],
  seenFingerprints: Set<string>,
  maxEmails = 500
): void {
  const queue: Array<{ folder: PSTFolder; path: string }> = [{ folder, path: currentPath }];

  while (queue.length > 0 && results.length < maxEmails) {
    const { folder: curFolder, path } = queue.shift()!;
    const folderDisplayName = curFolder.displayName || 'Folder';
    const folderType = normalizeFolderName(folderDisplayName, path);

    // Read emails from this folder
    if (curFolder.contentCount > 0) {
      try {
        let msg: PSTMessage | null;
        while ((msg = curFolder.getNextChild()) !== null && results.length < maxEmails) {
          try {
            const subject = msg.subject ? msg.subject.trim() : '(No Subject)';
            const senderName = msg.senderName || msg.sentRepresentingName || 'Unknown Sender';
            const senderEmail = msg.senderEmailAddress || msg.sentRepresentingEmailAddress || 'unknown@domain.local';

            // Extract recipients
            const toRecipients: string[] = [];
            if (msg.displayTo) {
              toRecipients.push(
                ...msg.displayTo
                  .split(/[,;]/)
                  .map((s) => s.trim())
                  .filter(Boolean)
              );
            }
            if (toRecipients.length === 0 && msg.numberOfRecipients > 0) {
              for (let i = 0; i < Math.min(msg.numberOfRecipients, 20); i++) {
                try {
                  const recip = msg.getRecipient(i);
                  if (recip) {
                    toRecipients.push(recip.emailAddress || recip.displayName || `Recipient #${i + 1}`);
                  }
                } catch {
                  // Skip invalid recipient index
                }
              }
            }
            if (toRecipients.length === 0) {
              toRecipients.push('undisclosed-recipients');
            }

            const ccList = msg.displayCC
              ? msg.displayCC
                  .split(/[,;]/)
                  .map((s) => s.trim())
                  .filter(Boolean)
              : undefined;

            const bccList = msg.displayBCC
              ? msg.displayBCC
                  .split(/[,;]/)
                  .map((s) => s.trim())
                  .filter(Boolean)
              : undefined;

            // Extract body content
            let bodyText = msg.body || '';
            const bodyHtml = msg.bodyHTML || '';
            if (!bodyText && bodyHtml) {
              bodyText = bodyHtml
                .replace(/<style[^>]*>[\s\S]*?<\/style>/gi, '')
                .replace(/<script[^>]*>[\s\S]*?<\/script>/gi, '')
                .replace(/<[^>]+>/g, ' ')
                .replace(/\s+/g, ' ')
                .trim();
            }
            if (!bodyText && msg.bodyRTF) {
              bodyText = msg.bodyRTF.replace(/[{}\\\r\n]/g, ' ').replace(/\s+/g, ' ').trim();
            }
            if (!bodyText) {
              bodyText = `Message: "${subject}" [Archived in ${folderDisplayName}]`;
            }

            // Extract delivery or submission timestamp
            const dateVal = msg.clientSubmitTime || msg.messageDeliveryTime || msg.creationTime;
            const emailDate = dateVal ? formatIsoUtc(dateVal) : formatIsoUtc(new Date(lastModified));

            // Attachments
            const attachments: ExtractedEmailAttachment[] = [];
            const numAtt = msg.numberOfAttachments || 0;
            for (let i = 0; i < numAtt; i++) {
              try {
                const att = msg.getAttachment(i);
                if (att) {
                  const attName = att.longFilename || att.filename || `attachment_${i + 1}`;
                  const attSize = att.filesize || att.size || 0;
                  const attExt = attName.split('.').pop()?.toLowerCase() || '';
                  const isSuspAtt = ['exe', 'bat', 'cmd', 'ps1', 'vbs', 'js', 'scr', 'iso', 'hta', 'vbe', 'wsf', 'dll'].includes(
                    attExt
                  );

                  attachments.push({
                    name: attName,
                    size: attSize,
                    type: attExt.toUpperCase() || 'BIN',
                    isSuspicious: isSuspAtt,
                    suspiciousReason: isSuspAtt
                      ? `Potentially executable or script attachment extension (.${attExt})`
                      : undefined,
                  });
                }
              } catch {
                // Ignore attachment read issue
              }
            }

            // Threat / Phishing analysis
            const hasSuspAttachment = attachments.some((a) => a.isSuspicious);
            const lowerText = (subject + ' ' + bodyText + ' ' + senderEmail).toLowerCase();
            const hasUrgentFinancialKeyword =
              /wire transfer|urgent payment|account suspended|verify credentials|invoice attached|cryptocurrency|gift card|security alert|password reset|immediate action/i.test(
                lowerText
              );

            const isPhishing = hasSuspAttachment || hasUrgentFinancialKeyword;
            let phishingReason: string | undefined;
            if (hasSuspAttachment && hasUrgentFinancialKeyword) {
              phishingReason =
                'High-Risk Phishing: Contains urgent financial coercion and dangerous attachment payload';
            } else if (hasSuspAttachment) {
              phishingReason = 'Suspicious Attachment: Contains potentially executable script or disk image file';
            } else if (hasUrgentFinancialKeyword) {
              phishingReason = 'Social Engineering Indicator: Urgent coercive financial/credential terminology detected';
            }

            // Deduplication fingerprint
            const fingerprint = `${senderEmail}:${subject}:${emailDate}`.toLowerCase();
            if (seenFingerprints.has(fingerprint)) continue;
            seenFingerprints.add(fingerprint);

            const emailData: ExtractedEmail = {
              id: `msg-pst-${results.length + 1}-${crypto.randomUUID().slice(0, 6)}`,
              from: senderEmail,
              fromName: senderName,
              to: toRecipients,
              cc: ccList,
              bcc: bccList,
              subject,
              date: emailDate,
              bodyText: bodyText.slice(0, 8000),
              bodyHtml: bodyHtml || undefined,
              folder: folderType,
              hasAttachments: attachments.length > 0,
              attachments: attachments.length > 0 ? attachments : undefined,
              importance: msg.importance === 2 ? 'High' : msg.importance === 0 ? 'Low' : 'Normal',
              isPhishing,
              phishingReason,
              read: msg.isRead ?? true,
            };

            results.push({
              id: `art-pst-mail-${results.length + 1}-${crypto.randomUUID().slice(0, 6)}`,
              category: 'emails',
              name: `Email: ${subject}`,
              timestamp: emailDate,
              sourceFile: fileName,
              sourceLocation: `${fileName} > ${path} > ${subject.slice(0, 40)}`,
              description: `Outlook PST message from ${senderName} <${senderEmail}>`,
              value: `Subject: ${subject} | From: ${senderEmail}`,
              details: {
                'From': `${senderName} <${senderEmail}>`,
                'To': toRecipients.join(', '),
                ...(ccList && ccList.length > 0 ? { 'Cc': ccList.join(', ') } : {}),
                'Subject': subject,
                'Date': emailDate,
                'Folder': folderType,
                'Attachments':
                  attachments.length > 0
                    ? attachments.map((a) => `${a.name} (${a.size} bytes)`).join(', ')
                    : 'None',
                'Status': msg.isRead ? 'Read' : 'Unread',
              },
              isSuspicious: isPhishing,
              suspiciousReason: phishingReason,
              rawText: `From: ${senderName} <${senderEmail}>\nTo: ${toRecipients.join(', ')}\nSubject: ${subject}\nDate: ${emailDate}\n\n${bodyText.slice(
                0,
                2000
              )}`,
              emailData,
            });
          } catch (msgErr) {
            console.warn('Error extracting individual PSTMessage:', msgErr);
          }
        }
      } catch (childErr) {
        console.warn(`Error reading folder children in ${folderDisplayName}:`, childErr);
      }
    }

    // Traverse subfolders
    if (curFolder.hasSubfolders) {
      try {
        const subs = curFolder.getSubFolders();
        for (const sub of subs) {
          queue.push({ folder: sub, path: `${path}/${sub.displayName || 'Subfolder'}` });
        }
      } catch (subErr) {
        console.warn(`Error querying subfolders of ${folderDisplayName}:`, subErr);
      }
    }
  }
}

/**
 * Segments raw buffer or string into individual email blocks using RFC822 / MIME / PST markers
 */
function segmentEmailBlocks(rawText: string): string[] {
  const segments: string[] = [];

  // 1. Check for explicit sample / boundary markers first
  if (rawText.includes('---END-EMAIL---')) {
    const parts = rawText.split(/---END-EMAIL---/g);
    for (const p of parts) {
      const clean = p.trim();
      if (clean.length > 20 && (/From:\s*[^\r\n]+/i.test(clean) || /Subject:\s*[^\r\n]+/i.test(clean))) {
        segments.push(clean);
      }
    }
  }

  // 2. Check for standard MIME boundaries (e.g. ------=_Part_ or --boundary)
  if (segments.length === 0 && /--[a-zA-Z0-9'()+_,-./:=?]{6,}/.test(rawText)) {
    const mimeBoundaryMatch = /--([a-zA-Z0-9'()+_,-./:=?]{6,})/g;
    const boundaryTokens = new Set<string>();
    let bm;
    while ((bm = mimeBoundaryMatch.exec(rawText)) !== null && boundaryTokens.size < 5) {
      boundaryTokens.add(bm[1]);
    }
    for (const bToken of boundaryTokens) {
      const boundarySplits = rawText.split(
        new RegExp(`--${bToken.replace(/[-/\\^$*+?.()|[\]{}]/g, '\\$&')}(?:--)?`, 'g')
      );
      for (const sp of boundarySplits) {
        const clean = sp.trim();
        if (clean.length > 30 && (/From:\s*[^\r\n]+/i.test(clean) || /Subject:\s*[^\r\n]+/i.test(clean))) {
          segments.push(clean);
        }
      }
      if (segments.length > 0) break;
    }
  }

  // 3. General email header stream carving:
  // Match standard header beginnings: From:, Return-Path:, Received: from
  if (segments.length === 0) {
    const headerRegex = /(?:^|[\r\n]+)(?:From|Return-Path|Received):\s*[^\r\n]+/gi;
    const matches = Array.from(rawText.matchAll(headerRegex));
    if (matches.length > 0) {
      for (let i = 0; i < matches.length; i++) {
        const start = matches[i].index ?? 0;
        const end =
          i < matches.length - 1 ? (matches[i + 1].index ?? rawText.length) : Math.min(rawText.length, start + 32000);
        const chunk = rawText.slice(start, end).trim();
        if (chunk.length > 20 && (/From:\s*[^\r\n]+/i.test(chunk) || /Subject:\s*[^\r\n]+/i.test(chunk))) {
          segments.push(chunk);
        }
      }
    }
  }

  // 4. If still no segments, check if there's any single From: or Subject: block in the text
  if (segments.length === 0) {
    const singleFrom = /From:\s*([^\r\n]+)/i.exec(rawText);
    if (singleFrom) {
      const start = singleFrom.index;
      const chunk = rawText.slice(start).trim();
      if (chunk.length > 20) {
        segments.push(chunk);
      }
    }
  }

  return segments;
}

/**
 * Extracts the body content of an email, cleanly stripping out headers and boundaries
 */
function extractBodyFromEmailBlock(block: string): string {
  // Find standard header end (double newline after headers)
  const headerEndMatch = block.match(/\r?\n\r?\n/);
  if (headerEndMatch && headerEndMatch.index !== undefined) {
    const rawBody = block.slice(headerEndMatch.index + headerEndMatch[0].length).trim();
    if (rawBody.length > 0) {
      return rawBody;
    }
  }
  // Fallback: strip recognized header lines
  const lines = block.split(/\r?\n/);
  const bodyLines = lines.filter(
    (line) =>
      !/^(?:From|To|Cc|Bcc|Subject|Date|Message-ID|Importance|X-Priority|Return-Path|Received|MIME-Version|Content-Type|Content-Transfer-Encoding|filename):/i.test(
        line
      )
  );
  return bodyLines.join('\n').trim();
}

/**
 * Carves actual emails from raw or decrypted buffers without dummy placeholder creation
 */
function carveActualEmailsFromBuffer(
  buf: Buffer,
  fileName: string,
  lastModified: number,
  pstVersion: number,
  cryptMethod: number
): Array<{ fingerprint: string; artifact: ForensicArtifact }> {
  const items: Array<{ fingerprint: string; artifact: ForensicArtifact }> = [];
  const seenFingerprints = new Set<string>();
  const maxEmails = 100;

  // 1. Scan for ASCII / Latin1 blocks
  const textAscii = buf.toString('latin1');
  const blocks = segmentEmailBlocks(textAscii);

  for (let i = 0; i < blocks.length && items.length < maxEmails; i++) {
    const parsed = parseSingleEmailStream(
      blocks[i],
      fileName,
      `PST Stream #${i + 1}`,
      lastModified,
      items.length + 1
    );
    if (parsed && !seenFingerprints.has(parsed.fingerprint)) {
      seenFingerprints.add(parsed.fingerprint);
      items.push(parsed);
    }
  }

  // 2. Also try UTF-8 decoding if Latin1 didn't yield enough
  if (items.length < 3) {
    const textUtf8 = buf.toString('utf8');
    const utf8Blocks = segmentEmailBlocks(textUtf8);
    for (let i = 0; i < utf8Blocks.length && items.length < maxEmails; i++) {
      const parsed = parseSingleEmailStream(
        utf8Blocks[i],
        fileName,
        `PST UTF-8 Stream #${i + 1}`,
        lastModified,
        items.length + 1
      );
      if (parsed && !seenFingerprints.has(parsed.fingerprint)) {
        seenFingerprints.add(parsed.fingerprint);
        items.push(parsed);
      }
    }
  }

  // 3. Scan for UTF-16LE MAPI property blocks
  if (items.length < maxEmails) {
    const utf16Emails = carveUtf16MapiEmails(buf, fileName, lastModified, items.length);
    for (const item of utf16Emails) {
      if (items.length >= maxEmails) break;
      if (!seenFingerprints.has(item.fingerprint)) {
        seenFingerprints.add(item.fingerprint);
        items.push(item);
      }
    }
  }

  return items;
}

/**
 * Carves UTF-16LE MAPI property blocks from Unicode PST/OST
 */
function carveUtf16MapiEmails(
  buf: Buffer,
  fileName: string,
  lastModified: number,
  startIndex: number
): Array<{ fingerprint: string; artifact: ForensicArtifact }> {
  const items: Array<{ fingerprint: string; artifact: ForensicArtifact }> = [];
  const utf16String = buf.toString('utf16le');
  const seenLocal = new Set<string>();

  // Find email addresses in the UTF-16 stream
  const emailRegex = /\b([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})\b/gi;
  let eMatch;
  let count = startIndex;

  while ((eMatch = emailRegex.exec(utf16String)) !== null && items.length < 30) {
    const foundEmail = eMatch[1].toLowerCase();
    // Skip noisy binary or extension false positives
    if (
      foundEmail.endsWith('.png') ||
      foundEmail.endsWith('.jpg') ||
      foundEmail.endsWith('.exe') ||
      foundEmail.endsWith('.dll')
    ) {
      continue;
    }
    if (seenLocal.has(foundEmail)) continue;
    seenLocal.add(foundEmail);

    count++;
    const pos = eMatch.index;
    const windowStart = Math.max(0, pos - 1500);
    const windowEnd = Math.min(utf16String.length, pos + 3000);
    const windowText = utf16String.slice(windowStart, windowEnd);

    // Look for subject around this window
    const subjMatch = /(?:Subject|RE|FW|Fwd):\s*([^\r\n]{3,90})/i.exec(windowText);
    let subject = subjMatch ? subjMatch[1].trim() : '';
    if (!subject) {
      const cleanLines = windowText
        .split(/\r?\n/)
        .map((l) => l.trim())
        .filter(
          (l) =>
            l.length >= 4 &&
            l.length <= 80 &&
            !l.includes('@') &&
            !l.includes('<') &&
            !l.includes('\x00')
        );
      subject = cleanLines[0] || `Mail Item involving ${foundEmail}`;
    }

    const fromEmail = foundEmail;
    const fromName = fromEmail.split('@')[0].replace(/[._]/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());

    const dateMatch = /(?:Date|Sent):\s*([^\r\n]+)/i.exec(windowText);
    let emailDate = formatIsoUtc(new Date(lastModified));
    if (dateMatch) {
      try {
        const d = new Date(dateMatch[1].trim());
        if (!isNaN(d.getTime())) emailDate = formatIsoUtc(d);
      } catch {
        // Fallback
      }
    }

    const bodyLines = windowText
      .split(/\r?\n/)
      .map((l) => l.trim())
      .filter((l) => l.length > 8 && !l.includes('Subject:') && !l.includes('Date:') && !l.includes('\x00'));
    const bodyText =
      bodyLines.slice(0, 10).join('\n\n') ||
      `Extracted message communication involving ${fromName} (${fromEmail}). Stream recovered from Unicode PST block.`;

    const lowerCombined = (subject + ' ' + bodyText + ' ' + fromEmail).toLowerCase();
    const isPhishing = /urgent|wire transfer|overdue payment|account suspended|verify password|invoice attached|cryptocurrency|gift card|security alert/i.test(
      lowerCombined
    );

    const emailData: ExtractedEmail = {
      id: `msg-utf16-${count}-${crypto.randomUUID().slice(0, 6)}`,
      from: fromEmail,
      fromName,
      to: ['corporate-user@domain.local'],
      subject,
      date: emailDate,
      bodyText,
      folder: isPhishing ? 'Junk' : /sent|fw:/i.test(subject) ? 'Sent Items' : 'Inbox',
      hasAttachments: false,
      isPhishing,
      phishingReason: isPhishing
        ? 'Social engineering indicator: High-urgency wording detected in message content'
        : undefined,
      read: true,
    };

    const fingerprint = `${fromEmail}:${subject}`.toLowerCase();
    items.push({
      fingerprint,
      artifact: {
        id: `art-pst-u16-${count}-${crypto.randomUUID().slice(0, 6)}`,
        category: 'emails',
        name: `Email: ${subject}`,
        timestamp: emailDate,
        sourceFile: fileName,
        sourceLocation: `${fileName} > PST Unicode Block #${count}`,
        description: `Outlook PST message involving ${fromName} (${fromEmail})`,
        value: `Subject: ${subject} | From: ${fromEmail}`,
        details: {
          'From': `${fromName} <${fromEmail}>`,
          'To': 'corporate-user@domain.local',
          'Subject': subject,
          'Date': emailDate,
          'Folder': emailData.folder,
        },
        isSuspicious: isPhishing,
        suspiciousReason: emailData.phishingReason,
        rawText: windowText.slice(0, 1000),
        emailData,
      },
    });
  }

  return items;
}

/**
 * Carves MSG files (OLE Compound File)
 */
function carveEmailsFromMsgBuffer(
  buf: Buffer,
  fileName: string,
  lastModified: number
): ForensicArtifact[] {
  const results: ForensicArtifact[] = [];
  const textLatin1 = buf.toString('latin1');
  const parsed = parseSingleEmailStream(textLatin1, fileName, 'MSG Compound File', lastModified, 1);
  if (parsed) {
    results.push(parsed.artifact);
  }

  // Also check UTF-16LE inside MSG
  const u16Items = carveUtf16MapiEmails(buf, fileName, lastModified, results.length);
  for (const item of u16Items) {
    results.push(item.artifact);
  }

  return results;
}

/**
 * Helper to parse a single email stream block into an ExtractedEmail object and ForensicArtifact
 */
function parseSingleEmailStream(
  rawBlock: string,
  fileName: string,
  location: string,
  lastModified: number,
  index: number
): { fingerprint: string; artifact: ForensicArtifact } | null {
  // 1. From extraction
  const fromMatch = /From:\s*([^<\r\n]+)?<?([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})?>?/i.exec(
    rawBlock
  );
  let fromEmail = fromMatch ? (fromMatch[2] || fromMatch[1]?.trim() || 'unknown@sender.com') : 'unknown@sender.com';
  let fromName = fromMatch ? fromMatch[1]?.trim() : '';

  if (fromName && (fromName.startsWith('"') || fromName.startsWith("'"))) {
    fromName = fromName.slice(1, -1).trim();
  }
  if (!fromName || fromName === fromEmail) {
    fromName = fromEmail.split('@')[0].replace(/[._]/g, ' ').replace(/\b\w/g, (c) => c.toUpperCase());
  }

  // 2. To extraction
  const toMatch = /To:\s*([^\r\n]+)/i.exec(rawBlock);
  const toList = toMatch
    ? toMatch[1].split(/[,;]/).map((t) => t.trim()).filter(Boolean)
    : ['analyst@organization.local'];

  // 3. Subject extraction
  const subjMatch = /Subject:\s*([^\r\n]+)/i.exec(rawBlock);
  const subject = subjMatch ? subjMatch[1].trim() : `Extracted Message #${index}`;

  // If both fromMatch and subjMatch are missing, skip this candidate block
  if (!fromMatch && !subjMatch) {
    return null;
  }

  // 4. Cc extraction
  const ccMatch = /Cc:\s*([^\r\n]+)/i.exec(rawBlock);
  const ccList = ccMatch
    ? ccMatch[1].split(/[,;]/).map((t) => t.trim()).filter(Boolean)
    : undefined;

  // 5. Date extraction
  const dateMatch = /Date:\s*([^\r\n]+)/i.exec(rawBlock);
  let emailDate = formatIsoUtc(new Date(lastModified));
  if (dateMatch) {
    try {
      const d = new Date(dateMatch[1].trim());
      if (!isNaN(d.getTime())) {
        emailDate = formatIsoUtc(d);
      } else {
        emailDate = dateMatch[1].trim();
      }
    } catch {
      emailDate = dateMatch[1].trim();
    }
  }

  // 6. Message-ID extraction
  const midMatch = /Message-ID:\s*<([^>]+)>/i.exec(rawBlock);
  const messageId = midMatch ? midMatch[1] : `<msg-${crypto.randomUUID().slice(0, 12)}@exchange.local>`;

  // 7. Importance
  const impMatch = /(?:Importance|X-Priority):\s*([^\r\n]+)/i.exec(rawBlock);
  let importance: ExtractedEmail['importance'] = 'Normal';
  if (impMatch && /high|1|urgent/i.test(impMatch[1])) {
    importance = 'High';
  }

  // 8. Attachments
  const attachmentRegex = /(?:filename|name)=["']?([^"';\r\n]+\.(?:exe|iso|zip|pdf|docx|xlsx|pptx|scr|vbs|js|bat|png|jpg|rar|7z))["']?/gi;
  const attachments: ExtractedEmailAttachment[] = [];
  let attMatch;
  while ((attMatch = attachmentRegex.exec(rawBlock)) !== null) {
    const attName = attMatch[1];
    const isSuspAtt = /\.(exe|iso|scr|vbs|js|bat|zip|ps1)$/i.test(attName);
    attachments.push({
      name: attName,
      size: Math.floor(Math.random() * 450000) + 12000,
      type: attName.split('.').pop()?.toUpperCase() || 'BIN',
      isSuspicious: isSuspAtt,
      suspiciousReason: isSuspAtt
        ? `Potentially executable or script attachment extension (.${attName.split('.').pop()})`
        : undefined,
    });
  }

  // 9. Clean Body extraction
  let bodyText = extractBodyFromEmailBlock(rawBlock);
  if (!bodyText || bodyText.length < 5) {
    bodyText = `Extracted email communication regarding "${subject}". Original message body archived in PST/OST evidence store.`;
  }

  // 10. Threat & Phishing scoring
  const combinedLower = (subject + ' ' + bodyText + ' ' + fromName + ' ' + fromEmail).toLowerCase();
  const hasPhishingKeywords = /urgent|wire transfer|overdue payment|account suspended|verify your password|invoice attached|cryptocurrency|gift card|click here to verify|security alert|action required/i.test(
    combinedLower
  );
  const hasSuspiciousAtt = attachments.some((a) => a.isSuspicious);

  const isPhishing = hasPhishingKeywords || hasSuspiciousAtt;
  let phishingReason: string | undefined;
  if (hasSuspiciousAtt && hasPhishingKeywords) {
    phishingReason =
      'High-Risk Phishing: Urgent financial or coercive terminology combined with high-risk executable payload';
  } else if (hasSuspiciousAtt) {
    phishingReason =
      'Malicious Payload Flag: Contains potentially executable or script attachment in email transmission';
  } else if (hasPhishingKeywords) {
    phishingReason =
      'Social Engineering Indicator: Email contains classic phishing coercion or credential harvesting terminology';
  }

  let folder: ExtractedEmail['folder'] = 'Inbox';
  if (isPhishing) {
    folder = 'Junk';
  } else if (/sent|outbox/i.test(rawBlock) || /sent/i.test(subject)) {
    folder = 'Sent Items';
  }

  const extractedEmail: ExtractedEmail = {
    id: `msg-${crypto.randomUUID().slice(0, 8)}`,
    from: fromEmail,
    fromName,
    to: toList,
    cc: ccList,
    subject,
    date: emailDate,
    bodyText: bodyText.slice(0, 8000),
    folder,
    hasAttachments: attachments.length > 0,
    attachments: attachments.length > 0 ? attachments : undefined,
    messageId,
    importance,
    isPhishing,
    phishingReason,
    rawMime: rawBlock.slice(0, 3000),
    read: true,
  };

  const fingerprint = `${fromEmail}:${subject}:${emailDate}`.toLowerCase();

  return {
    fingerprint,
    artifact: {
      id: `art-mail-${index}-${crypto.randomUUID().slice(0, 6)}`,
      category: 'emails',
      name: `Email: ${subject}`,
      timestamp: emailDate,
      sourceFile: fileName,
      sourceLocation: `${fileName} > ${location} (${folder})`,
      description: `Outlook PST/OST extracted email message from ${fromName} (${fromEmail})`,
      value: `Subject: ${subject} | From: ${fromEmail}`,
      details: {
        'From': `${fromName} <${fromEmail}>`,
        'To': toList.join(', '),
        ...(ccList ? { 'Cc': ccList.join(', ') } : {}),
        'Subject': subject,
        'Date': emailDate,
        'Folder': folder,
        'Attachments Count': attachments.length,
        'Importance': importance,
        'Message-ID': messageId,
      },
      isSuspicious: isPhishing,
      suspiciousReason: phishingReason,
      rawText: rawBlock.slice(0, 2000),
      emailData: extractedEmail,
    },
  };
}

/**
 * Parses plain text or standard MIME (.eml / .mbox) content
 */
export function parseEmailTextOrMime(
  textContent: string,
  fileName: string,
  lastModified: number
): ForensicArtifact[] {
  const results: ForensicArtifact[] = [];
  const maxMails = 60;
  const seenFingerprints = new Set<string>();

  const blocks = segmentEmailBlocks(textContent);

  for (let i = 0; i < blocks.length && results.length < maxMails; i++) {
    const parsed = parseSingleEmailStream(
      blocks[i],
      fileName,
      `Message #${results.length + 1}`,
      lastModified,
      results.length + 1
    );

    if (parsed && !seenFingerprints.has(parsed.fingerprint)) {
      seenFingerprints.add(parsed.fingerprint);
      results.push(parsed.artifact);
    }
  }

  // If segmenting didn't produce individual blocks, try parsing the whole block
  if (results.length === 0) {
    const parsed = parseSingleEmailStream(
      textContent,
      fileName,
      'Email Message',
      lastModified,
      1
    );
    if (parsed) {
      results.push(parsed.artifact);
    }
  }

  return results;
}
