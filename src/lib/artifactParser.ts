/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { Buffer } from 'buffer';
import { 
  ForensicArtifact, 
  ArtifactAnalysisOptions, 
  ArtifactCategory,
  ExtractedEmail,
  WindowsEventData,
  RecentFileData
} from '../types';
import { parseEvtxBinary, parseEvtxTextOrXml } from './evtxParser';
import { parsePstOrMailboxBinary, parseEmailTextOrMime } from './pstParser';
import { isRegistryHive, parseRegistryHive } from './registryHiveParser';

export interface CategoryMeta {
  id: ArtifactCategory;
  label: string;
  shortLabel: string;
  description: string;
  badgeColor: string;
}

export const ARTIFACT_CATEGORIES: CategoryMeta[] = [
  {
    id: 'all',
    label: 'All Artifacts',
    shortLabel: 'All',
    description: 'Consolidated forensic findings across all categories',
    badgeColor: 'bg-zinc-800 text-zinc-300'
  },
  {
    id: 'windows_events',
    label: 'Windows Event Logs',
    shortLabel: 'Event Logs',
    description: 'Security, System, PowerShell, and Application audit logs (EVTX/XML)',
    badgeColor: 'bg-emerald-950/70 text-emerald-400 border border-emerald-800/50'
  },
  {
    id: 'recent_files',
    label: 'Recent Files & Shellbags',
    shortLabel: 'Recent Files',
    description: 'Recently accessed documents, LNK shortcuts, JumpLists, and Shellbags',
    badgeColor: 'bg-teal-950/70 text-teal-400 border border-teal-800/50'
  },
  {
    id: 'emails',
    label: 'Outlook & PST Mailbox',
    shortLabel: 'Emails',
    description: 'Extracted Outlook PST/OST messages, EML, and MSG emails with attachments',
    badgeColor: 'bg-blue-950/70 text-blue-400 border border-blue-800/50'
  },
  {
    id: 'browser_history',
    label: 'Browser History',
    shortLabel: 'Browser',
    description: 'Visited URLs, typed addresses, web searches, and download activities',
    badgeColor: 'bg-sky-950/70 text-sky-400 border border-sky-800/50'
  },
  {
    id: 'user_activity',
    label: 'Recent User Activities',
    shortLabel: 'User Activity',
    description: 'Recent documents, JumpLists, UserAssist, LNK files, and Prefetch execution',
    badgeColor: 'bg-purple-950/70 text-purple-400 border border-purple-800/50'
  },
  {
    id: 'system_info',
    label: 'System & OS Info',
    shortLabel: 'System Info',
    description: 'Computer name, OS build, timezone, network configuration, and environment',
    badgeColor: 'bg-indigo-950/70 text-indigo-400 border border-indigo-800/50'
  },
  {
    id: 'usb_connect',
    label: 'USB Connection History',
    shortLabel: 'USB Connect',
    description: 'Attached removable storage devices, serial numbers, VID/PID, and drive mappings',
    badgeColor: 'bg-amber-950/70 text-amber-400 border border-amber-800/50'
  },
  {
    id: 'run_keys',
    label: 'Run & Auto-Start Keys',
    shortLabel: 'Run Keys',
    description: 'Persistence mechanisms, Run/RunOnce registry values, startup items, and scheduled tasks',
    badgeColor: 'bg-rose-950/70 text-rose-400 border border-rose-800/50'
  },
  {
    id: 'user_accounts',
    label: 'User Accounts & Security',
    shortLabel: 'User Accounts',
    description: 'SAM user records, Relative Identifiers (RIDs), account privileges, and logon profiles',
    badgeColor: 'bg-violet-950/70 text-violet-400 border border-violet-800/50'
  }
];

// Helper to extract text from a file safely
async function readFileAsText(file: File, maxBytes = 4 * 1024 * 1024): Promise<string> {
  const slice = file.slice(0, maxBytes);
  return await slice.text();
}

// Helper to extract binary buffer safely
async function readFileAsArrayBuffer(file: File, maxBytes = 64 * 1024 * 1024): Promise<ArrayBuffer> {
  const slice = file.slice(0, maxBytes);
  return await slice.arrayBuffer();
}

// Helper to extract UTF-16LE and ASCII paths from binary buffers (for LNK, JumpLists, Shellbags)
function extractPathsFromBinary(buf: Buffer, maxPaths = 25): Array<{ path: string; offset: number }> {
  const paths: Array<{ path: string; offset: number }> = [];
  const seen = new Set<string>();

  // 1. Scan UTF-16LE string representations
  const utf16 = buf.toString('utf16le');
  const pathRegex = /([a-zA-Z]:\\[a-zA-Z0-9_\-.\s\\]+\.(exe|docx|xlsx|pptx|pdf|zip|rar|ps1|bat|vbs|txt|lnk))/gi;
  let match;
  while ((match = pathRegex.exec(utf16)) !== null && paths.length < maxPaths) {
    const p = match[1].trim();
    if (p.length > 8 && !seen.has(p.toLowerCase())) {
      seen.add(p.toLowerCase());
      paths.push({ path: p, offset: match.index * 2 });
    }
  }

  // 2. Scan Latin-1 representation for standard ASCII paths
  const latin1 = buf.toString('latin1');
  let matchAscii;
  while ((matchAscii = pathRegex.exec(latin1)) !== null && paths.length < maxPaths) {
    const p = matchAscii[1].trim();
    if (p.length > 8 && !seen.has(p.toLowerCase())) {
      seen.add(p.toLowerCase());
      paths.push({ path: p, offset: matchAscii.index });
    }
  }

  return paths;
}

// Local forensic analyzer that processes uploaded files against selected analysis categories
export async function analyzeArtifactFiles(
  files: File[],
  options: ArtifactAnalysisOptions
): Promise<ForensicArtifact[]> {
  const results: ForensicArtifact[] = [];

  for (const file of files) {
    const fileNameLower = file.name.toLowerCase();

    // Probe first 16 bytes for magic signatures
    const headerSlice = await file.slice(0, 16).arrayBuffer();
    const headerBuf = Buffer.from(headerSlice);
    const isEvtxMagic =
      headerBuf.length >= 8 && headerBuf.subarray(0, 8).toString('ascii') === 'ElfFile\0';
    const isPstMagic =
      headerBuf.length >= 4 &&
      headerBuf[0] === 0x21 &&
      headerBuf[1] === 0x42 &&
      headerBuf[2] === 0x44 &&
      headerBuf[3] === 0x4e;
    const isOleMsgMagic =
      headerBuf.length >= 8 &&
      headerBuf[0] === 0xd0 &&
      headerBuf[1] === 0xcf &&
      headerBuf[2] === 0x11 &&
      headerBuf[3] === 0xe0;

    const isEvtxFile = isEvtxMagic || fileNameLower.endsWith('.evtx');
    const isMailboxFile =
      isPstMagic ||
      isOleMsgMagic ||
      /\.(pst|ost|msg|eml|mbox)$/i.test(fileNameLower);
    const isRegFile = isRegistryHive(headerBuf, file.name);

    // ----------------------------------------------------
    // Windows Registry Hives (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT)
    // ----------------------------------------------------
    if (isRegFile) {
      try {
        const regSlice = await readFileAsArrayBuffer(file, 128 * 1024 * 1024);
        const regBuf = Buffer.from(regSlice);
        const regArtifacts = parseRegistryHive(regBuf, file.name, file.lastModified);
        for (const art of regArtifacts) {
          if (art.category === 'system_info' && !options.systemInfo) continue;
          if (art.category === 'usb_connect' && !options.usbHistory) continue;
          if (art.category === 'run_keys' && !options.registryHives) continue;
          if (art.category === 'user_accounts' && !options.userAccounts) continue;
          if (art.category === 'recent_files' && !options.recentFiles) continue;
          if (art.category === 'user_activity' && !options.userActivities) continue;
          results.push(art);
        }
      } catch (err) {
        console.warn(`Error parsing registry hive ${file.name}:`, err);
      }
    }

    // ----------------------------------------------------
    // 1. Windows Event Logs Analysis (.evtx, .xml, text logs)
    // ----------------------------------------------------
    if (options.windowsEvents) {
      if (isEvtxFile) {
        try {
          const evtxBuffer = await readFileAsArrayBuffer(file, 40 * 1024 * 1024);
          const evtxArtifacts = await parseEvtxBinary(evtxBuffer, file.name, file.lastModified);
          results.push(...evtxArtifacts);
        } catch (err) {
          console.warn(`Error parsing binary EVTX file ${file.name}:`, err);
        }
      }

      // If not an EVTX or if 0 records were found, test for XML or formatted text exports
      if (!isEvtxFile || results.filter((r) => r.category === 'windows_events').length === 0) {
        const textContent = await readFileAsText(file);
        const textEvtArtifacts = parseEvtxTextOrXml(textContent, file.name, file.lastModified);
        results.push(...textEvtArtifacts);
      }
    }

    // ----------------------------------------------------
    // 2. Recent Files, LNK Shortcuts, Shellbags, JumpLists
    // ----------------------------------------------------
    if (options.recentFiles) {
      const isLnk = fileNameLower.endsWith('.lnk');
      const isJumpList = fileNameLower.includes('destinations-ms');
      const isShellbag = /shell|bag/i.test(fileNameLower);

      let sourceArtifact: RecentFileData['sourceArtifact'] = 'RecentDocs';
      if (isLnk) sourceArtifact = 'LNK Shortcut';
      else if (isJumpList) sourceArtifact = 'JumpList';
      else if (isShellbag) sourceArtifact = 'Shellbag';
      else if (/word|excel|powerpnt/i.test(fileNameLower)) sourceArtifact = 'Office Recent';

      const seenPaths = new Set<string>();

      // Extract paths from binary (UTF-16LE and ASCII)
      const rawSlice = await readFileAsArrayBuffer(file, 4 * 1024 * 1024);
      const binaryPaths = extractPathsFromBinary(Buffer.from(rawSlice), 30);

      for (const { path: fullPath, offset } of binaryPaths) {
        if (!seenPaths.has(fullPath.toLowerCase())) {
          seenPaths.add(fullPath.toLowerCase());
          const fileName = fullPath.split('\\').pop() || fullPath;
          const ext = fileName.includes('.') ? fileName.split('.').pop()!.toLowerCase() : 'EXE';

          const isSusp =
            /(temp|appdata|public)\\.*\.exe$/i.test(fullPath) ||
            /\.(pdf|doc|docx|xls|xlsx)\.(exe|vbs|ps1|bat)$/i.test(fullPath) ||
            /mimikatz|payload|backdoor|stager|nc\.exe|cmd\.exe/i.test(fullPath);

          const recentFileData: RecentFileData = {
            fileName,
            filePath: fullPath,
            targetPath: fullPath,
            extension: ext,
            fileExtension: ext,
            accessTime: new Date(file.lastModified).toISOString().replace('T', ' ').slice(0, 19) + ' UTC',
            sourceArtifact,
            isSuspicious: isSusp,
          };

          results.push({
            id: `art-rcnt-${crypto.randomUUID().slice(0, 8)}`,
            category: 'recent_files',
            name: `${sourceArtifact}: ${fileName}`,
            timestamp: recentFileData.accessTime,
            sourceFile: file.name,
            sourceLocation: `${file.name} > ${sourceArtifact} Record (Offset: 0x${offset.toString(16).toUpperCase()})`,
            description: `Recently accessed file traced via ${sourceArtifact}`,
            value: fullPath,
            details: {
              'File Name': fileName,
              'Full Target Path': fullPath,
              'Extension': ext.toUpperCase(),
              'Carving Source': sourceArtifact,
              'Evidence File': file.name,
            },
            isSuspicious: isSusp,
            suspiciousReason: isSusp
              ? 'Target path executes from temporary/unprivileged directories or uses masquerading double extension'
              : undefined,
            rawText: `Offset 0x${offset.toString(16).toUpperCase()}: ${fullPath}`,
            recentFileData,
          });
        }
      }

      // Shellbag & MRU folder exploration history (e.g. Explorer visited folders)
      const textContent = await readFileAsText(file);
      const folderPathRegex = /([a-zA-Z]:\\(?:Users|Windows|Program Files|Downloads|Desktop|Documents|AppData)[a-zA-Z0-9_\-\\ ]*)/gi;
      let folderMatch;
      let folderCount = 0;
      while ((folderMatch = folderPathRegex.exec(textContent)) !== null && folderCount < 15) {
        const folder = folderMatch[1].trim();
        if (folder.length > 10 && !seenPaths.has(folder.toLowerCase())) {
          seenPaths.add(folder.toLowerCase());
          folderCount++;
          const folderName = folder.split('\\').pop() || folder;

          const recentFileData: RecentFileData = {
            fileName: folderName,
            filePath: folder,
            extension: 'FOLDER',
            fileExtension: 'FOLDER',
            accessTime: new Date(file.lastModified).toISOString().replace('T', ' ').slice(0, 19) + ' UTC',
            sourceArtifact: 'Shellbag',
            isSuspicious: /temp|tor|hidden/i.test(folder),
          };

          results.push({
            id: `art-bag-${crypto.randomUUID().slice(0, 8)}`,
            category: 'recent_files',
            name: `Shellbag Visited Folder: ${folderName}`,
            timestamp: recentFileData.accessTime,
            sourceFile: file.name,
            sourceLocation: `${file.name} > Shell Bags Tree`,
            description: 'Explorer folder navigation and visual view preferences recorded by Windows Shell',
            value: folder,
            details: {
              'Folder Name': folderName,
              'Explorer Path': folder,
              'Artifact Source': 'Windows Shellbag',
            },
            isSuspicious: recentFileData.isSuspicious ?? false,
            suspiciousReason: recentFileData.isSuspicious
              ? 'User explored suspicious staging directory'
              : undefined,
            rawText: folder,
            recentFileData,
          });
        }
      }
    }

    // ----------------------------------------------------
    // 3. PST / OST / EML / MSG Email Analysis with Outlook Layout
    // ----------------------------------------------------
    if (options.pstEmails) {
      let emailCountForThisFile = 0;
      if (isMailboxFile) {
        try {
          const mailBuffer = await readFileAsArrayBuffer(file, 128 * 1024 * 1024);
          const mailArtifacts = await parsePstOrMailboxBinary(mailBuffer, file.name, file.lastModified);
          results.push(...mailArtifacts);
          emailCountForThisFile += mailArtifacts.length;
        } catch (err) {
          console.warn(`Error parsing binary mailbox file ${file.name}:`, err);
        }
      }

      // If not recognized as binary mailbox or if 0 emails were carved from this file, test for RFC822 / text email headers
      if (!isMailboxFile || emailCountForThisFile === 0) {
        try {
          const textContent = await readFileAsText(file);
          const emlArtifacts = parseEmailTextOrMime(textContent, file.name, file.lastModified);
          results.push(...emlArtifacts);
        } catch (emlErr) {
          console.warn(`Error parsing text email format for ${file.name}:`, emlErr);
        }
      }
    }

    // Read textContent for remaining textual / artifact parsers
    const textContent = await readFileAsText(file);

    // ----------------------------------------------------
    // 4. Browser History Analysis
    // ----------------------------------------------------
    if (options.browserHistory) {
      const urlRegex = /https?:\/\/[a-zA-Z0-9\-\._~:\/\?#\[\]@!$&'\(\)\*\+,;=%]+/gi;
      const urls = new Set<string>();
      let match;
      let count = 0;
      while ((match = urlRegex.exec(textContent)) !== null && count < 30) {
        const u = match[0];
        if (u.length > 12 && !urls.has(u)) {
          urls.add(u);
          count++;
          let hostname = '';
          let protocol = '';
          try {
            const parsedUrl = new URL(u);
            hostname = parsedUrl.hostname;
            protocol = parsedUrl.protocol;
          } catch {
            hostname = u.slice(0, 30);
            protocol = 'http:';
          }
          const isSuspicious = /powershell|defender|mimikatz|pastebin|raw|temp|payload|c2|tunnel/i.test(u);
          results.push({
            id: `art-url-${crypto.randomUUID().slice(0, 8)}`,
            category: 'browser_history',
            name: `Extracted Web Access: ${hostname}`,
            timestamp: new Date(file.lastModified).toISOString().replace('T', ' ').slice(0, 19) + ' UTC',
            sourceFile: file.name,
            sourceLocation: `${file.name} > String Stream (Offset: 0x${match.index.toString(16).toUpperCase()})`,
            description: `Carved URI from ${file.name}`,
            value: u,
            details: {
              'Domain': hostname,
              'Protocol': protocol,
              'File Offset': `0x${match.index.toString(16).toUpperCase()}`,
              'Source Match': 'ASCII/UTF-8 Carved Stream'
            },
            isSuspicious,
            suspiciousReason: isSuspicious ? 'URL contains known attack staging or security bypass keywords' : undefined,
            rawText: `Offset 0x${match.index.toString(16).toUpperCase()}: ${u}`
          });
        }
      }
    }

    // ----------------------------------------------------
    // 5. Registry Hives / Run Keys Analysis (Text / Carved Fallback)
    // ----------------------------------------------------
    if (options.registryHives && (!isRegFile || results.filter((r) => r.sourceFile === file.name && r.category === 'run_keys').length === 0)) {
      const runKeyRegex = /(SOFTWARE|SYSTEM|Microsoft\\Windows\\CurrentVersion\\(Run|RunOnce|RunServices|Explorer\\UserAssist|Shell Folders))[^\r\n]*/gi;
      let runMatch;
      let runCount = 0;
      while ((runMatch = runKeyRegex.exec(textContent)) !== null && runCount < 20) {
        const line = runMatch[0].trim();
        if (line.length > 10) {
          runCount++;
          const isSusp = /temp|powershell|cmd\.exe|hidden|bypass|wscript|cscript|\.bat|\.vbs/i.test(line);
          results.push({
            id: `art-reg-${crypto.randomUUID().slice(0, 8)}`,
            category: 'run_keys',
            name: `Registry Key: ${line.split('\\').slice(-1)[0] || 'Run Entry'}`,
            timestamp: new Date(file.lastModified).toISOString().replace('T', ' ').slice(0, 19) + ' UTC',
            sourceFile: file.name,
            sourceLocation: line,
            description: 'Identified auto-start or registry persistence key',
            value: line,
            details: {
              'Hive Fragment': line.split('\\')[0],
              'Registry Path': line,
              'File Source': file.name
            },
            isSuspicious: isSusp,
            suspiciousReason: isSusp ? 'Command in Run key targets script interpreters or temporary directories' : undefined,
            rawText: line
          });
        }
      }
    }

    // ----------------------------------------------------
    // 6. USB Device Connection History (Text / Carved Fallback)
    // ----------------------------------------------------
    if (options.usbHistory && (!isRegFile || results.filter((r) => r.sourceFile === file.name && r.category === 'usb_connect').length === 0)) {
      const usbRegex = /USBSTOR\\[^\s\r\n\x00]+/gi;
      let usbMatch;
      let usbCount = 0;
      while ((usbMatch = usbRegex.exec(textContent)) !== null && usbCount < 15) {
        const dev = usbMatch[0].replace(/[^\x20-\x7E]/g, '');
        if (dev.length > 10) {
          usbCount++;
          results.push({
            id: `art-usb-${crypto.randomUUID().slice(0, 8)}`,
            category: 'usb_connect',
            name: `Carved USBSTOR Record: ${dev.slice(0, 40)}`,
            timestamp: new Date(file.lastModified).toISOString().replace('T', ' ').slice(0, 19) + ' UTC',
            sourceFile: file.name,
            sourceLocation: `USBSTOR Registry Node`,
            description: 'Extracted hardware identifier for connected USB mass storage device',
            value: dev,
            details: {
              'Device Descriptor': dev,
              'Source Evidence': file.name
            },
            isSuspicious: true,
            suspiciousReason: 'Uncatalogued external hardware identified in raw storage streams',
            rawText: dev
          });
        }
      }
    }

    // ----------------------------------------------------
    // 7. Recent User Activities (Prefetch, UserAssist)
    // ----------------------------------------------------
    if (options.userActivities) {
      const execRegex = /([a-zA-Z0-9_\-\\]+\.(exe|ps1|bat|vbs|docx|xlsx|pdf|lnk))/gi;
      const seen = new Set<string>();
      let execMatch;
      let execCount = 0;
      while ((execMatch = execRegex.exec(textContent)) !== null && execCount < 20) {
        const item = execMatch[0];
        if (item.length > 5 && !seen.has(item.toLowerCase())) {
          seen.add(item.toLowerCase());
          execCount++;
          const isSusp = /mimikatz|payload|backdoor|exploit|update_svc|temp/i.test(item);
          results.push({
            id: `art-act-${crypto.randomUUID().slice(0, 8)}`,
            category: 'user_activity',
            name: `User Artifact: ${item}`,
            timestamp: new Date(file.lastModified).toISOString().replace('T', ' ').slice(0, 19) + ' UTC',
            sourceFile: file.name,
            sourceLocation: `${file.name} > Evidence Stream`,
            description: `Execution or document artifact discovered in ${file.name}`,
            value: item,
            details: {
              'Item Reference': item,
              'Type': item.endsWith('.exe') ? 'Executable' : item.endsWith('.lnk') ? 'Shell Link' : 'Document',
              'Container File': file.name
            },
            isSuspicious: isSusp,
            suspiciousReason: isSusp ? 'Identified file matches known malicious naming convention' : undefined,
            rawText: `Offset 0x${execMatch.index.toString(16)}: ${item}`
          });
        }
      }
    }

    // ----------------------------------------------------
    // 8. System & OS Info (Text / Carved Fallback)
    // ----------------------------------------------------
    if (options.systemInfo && (!isRegFile || results.filter((r) => r.sourceFile === file.name && r.category === 'system_info').length === 0)) {
      const sysRegex = /(Windows\s+(?:10|11|Server\s+\d+|7)|CurrentBuild(?:Number)?\s*=\s*\d+|ComputerName\s*=\s*[A-Za-z0-9\-]+|TimeZoneKeyName\s*=\s*[A-Za-z\s]+)/gi;
      let sysMatch;
      let sysCount = 0;
      while ((sysMatch = sysRegex.exec(textContent)) !== null && sysCount < 10) {
        const sysVal = sysMatch[0].trim();
        sysCount++;
        results.push({
          id: `art-sys-${crypto.randomUUID().slice(0, 8)}`,
          category: 'system_info',
          name: `System Property: ${sysVal.split('=')[0].trim()}`,
          timestamp: new Date(file.lastModified).toISOString().replace('T', ' ').slice(0, 19) + ' UTC',
          sourceFile: file.name,
          sourceLocation: `${file.name} > OS Metadata`,
          description: 'Operating system configuration parameter',
          value: sysVal,
          details: {
            'Property String': sysVal,
            'Evidence Source': file.name
          },
          isSuspicious: false,
          rawText: sysVal
        });
      }
    }

    // ----------------------------------------------------
    // 9. User Accounts & Security (Text / Carved Fallback)
    // ----------------------------------------------------
    if (options.userAccounts && (!isRegFile || results.filter((r) => r.sourceFile === file.name && r.category === 'user_accounts').length === 0)) {
      const userRegex = /(Administrator|Guest|DefaultAccount|WDAGUtilityAccount|VictimUser|svc_[a-zA-Z0-9]+|user_[a-zA-Z0-9]+)/gi;
      const seenUsers = new Set<string>();
      let uMatch;
      let uCount = 0;
      while ((uMatch = userRegex.exec(textContent)) !== null && uCount < 10) {
        const uname = uMatch[0];
        if (!seenUsers.has(uname.toLowerCase())) {
          seenUsers.add(uname.toLowerCase());
          uCount++;
          const isSusp = uname.startsWith('svc_');
          results.push({
            id: `art-usr-${crypto.randomUUID().slice(0, 8)}`,
            category: 'user_accounts',
            name: `Discovered User Account: ${uname}`,
            timestamp: new Date(file.lastModified).toISOString().replace('T', ' ').slice(0, 19) + ' UTC',
            sourceFile: file.name,
            sourceLocation: `${file.name} > SAM / Security Accounts`,
            description: `Security account record identified in file`,
            value: uname,
            details: {
              'Account Name': uname,
              'Identified In': file.name
            },
            isSuspicious: isSusp,
            suspiciousReason: isSusp ? 'Non-standard service account found in user tables' : undefined,
            rawText: `Account match: ${uname}`
          });
        }
      }
    }
  }

  // Pure carved results directly from uploaded files without any mock baseline data
  return results;
}
