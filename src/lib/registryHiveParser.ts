/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { Buffer } from 'buffer';
import { ForensicArtifact } from '../types';

export interface RegistryValue {
  name: string;
  type: number;
  typeName: string;
  data: string | number | Buffer | string[];
  rawBytes?: Buffer;
}

export interface RegistryKeyNode {
  name: string;
  path: string;
  lastWritten: string;
  values: Record<string, RegistryValue>;
  subkeys: string[];
}

const REG_TYPES: Record<number, string> = {
  0: 'REG_NONE',
  1: 'REG_SZ',
  2: 'REG_EXPAND_SZ',
  3: 'REG_BINARY',
  4: 'REG_DWORD',
  5: 'REG_DWORD_BIG_ENDIAN',
  6: 'REG_LINK',
  7: 'REG_MULTI_SZ',
  8: 'REG_RESOURCE_LIST',
  9: 'REG_FULL_RESOURCE_DESCRIPTOR',
  10: 'REG_RESOURCE_REQUIREMENTS_LIST',
  11: 'REG_QWORD',
};

function formatIsoUtc(date: Date): string {
  if (isNaN(date.getTime())) return 'Unknown UTC';
  return date.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}

function fileTimeToDate(fileTime: bigint): Date {
  if (fileTime <= 0n || fileTime < 116444736000000000n) {
    return new Date(0);
  }
  const unixMs = Number((fileTime - 116444736000000000n) / 10000n);
  return new Date(unixMs);
}

/**
 * Checks if a buffer has the Windows Registry Hive header 'regf' or is a registry export file
 */
export function isRegistryHive(buf: Buffer, fileName?: string): boolean {
  if (buf.length >= 4) {
    // Check 'regf' magic header (0x66676572)
    if (
      buf[0] === 0x72 && // 'r'
      buf[1] === 0x65 && // 'e'
      buf[2] === 0x67 && // 'g'
      buf[3] === 0x66    // 'f'
    ) {
      return true;
    }
    // Check if 'regf' exists in the first 512 bytes
    if (buf.subarray(0, Math.min(buf.length, 512)).includes('regf')) {
      return true;
    }
    // Check for Windows Registry text export headers
    const sample = buf.subarray(0, Math.min(buf.length, 256)).toString('latin1');
    if (sample.includes('Windows Registry Editor') || sample.includes('REGEDIT') || sample.includes('[HKEY_')) {
      return true;
    }
  }
  if (fileName) {
    const fn = fileName.toLowerCase();
    if (/(system|software|sam|security|ntuser|usrclass)/i.test(fn)) {
      return true;
    }
    if (/\.(hiv|hive|dat|reg)$/i.test(fn)) {
      return true;
    }
  }
  return false;
}

/**
 * Parses exported .reg text files (UTF-8, UTF-16LE, or Latin-1) into a registry key map
 */
function parseRegTextExport(buf: Buffer): Map<string, RegistryKeyNode> {
  const keysMap = new Map<string, RegistryKeyNode>();
  let text = '';
  // Detect UTF-16LE
  if ((buf.length >= 2 && buf[0] === 0xff && buf[1] === 0xfe) || (buf.length >= 4 && buf[1] === 0 && buf[3] === 0)) {
    text = buf.toString('utf16le');
  } else {
    text = buf.toString('utf8');
  }

  const lines = text.split(/\r?\n/);
  let currentKey: RegistryKeyNode | null = null;

  for (const rawLine of lines) {
    const line = rawLine.trim();
    if (!line || line.startsWith(';') || line.startsWith('Windows Registry Editor') || line.startsWith('REGEDIT')) {
      continue;
    }

    if (line.startsWith('[') && line.endsWith(']')) {
      let keyPath = line.slice(1, -1).trim();
      keyPath = keyPath.replace(/^(HKEY_LOCAL_MACHINE|HKEY_CURRENT_USER|HKLM|HKCU)\\/i, '');
      const keyName = keyPath.split('\\').pop() || keyPath;
      currentKey = {
        name: keyName,
        path: keyPath,
        lastWritten: '',
        values: {},
        subkeys: [],
      };
      keysMap.set(keyPath.toLowerCase(), currentKey);
      if (!keysMap.has(keyName.toLowerCase())) {
        keysMap.set(keyName.toLowerCase(), currentKey);
      }
      continue;
    }

    if (currentKey && line.includes('=')) {
      const eqIdx = line.indexOf('=');
      let valName = line.slice(0, eqIdx).trim();
      if (valName.startsWith('"') && valName.endsWith('"')) {
        valName = valName.slice(1, -1);
      } else if (valName === '@') {
        valName = '';
      }
      const valDataStr = line.slice(eqIdx + 1).trim();
      let valData: any = valDataStr;
      let valType = 1;
      let rawBytes: Buffer | undefined;

      if (valDataStr.startsWith('"') && valDataStr.endsWith('"')) {
        valData = valDataStr.slice(1, -1).replace(/\\"/g, '"').replace(/\\\\/g, '\\');
        valType = 1;
      } else if (valDataStr.startsWith('dword:')) {
        valData = parseInt(valDataStr.replace('dword:', ''), 16) || 0;
        valType = 4;
      } else if (valDataStr.startsWith('hex:')) {
        const hexParts = valDataStr.replace('hex:', '').split(',').map(s => parseInt(s.trim(), 16)).filter(n => !isNaN(n));
        rawBytes = Buffer.from(hexParts);
        valData = rawBytes.toString('latin1');
        valType = 3;
      }

      currentKey.values[valName] = {
        name: valName,
        type: valType,
        typeName: REG_TYPES[valType] || 'REG_SZ',
        data: valData,
        rawBytes,
      };
    }
  }

  return keysMap;
}

/**
 * Case-insensitive value lookup for a registry key node
 */
export function getVal(node: RegistryKeyNode | undefined, valName: string): RegistryValue | undefined {
  if (!node || !node.values) return undefined;
  if (node.values[valName]) return node.values[valName];
  const targetLower = valName.toLowerCase();
  for (const [k, v] of Object.entries(node.values)) {
    if (k.toLowerCase() === targetLower) return v;
  }
  return undefined;
}

/**
 * Parses a Windows Registry Hive (SYSTEM, SOFTWARE, SAM, SECURITY, NTUSER.DAT)
 * and returns structured forensic artifacts.
 */
export function parseRegistryHive(
  buf: Buffer,
  fileName: string,
  lastModified: number
): ForensicArtifact[] {
  const artifacts: ForensicArtifact[] = [];
  const fileNameUpper = fileName.toUpperCase();

  // Check if binary regf hive or text .reg export
  const isBinaryRegf =
    buf.length >= 4 && (
      (buf[0] === 0x72 && buf[1] === 0x65 && buf[2] === 0x67 && buf[3] === 0x66) ||
      buf.subarray(0, Math.min(buf.length, 512)).includes('regf')
    );

  // Parse registry cells & build key/value map
  let keysMap = isBinaryRegf
    ? parseAllHiveKeysAndValues(buf, fileName, lastModified)
    : parseRegTextExport(buf);

  // If text parse returned empty on a non-binary file, try binary parser as fallback, and vice versa
  if (keysMap.size === 0) {
    if (isBinaryRegf) {
      keysMap = parseRegTextExport(buf);
    } else {
      keysMap = parseAllHiveKeysAndValues(buf, fileName, lastModified);
    }
  }

  // Detect hive type
  const isSystemHive =
    fileNameUpper.includes('SYSTEM') ||
    findKeyMatches(keysMap, /ControlSet|CurrentControlSet|Select|MountedDevices|HardwareConfig|TimeZoneInformation|ComputerName/i).length > 0;
  const isSoftwareHive =
    fileNameUpper.includes('SOFTWARE') ||
    findKeyMatches(keysMap, /Microsoft\\Windows\\CurrentVersion/i).length > 0;
  const isSamHive =
    fileNameUpper.includes('SAM') ||
    findKeyMatches(keysMap, /SAM\\Domains\\Account\\Users/i).length > 0;
  const isNtUserHive =
    fileNameUpper.includes('NTUSER') ||
    findKeyMatches(keysMap, /Software\\Microsoft\\Windows\\CurrentVersion\\Explorer/i).length > 0;

  // 1. If SYSTEM Hive, extract comprehensive System & OS info, USBSTOR, Network, and Persistent Services
  if (isSystemHive) {
    extractSystemHiveArtifacts(keysMap, buf, fileName, lastModified, artifacts);
  }

  // 2. If SOFTWARE Hive, extract OS version, installed software, and Run/RunOnce persistence
  if (isSoftwareHive) {
    extractSoftwareHiveArtifacts(keysMap, buf, fileName, lastModified, artifacts);
  }

  // 3. If SAM Hive, extract user accounts, RIDs, and privileges
  if (isSamHive) {
    extractSamHiveArtifacts(keysMap, buf, fileName, lastModified, artifacts);
  }

  // 4. If NTUSER.DAT Hive, extract user environment, Run keys, and Shellbags/MRU
  if (isNtUserHive) {
    extractNtUserHiveArtifacts(keysMap, buf, fileName, lastModified, artifacts);
  }

  // 5. If hive type could not be strictly determined, still run system info extraction if any ControlSet or TimeZone/ComputerName key is present
  if (!isSystemHive && !isSoftwareHive && !isSamHive && !isNtUserHive) {
    if (findKey(keysMap, /ControlSet|ComputerName|TimeZoneInformation|Select/i)) {
      extractSystemHiveArtifacts(keysMap, buf, fileName, lastModified, artifacts);
    }
  }

  // 6. General scan for Run / RunOnce / Auto-start persistence in any hive
  extractRunKeysFromMap(keysMap, fileName, lastModified, artifacts);

  // 7. If no structured keys were recovered or if SYSTEM hive has missing core fields, run carver
  const hasCompName = artifacts.some((a) => a.name.includes('Computer Name'));
  if (artifacts.length === 0 || (isSystemHive && !hasCompName)) {
    extractCarvedRegistryArtifacts(buf, fileName, lastModified, artifacts);
  }

  return artifacts;
}

/**
 * Helper to carve a string near a keyword in raw buffer (UTF-16LE or ASCII)
 */
function carveStringNearKeyword(buf: Buffer, keyword: string, maxWindow = 180): string | null {
  const needles = [
    Buffer.from(keyword, 'utf16le'),
    Buffer.from(keyword, 'ascii'),
  ];

  for (const needle of needles) {
    let searchPos = 0;
    while (searchPos + needle.length < buf.length) {
      const idx = buf.indexOf(needle, searchPos);
      if (idx === -1) break;

      // Scan within a window of maxWindow bytes around and after the keyword
      const windowStart = idx + needle.length;
      const windowEnd = Math.min(buf.length, windowStart + maxWindow);
      const windowBuf = buf.subarray(windowStart, windowEnd);

      // Try to find UTF-16LE strings in this window
      for (let i = 0; i + 4 < windowBuf.length; i += 2) {
        let u16len = 0;
        while (i + u16len + 1 < windowBuf.length && windowBuf[i + u16len + 1] === 0) {
          const charCode = windowBuf[i + u16len];
          if (charCode >= 32 && charCode <= 126) {
            u16len += 2;
          } else {
            break;
          }
        }
        if (u16len >= 4 && u16len <= 80) {
          const candidate = windowBuf.subarray(i, i + u16len).toString('utf16le').trim();
          if (
            candidate.length >= 2 &&
            !candidate.toLowerCase().includes(keyword.toLowerCase()) &&
            !candidate.includes('\\') &&
            !candidate.includes('=') &&
            /^[A-Za-z0-9\-_. ]+$/.test(candidate)
          ) {
            return candidate;
          }
        }
      }

      // Try to find ASCII strings in this window
      const asciiSub = windowBuf.toString('ascii');
      const asciiMatch = /[\x00\x01-\x1f]([A-Za-z0-9\-_. ]{2,35})[\x00\r\n]/g.exec(asciiSub);
      if (asciiMatch && asciiMatch[1]) {
        const candidate = asciiMatch[1].trim();
        if (
          candidate.length >= 2 &&
          !candidate.toLowerCase().includes(keyword.toLowerCase()) &&
          !candidate.includes('\\')
        ) {
          return candidate;
        }
      }

      searchPos = idx + needle.length;
    }
  }

  return null;
}

/**
 * Extracts System & OS Info from SYSTEM hive (ComputerName, Timezone, OS, TCPIP, USB, Services)
 */
function extractSystemHiveArtifacts(
  keysMap: Map<string, RegistryKeyNode>,
  buf: Buffer,
  fileName: string,
  lastModified: number,
  artifacts: ForensicArtifact[]
): void {
  // Determine active ControlSet
  let activeControlSet = 'ControlSet001';
  let currentValNum = 1;
  let defaultValNum: number | undefined;
  let lastKnownGoodNum: number | undefined;

  const selectKey = findKey(keysMap, /Select$/i);
  if (selectKey) {
    const currVal = getVal(selectKey, 'Current');
    if (currVal && typeof currVal.data === 'number' && currVal.data >= 1 && currVal.data <= 9) {
      currentValNum = currVal.data;
      activeControlSet = `ControlSet00${currVal.data}`;
    }
    const defVal = getVal(selectKey, 'Default');
    if (defVal && typeof defVal.data === 'number') defaultValNum = defVal.data;
    const lkgVal = getVal(selectKey, 'LastKnownGood');
    if (lkgVal && typeof lkgVal.data === 'number') lastKnownGoodNum = lkgVal.data;
  }

  // Ensure activeControlSet actually exists in keysMap; if not, pick whichever ControlSet exists
  if (!findKey(keysMap, new RegExp(activeControlSet, 'i'))) {
    for (const cs of ['ControlSet001', 'ControlSet002', 'ControlSet003', 'CurrentControlSet']) {
      if (findKey(keysMap, new RegExp(cs, 'i'))) {
        activeControlSet = cs;
        break;
      }
    }
  }

  // Record Active ControlSet configuration artifact
  artifacts.push({
    id: `art-sys-select-${crypto.randomUUID().slice(0, 8)}`,
    category: 'system_info',
    name: `Registry Configuration: Active ${activeControlSet}`,
    timestamp: selectKey?.lastWritten || formatIsoUtc(new Date(lastModified)),
    sourceFile: fileName,
    sourceLocation: `SYSTEM > ${selectKey?.path || 'Select'}`,
    description: 'Kernel hardware profile control set selection (Current, Default, and LastKnownGood)',
    value: `${activeControlSet} (Current=${currentValNum}${defaultValNum !== undefined ? `, Default=${defaultValNum}` : ''}${lastKnownGoodNum !== undefined ? `, LastKnownGood=${lastKnownGoodNum}` : ''})`,
    details: {
      'Active Control Set': activeControlSet,
      'Current Value': String(currentValNum),
      'Default Value': String(defaultValNum ?? 'N/A'),
      'LastKnownGood Value': String(lastKnownGoodNum ?? 'N/A'),
      'Registry Path': selectKey?.path || 'SYSTEM\\Select',
    },
    isSuspicious: false,
    rawText: `Current=${currentValNum}; ActiveControlSet=${activeControlSet}`,
  });

  // ----------------------------------------------------
  // A. Computer Name
  // ----------------------------------------------------
  let computerName = '';

  // 1. Check ActiveComputerName subkey
  const activeCompKey =
    findKey(keysMap, new RegExp(`${activeControlSet}\\\\Control\\\\ComputerName\\\\ActiveComputerName$`, 'i')) ||
    findKey(keysMap, /Control\\ComputerName\\ActiveComputerName$/i);
  if (activeCompKey) {
    const val = getVal(activeCompKey, 'ComputerName') || Object.values(activeCompKey.values)[0];
    if (val && typeof val.data === 'string' && val.data.trim()) {
      computerName = val.data.trim();
    }
  }

  // 2. Check static ComputerName subkey
  if (!computerName) {
    const staticCompKey =
      findKey(keysMap, new RegExp(`${activeControlSet}\\\\Control\\\\ComputerName\\\\ComputerName$`, 'i')) ||
      findKey(keysMap, /Control\\ComputerName\\ComputerName$/i);
    if (staticCompKey) {
      const val = getVal(staticCompKey, 'ComputerName') || Object.values(staticCompKey.values)[0];
      if (val && typeof val.data === 'string' && val.data.trim()) {
        computerName = val.data.trim();
      }
    }
  }

  // 3. Scan all nodes in keysMap for any node having ComputerName or ActiveComputerName
  if (!computerName) {
    for (const node of keysMap.values()) {
      const cVal = getVal(node, 'ComputerName') || getVal(node, 'ActiveComputerName');
      if (cVal && typeof cVal.data === 'string') {
        const str = cVal.data.trim();
        if (str.length >= 2 && str.length <= 40 && !str.includes('\\') && !str.includes('/') && !str.includes('=')) {
          computerName = str;
          break;
        }
      }
    }
  }

  // 4. Check Tcpip Parameters Hostname
  if (!computerName) {
    const tcpKey = findKey(keysMap, /Services\\Tcpip\\Parameters$/i);
    if (tcpKey) {
      const hVal = getVal(tcpKey, 'Hostname') || getVal(tcpKey, 'NV Hostname') || getVal(tcpKey, 'DHCPHostname');
      if (hVal && typeof hVal.data === 'string' && hVal.data.trim()) {
        computerName = hVal.data.trim();
      }
    }
  }

  // 5. Carve ComputerName from raw buffer (UTF-16LE and ASCII)
  if (!computerName) {
    computerName = carveStringNearKeyword(buf, 'ComputerName', 160) || '';
  }

  if (computerName) {
    artifacts.push({
      id: `art-sys-compname-${crypto.randomUUID().slice(0, 8)}`,
      category: 'system_info',
      name: `Computer Name: ${computerName}`,
      timestamp: formatIsoUtc(new Date(lastModified)),
      sourceFile: fileName,
      sourceLocation: `SYSTEM > ${activeCompKey?.path || 'Control\\ComputerName'}`,
      description: 'Host system NetBIOS / Windows computer identity extracted from SYSTEM registry hive',
      value: computerName,
      details: {
        'Computer Name': computerName,
        'Registry Path': activeCompKey?.path || 'SYSTEM\\CurrentControlSet\\Control\\ComputerName',
        'ControlSet': activeControlSet,
        'Last Modified': activeCompKey ? activeCompKey.lastWritten : formatIsoUtc(new Date(lastModified)),
      },
      isSuspicious: false,
      rawText: `ComputerName = ${computerName}`,
    });
  }

  // ----------------------------------------------------
  // B. Time Zone Information
  // ----------------------------------------------------
  let tzKeyName = '';
  let standardName = '';
  let daylightName = '';
  let activeTimeBias: string | number | undefined;
  let bias: string | number | undefined;

  const tzKey =
    findKey(keysMap, new RegExp(`${activeControlSet}\\\\Control\\\\TimeZoneInformation`, 'i')) ||
    findKey(keysMap, /Control\\TimeZoneInformation/i);

  if (tzKey) {
    tzKeyName = String(getVal(tzKey, 'TimeZoneKeyName')?.data || getVal(tzKey, 'StandardName')?.data || '');
    standardName = String(getVal(tzKey, 'StandardName')?.data || '');
    daylightName = String(getVal(tzKey, 'DaylightName')?.data || '');
    activeTimeBias = getVal(tzKey, 'ActiveTimeBias')?.data as any;
    bias = getVal(tzKey, 'Bias')?.data as any;
  }

  // Check any node having TimeZoneKeyName
  if (!tzKeyName) {
    for (const node of keysMap.values()) {
      const v = getVal(node, 'TimeZoneKeyName');
      if (v && typeof v.data === 'string' && v.data.trim()) {
        tzKeyName = v.data.trim();
        break;
      }
    }
  }

  // Carve TimeZoneKeyName from raw buffer
  if (!tzKeyName) {
    tzKeyName = carveStringNearKeyword(buf, 'TimeZoneKeyName', 160) || '';
  }

  if (tzKeyName) {
    artifacts.push({
      id: `art-sys-tz-${crypto.randomUUID().slice(0, 8)}`,
      category: 'system_info',
      name: `Time Zone: ${tzKeyName}`,
      timestamp: tzKey?.lastWritten || formatIsoUtc(new Date(lastModified)),
      sourceFile: fileName,
      sourceLocation: `SYSTEM > ${tzKey?.path || 'Control\\TimeZoneInformation'}`,
      description: 'Configured Windows system time zone and daylight saving time bias',
      value: `${tzKeyName} (Bias: ${activeTimeBias ?? bias ?? '0'} mins)`,
      details: {
        'Time Zone Name': tzKeyName,
        'Standard Name': standardName || tzKeyName,
        'Daylight Name': daylightName,
        'Active Time Bias (Minutes)': String(activeTimeBias ?? 'N/A'),
        'Base Bias': String(bias ?? 'N/A'),
        'Registry Path': tzKey?.path || 'SYSTEM\\CurrentControlSet\\Control\\TimeZoneInformation',
      },
      isSuspicious: false,
      rawText: `TimeZoneKeyName = ${tzKeyName}`,
    });
  }

  // ----------------------------------------------------
  // C. Operating System Platform Role (ProductOptions)
  // ----------------------------------------------------
  const prodOptKey =
    findKey(keysMap, new RegExp(`${activeControlSet}\\\\Control\\\\ProductOptions`, 'i')) ||
    findKey(keysMap, /Control\\ProductOptions$/i);

  if (prodOptKey) {
    const pTypeVal = getVal(prodOptKey, 'ProductType');
    const pType = String(pTypeVal?.data || '').trim();
    if (pType) {
      let roleDesc = 'Windows Workstation / Client OS (WinNT)';
      if (pType.toLowerCase() === 'servernt') roleDesc = 'Windows Standalone / Member Server (ServerNT)';
      else if (pType.toLowerCase() === 'lanmannt') roleDesc = 'Windows Active Directory Domain Controller (LanmanNT)';

      const suite = String(getVal(prodOptKey, 'ProductSuite')?.data || 'None');

      artifacts.push({
        id: `art-sys-prod-${crypto.randomUUID().slice(0, 8)}`,
        category: 'system_info',
        name: `OS Role & Edition: ${roleDesc.split('(')[0].trim()}`,
        timestamp: prodOptKey.lastWritten || formatIsoUtc(new Date(lastModified)),
        sourceFile: fileName,
        sourceLocation: `SYSTEM > ${prodOptKey.path}`,
        description: `Operating system role: ${roleDesc}`,
        value: `${roleDesc} [Suite: ${suite}]`,
        details: {
          'Product Type': pType,
          'Role Description': roleDesc,
          'Product Suite': suite,
          'Registry Path': prodOptKey.path,
        },
        isSuspicious: false,
        rawText: `ProductType = ${pType}; ProductSuite = ${suite}`,
      });
    }
  }

  // ----------------------------------------------------
  // D. Environment & Operating System Kernel
  // ----------------------------------------------------
  const envKey =
    findKey(keysMap, new RegExp(`${activeControlSet}\\\\Control\\\\Session Manager\\\\Environment`, 'i')) ||
    findKey(keysMap, /Session Manager\\Environment/i);

  if (envKey) {
    const os = String(getVal(envKey, 'OS')?.data || 'Windows_NT');
    const arch = String(getVal(envKey, 'PROCESSOR_ARCHITECTURE')?.data || 'AMD64');
    const procId = String(getVal(envKey, 'PROCESSOR_IDENTIFIER')?.data || '');
    const procCount = String(getVal(envKey, 'NUMBER_OF_PROCESSORS')?.data || '');
    const sysRoot = String(getVal(envKey, 'SystemRoot')?.data || 'C:\\Windows');
    const comSpec = String(getVal(envKey, 'ComSpec')?.data || '');

    artifacts.push({
      id: `art-sys-env-${crypto.randomUUID().slice(0, 8)}`,
      category: 'system_info',
      name: `System Environment: ${os} (${arch})`,
      timestamp: envKey.lastWritten || formatIsoUtc(new Date(lastModified)),
      sourceFile: fileName,
      sourceLocation: `SYSTEM > ${envKey.path}`,
      description: 'Host CPU architecture, processor identification, and core environment variables',
      value: `${os} [${arch}] - ${procId || 'CPU'}`,
      details: {
        'OS Name': os,
        'Processor Architecture': arch,
        'Processor Identifier': procId,
        'Processor Count': procCount,
        'System Root': sysRoot,
        'Command Interpreter (ComSpec)': comSpec,
        'Registry Path': envKey.path,
      },
      isSuspicious: false,
      rawText: `OS=${os}; ARCH=${arch}; CPU=${procId}`,
    });
  }

  // ----------------------------------------------------
  // E. Windows Shutdown Time
  // ----------------------------------------------------
  let shutdownTimeStr = '';
  const winKey =
    findKey(keysMap, new RegExp(`${activeControlSet}\\\\Control\\\\Windows`, 'i')) ||
    findKey(keysMap, /Control\\Windows$/i);

  let shutVal = winKey ? getVal(winKey, 'ShutdownTime') : undefined;
  if (!shutVal) {
    for (const node of keysMap.values()) {
      const sv = getVal(node, 'ShutdownTime');
      if (sv && sv.rawBytes && sv.rawBytes.length >= 8) {
        shutVal = sv;
        break;
      }
    }
  }

  if (shutVal && shutVal.rawBytes && shutVal.rawBytes.length >= 8) {
    try {
      const ft = shutVal.rawBytes.readBigUInt64LE(0);
      const d = fileTimeToDate(ft);
      if (d.getTime() > 0 && d.getTime() < 2500000000000) {
        shutdownTimeStr = formatIsoUtc(d);
      }
    } catch {
      // Fallback
    }
  }

  if (shutdownTimeStr) {
    const csdVersion = winKey ? getVal(winKey, 'CSDVersion')?.data : undefined;
    artifacts.push({
      id: `art-sys-shut-${crypto.randomUUID().slice(0, 8)}`,
      category: 'system_info',
      name: `Last Windows Shutdown Time: ${shutdownTimeStr}`,
      timestamp: shutdownTimeStr,
      sourceFile: fileName,
      sourceLocation: `SYSTEM > ${winKey?.path || 'Control\\Windows'}`,
      description: 'Last clean operating system shutdown timestamp recorded by the Windows kernel',
      value: shutdownTimeStr,
      details: {
        'Shutdown Timestamp': shutdownTimeStr,
        'CSD Version (Service Pack)': String(csdVersion || 'None'),
        'Registry Key': winKey?.path || 'SYSTEM\\CurrentControlSet\\Control\\Windows',
      },
      isSuspicious: false,
      rawText: `ShutdownTime = ${shutdownTimeStr}`,
    });
  }

  // ----------------------------------------------------
  // F. Hardware & BIOS System Information
  // ----------------------------------------------------
  const sysInfoKey =
    findKey(keysMap, new RegExp(`${activeControlSet}\\\\Control\\\\SystemInformation`, 'i')) ||
    findKey(keysMap, /Control\\SystemInformation/i);

  if (sysInfoKey) {
    const mfg = String(getVal(sysInfoKey, 'SystemManufacturer')?.data || 'Standard PC');
    const model = String(getVal(sysInfoKey, 'SystemProductName')?.data || '');
    const biosVer = String(getVal(sysInfoKey, 'BIOSVersion')?.data || '');
    const biosDate = String(getVal(sysInfoKey, 'BIOSReleaseDate')?.data || '');

    artifacts.push({
      id: `art-sys-hw-${crypto.randomUUID().slice(0, 8)}`,
      category: 'system_info',
      name: `Hardware Platform: ${mfg} ${model}`.trim(),
      timestamp: sysInfoKey.lastWritten || formatIsoUtc(new Date(lastModified)),
      sourceFile: fileName,
      sourceLocation: `SYSTEM > ${sysInfoKey.path}`,
      description: 'Hardware vendor, system model name, and BIOS release version',
      value: `${mfg} ${model} (BIOS: ${biosVer} ${biosDate})`.trim(),
      details: {
        'Manufacturer': mfg,
        'Product Model': model,
        'BIOS Version': biosVer,
        'BIOS Release Date': biosDate,
        'Registry Path': sysInfoKey.path,
      },
      isSuspicious: false,
      rawText: `Manufacturer=${mfg}; Model=${model}; BIOS=${biosVer}`,
    });
  }

  // ----------------------------------------------------
  // G. Network Configuration & Interfaces (Tcpip)
  // ----------------------------------------------------
  const tcpParamsKey =
    findKey(keysMap, new RegExp(`${activeControlSet}\\\\Services\\\\Tcpip\\\\Parameters$`, 'i')) ||
    findKey(keysMap, /Services\\Tcpip\\Parameters$/i);

  if (tcpParamsKey) {
    const host = String(getVal(tcpParamsKey, 'Hostname')?.data || getVal(tcpParamsKey, 'DHCPHostname')?.data || '');
    const domain = String(getVal(tcpParamsKey, 'Domain')?.data || getVal(tcpParamsKey, 'DHCPDomain')?.data || '');

    if (host || domain) {
      artifacts.push({
        id: `art-sys-net-${crypto.randomUUID().slice(0, 8)}`,
        category: 'system_info',
        name: `Network Host & Domain: ${host}${domain ? '.' + domain : ''}`,
        timestamp: tcpParamsKey.lastWritten || formatIsoUtc(new Date(lastModified)),
        sourceFile: fileName,
        sourceLocation: `SYSTEM > ${tcpParamsKey.path}`,
        description: 'Host domain membership and TCP/IP network identity parameters',
        value: `Hostname: ${host || 'Local'} | Domain: ${domain || 'WORKGROUP'}`,
        details: {
          'TCP/IP Hostname': host,
          'DNS Domain': domain || 'None (Workgroup)',
          'Registry Path': tcpParamsKey.path,
        },
        isSuspicious: false,
        rawText: `Hostname=${host}; Domain=${domain}`,
      });
    }
  }

  // Check network adapter interfaces
  const ifaceKeys = findKeyMatches(keysMap, new RegExp(`${activeControlSet}\\\\Services\\\\Tcpip\\\\Parameters\\\\Interfaces`, 'i'));
  for (const ifKey of ifaceKeys) {
    const ip = String(getVal(ifKey, 'IPAddress')?.data || getVal(ifKey, 'DhcpIPAddress')?.data || '');
    const subnet = String(getVal(ifKey, 'SubnetMask')?.data || getVal(ifKey, 'DhcpSubnetMask')?.data || '');
    const gateway = String(getVal(ifKey, 'DefaultGateway')?.data || getVal(ifKey, 'DhcpDefaultGateway')?.data || '');
    const dns = String(getVal(ifKey, 'NameServer')?.data || getVal(ifKey, 'DhcpNameServer')?.data || '');

    if (ip && ip !== '0.0.0.0' && ip.length > 6) {
      const ifGuid = ifKey.path.split('\\').pop() || 'Interface';
      artifacts.push({
        id: `art-sys-iface-${crypto.randomUUID().slice(0, 8)}`,
        category: 'system_info',
        name: `Network Adapter Interface: ${ip}`,
        timestamp: ifKey.lastWritten || formatIsoUtc(new Date(lastModified)),
        sourceFile: fileName,
        sourceLocation: `SYSTEM > ${ifKey.path}`,
        description: 'Assigned IPv4 network address and default routing gateway',
        value: `IP: ${ip} | Gateway: ${gateway || 'None'} | DNS: ${dns || 'Default'}`,
        details: {
          'IPv4 Address': ip,
          'Subnet Mask': subnet,
          'Default Gateway': gateway,
          'DNS Name Servers': dns,
          'Interface GUID': ifGuid,
          'Registry Path': ifKey.path,
        },
        isSuspicious: false,
        rawText: `IP=${ip}; Mask=${subnet}; Gateway=${gateway}`,
      });
    }
  }

  // ----------------------------------------------------
  // H. Crash Control & Memory Dumps
  // ----------------------------------------------------
  const crashKey =
    findKey(keysMap, new RegExp(`${activeControlSet}\\\\Control\\\\CrashControl$`, 'i')) ||
    findKey(keysMap, /Control\\CrashControl$/i);

  if (crashKey) {
    const dumpFile = String(getVal(crashKey, 'DumpFile')?.data || '%SystemRoot%\\MEMORY.DMP');
    const miniDir = String(getVal(crashKey, 'MinidumpDir')?.data || '%SystemRoot%\\Minidump');
    const autoReboot = getVal(crashKey, 'AutoReboot')?.data;

    artifacts.push({
      id: `art-sys-crash-${crypto.randomUUID().slice(0, 8)}`,
      category: 'system_info',
      name: 'Crash Dump Configuration: Kernel Memory Dump',
      timestamp: crashKey.lastWritten || formatIsoUtc(new Date(lastModified)),
      sourceFile: fileName,
      sourceLocation: `SYSTEM > ${crashKey.path}`,
      description: 'System crash, blue screen of death (BSOD), and memory dump storage locations',
      value: `Dump: ${dumpFile} | Minidump: ${miniDir}`,
      details: {
        'Crash Dump File': dumpFile,
        'Minidump Directory': miniDir,
        'Auto Reboot On Crash': autoReboot === 1 ? 'Enabled' : 'Disabled',
        'Registry Path': crashKey.path,
      },
      isSuspicious: false,
      rawText: `DumpFile=${dumpFile}; MinidumpDir=${miniDir}`,
    });
  }

  // ----------------------------------------------------
  // I. Mounted Devices & Volume Drive Letters
  // ----------------------------------------------------
  const mountedKey = findKey(keysMap, /MountedDevices$/i);
  if (mountedKey) {
    for (const [valName, valObj] of Object.entries(mountedKey.values)) {
      if (valName.startsWith('\\DosDevices\\')) {
        const driveLetter = valName.replace('\\DosDevices\\', '');
        artifacts.push({
          id: `art-sys-mount-${crypto.randomUUID().slice(0, 8)}`,
          category: 'system_info',
          name: `Mounted Volume: ${driveLetter}`,
          timestamp: mountedKey.lastWritten || formatIsoUtc(new Date(lastModified)),
          sourceFile: fileName,
          sourceLocation: `SYSTEM > MountedDevices > ${valName}`,
          description: `Drive letter assignment mapped to volume signature in registry`,
          value: `Drive ${driveLetter}`,
          details: {
            'Drive Letter': driveLetter,
            'Device Signature / GUID': String(valObj.data || 'Partition Binary Signature'),
            'Registry Path': 'SYSTEM\\MountedDevices',
          },
          isSuspicious: false,
          rawText: `${valName} = ${valObj.data}`,
        });
      }
    }
  }

  // ----------------------------------------------------
  // J. Connected USB Mass Storage Devices (USBSTOR)
  // ----------------------------------------------------
  const usbStorKeys = findKeyMatches(keysMap, new RegExp(`${activeControlSet}\\\\Enum\\\\USBSTOR`, 'i'));
  for (const uKey of usbStorKeys) {
    const parts = uKey.path.split('\\');
    // Typical path: ControlSet001\Enum\USBSTOR\Disk&Ven_SanDisk&Prod_Cruzer&Rev_1.26\001402283921312
    if (parts.length >= 5) {
      const devDescriptor = parts[parts.length - 2];
      const serialNumber = parts[parts.length - 1];
      const friendlyName = String(getVal(uKey, 'FriendlyName')?.data || getVal(uKey, 'DeviceDesc')?.data || devDescriptor);

      const isSusp = /malware|payload|exfil|rubber|badusb/i.test(devDescriptor + ' ' + serialNumber);

      artifacts.push({
        id: `art-usb-${crypto.randomUUID().slice(0, 8)}`,
        category: 'usb_connect',
        name: `USB Storage Device: ${friendlyName}`,
        timestamp: uKey.lastWritten || formatIsoUtc(new Date(lastModified)),
        sourceFile: fileName,
        sourceLocation: `SYSTEM > ${uKey.path}`,
        description: 'Connected USB removable flash drive or external mass storage device',
        value: `${friendlyName} (S/N: ${serialNumber})`,
        details: {
          'Friendly Name': friendlyName,
          'Hardware Descriptor': devDescriptor,
          'Serial Number': serialNumber,
          'Device Path': uKey.path,
          'First Installed / Last Written': uKey.lastWritten,
        },
        isSuspicious: isSusp,
        suspiciousReason: isSusp ? 'Unverified removable device identified in system hardware enumeration' : undefined,
        rawText: `USBSTOR: ${devDescriptor}\\${serialNumber} (${friendlyName})`,
      });
    }
  }

  // ----------------------------------------------------
  // K. Suspicious & Auto-Start Services
  // ----------------------------------------------------
  const serviceKeys = findKeyMatches(keysMap, new RegExp(`${activeControlSet}\\\\Services\\\\[^\\\\]+$`, 'i'));
  for (const sKey of serviceKeys) {
    const sName = sKey.path.split('\\').pop() || 'Service';
    const imgPath = String(getVal(sKey, 'ImagePath')?.data || '');
    const startType = getVal(sKey, 'Start')?.data;
    const dispName = String(getVal(sKey, 'DisplayName')?.data || sName);

    if (imgPath) {
      const isSusp =
        /temp\\|appdata\\|powershell|cmd\.exe|hidden|bypass|\.vbs|\.bat|\.ps1|rundll32|mimikatz|nc\.exe/i.test(imgPath);

      // Report suspicious services or services starting automatically
      if (isSusp || (startType === 2 && !imgPath.toLowerCase().includes('windows\\system32'))) {
        artifacts.push({
          id: `art-sys-srv-${crypto.randomUUID().slice(0, 8)}`,
          category: 'run_keys',
          name: `Service Persistence: ${dispName}`,
          timestamp: sKey.lastWritten || formatIsoUtc(new Date(lastModified)),
          sourceFile: fileName,
          sourceLocation: `SYSTEM > ${sKey.path}`,
          description: `Windows service configured with binary path ${imgPath.slice(0, 80)}`,
          value: imgPath,
          details: {
            'Service Name': sName,
            'Display Name': dispName,
            'Image Path (Binary)': imgPath,
            'Start Type': startType === 2 ? 'Automatic (2)' : startType === 3 ? 'Manual (3)' : String(startType),
            'Registry Path': sKey.path,
          },
          isSuspicious: isSusp,
          suspiciousReason: isSusp
            ? 'Service image path executes from non-standard directory or utilizes command interpreter'
            : undefined,
          rawText: `${sName} ImagePath = ${imgPath}`,
        });
      }
    }
  }
}

/**
 * Extracts OS build, Product Name, and CurrentVersion from SOFTWARE hive
 */
function extractSoftwareHiveArtifacts(
  keysMap: Map<string, RegistryKeyNode>,
  buf: Buffer,
  fileName: string,
  lastModified: number,
  artifacts: ForensicArtifact[]
): void {
  const cvKey =
    findKey(keysMap, /Microsoft\\Windows NT\\CurrentVersion$/i) ||
    findKey(keysMap, /Windows NT\\CurrentVersion$/i);

  if (cvKey) {
    const prodName = String(cvKey.values['ProductName']?.data || 'Windows OS');
    const build = String(cvKey.values['CurrentBuild']?.data || cvKey.values['CurrentBuildNumber']?.data || '');
    const ubr = String(cvKey.values['UBR']?.data || '');
    const fullBuild = ubr ? `${build}.${ubr}` : build;
    const regOwner = String(cvKey.values['RegisteredOwner']?.data || '');
    const displayVer = String(cvKey.values['DisplayVersion']?.data || cvKey.values['ReleaseId']?.data || '');

    artifacts.push({
      id: `art-sys-osver-${crypto.randomUUID().slice(0, 8)}`,
      category: 'system_info',
      name: `Operating System: ${prodName} ${displayVer}`.trim(),
      timestamp: cvKey.lastWritten || formatIsoUtc(new Date(lastModified)),
      sourceFile: fileName,
      sourceLocation: `SOFTWARE > ${cvKey.path}`,
      description: 'Windows operating system release version, build compilation, and registered owner',
      value: `${prodName} (Build ${fullBuild})`,
      details: {
        'Product Name': prodName,
        'Display Version': displayVer,
        'Build Number': fullBuild,
        'Registered Owner': regOwner || 'Not Set',
        'Registry Path': cvKey.path,
      },
      isSuspicious: false,
      rawText: `ProductName = ${prodName}; Build = ${fullBuild}`,
    });
  }
}

/**
 * Extracts SAM user accounts, RIDs, and privileges
 */
function extractSamHiveArtifacts(
  keysMap: Map<string, RegistryKeyNode>,
  buf: Buffer,
  fileName: string,
  lastModified: number,
  artifacts: ForensicArtifact[]
): void {
  const userKeys = findKeyMatches(keysMap, /SAM\\Domains\\Account\\Users\\Names\\[^\\\\]+$/i);
  for (const uKey of userKeys) {
    const userName = uKey.path.split('\\').pop() || 'User';
    const isSusp = /(admin|root|svc_|temp|backdoor|support)/i.test(userName);

    artifacts.push({
      id: `art-sam-user-${crypto.randomUUID().slice(0, 8)}`,
      category: 'user_accounts',
      name: `SAM User Account: ${userName}`,
      timestamp: uKey.lastWritten || formatIsoUtc(new Date(lastModified)),
      sourceFile: fileName,
      sourceLocation: `SAM > ${uKey.path}`,
      description: 'Local security account identity registered in SAM database',
      value: userName,
      details: {
        'Account Username': userName,
        'Registry Path': uKey.path,
        'Last Modified': uKey.lastWritten,
      },
      isSuspicious: isSusp,
      suspiciousReason: isSusp ? 'Privileged or administrative account identifier' : undefined,
      rawText: `SAM Account: ${userName}`,
    });
  }
}

/**
 * Extracts NTUSER.DAT user environment and shell history
 */
function extractNtUserHiveArtifacts(
  keysMap: Map<string, RegistryKeyNode>,
  buf: Buffer,
  fileName: string,
  lastModified: number,
  artifacts: ForensicArtifact[]
): void {
  // Extract user environment
  const userEnvKey = findKey(keysMap, /Environment$/i);
  if (userEnvKey) {
    const userPath = String(userEnvKey.values['PATH']?.data || userEnvKey.values['Path']?.data || '');
    const userTemp = String(userEnvKey.values['TEMP']?.data || userEnvKey.values['TMP']?.data || '');
    if (userTemp) {
      artifacts.push({
        id: `art-ntuser-env-${crypto.randomUUID().slice(0, 8)}`,
        category: 'system_info',
        name: `User Profile Environment: TEMP`,
        timestamp: userEnvKey.lastWritten || formatIsoUtc(new Date(lastModified)),
        sourceFile: fileName,
        sourceLocation: `NTUSER.DAT > ${userEnvKey.path}`,
        description: 'User profile temporary directory and search path configuration',
        value: userTemp,
        details: {
          'TEMP Path': userTemp,
          'User PATH': userPath.slice(0, 150),
          'Registry Path': userEnvKey.path,
        },
        isSuspicious: false,
        rawText: `TEMP = ${userTemp}`,
      });
    }
  }
}

/**
 * Scans registry map for Run / RunOnce persistence keys
 */
function extractRunKeysFromMap(
  keysMap: Map<string, RegistryKeyNode>,
  fileName: string,
  lastModified: number,
  artifacts: ForensicArtifact[]
): void {
  const runKeys = findKeyMatches(
    keysMap,
    /(?:CurrentVersion|Windows)\\(?:Run|RunOnce|RunServices|RunServicesOnce)$/i
  );

  for (const rKey of runKeys) {
    for (const [valName, valObj] of Object.entries(rKey.values)) {
      const cmd = String(valObj.data || '');
      if (cmd && cmd.length > 2) {
        const isSusp = /temp\\|appdata\\|powershell|cmd\.exe|hidden|bypass|wscript|cscript|\.bat|\.vbs|\.ps1|rundll32|regsvr32/i.test(
          cmd
        );

        artifacts.push({
          id: `art-reg-run-${crypto.randomUUID().slice(0, 8)}`,
          category: 'run_keys',
          name: `Auto-Start: ${valName}`,
          timestamp: rKey.lastWritten || formatIsoUtc(new Date(lastModified)),
          sourceFile: fileName,
          sourceLocation: `${fileName} > ${rKey.path} > ${valName}`,
          description: `Auto-start persistence command registered under ${rKey.path.split('\\').pop()}`,
          value: cmd,
          details: {
            'Value Name': valName,
            'Command Line': cmd,
            'Registry Path': rKey.path,
            'Registry Type': valObj.typeName,
          },
          isSuspicious: isSusp,
          suspiciousReason: isSusp
            ? 'Auto-start command targets temporary path or launches script execution interpreters'
            : undefined,
          rawText: `${valName} = ${cmd}`,
        });
      }
    }
  }
}

/**
 * Fallback direct cell/string carver for fragmented or unallocated registry data
 */
function extractCarvedRegistryArtifacts(
  buf: Buffer,
  fileName: string,
  lastModified: number,
  artifacts: ForensicArtifact[]
): void {
  const text = buf.toString('latin1');
  const maxCarved = 25;

  // 1. Carve ComputerName
  const carvedComp = carveStringNearKeyword(buf, 'ComputerName', 160);
  if (carvedComp && !artifacts.some((a) => a.name.includes('Computer Name'))) {
    artifacts.push({
      id: `art-sys-carved-comp-${crypto.randomUUID().slice(0, 8)}`,
      category: 'system_info',
      name: `Computer Name: ${carvedComp}`,
      timestamp: formatIsoUtc(new Date(lastModified)),
      sourceFile: fileName,
      sourceLocation: `${fileName} > Carved Binary Stream`,
      description: 'Host system NetBIOS computer name recovered from registry stream',
      value: carvedComp,
      details: {
        'Computer Name': carvedComp,
        'Carved Source': fileName,
      },
      isSuspicious: false,
      rawText: `ComputerName: ${carvedComp}`,
    });
  }

  // 2. Carve TimeZoneKeyName
  const carvedTz = carveStringNearKeyword(buf, 'TimeZoneKeyName', 160);
  if (carvedTz && !artifacts.some((a) => a.name.includes('Time Zone'))) {
    artifacts.push({
      id: `art-sys-carved-tz-${crypto.randomUUID().slice(0, 8)}`,
      category: 'system_info',
      name: `Time Zone: ${carvedTz}`,
      timestamp: formatIsoUtc(new Date(lastModified)),
      sourceFile: fileName,
      sourceLocation: `${fileName} > Carved Binary Stream`,
      description: 'Configured Windows time zone name recovered from registry stream',
      value: carvedTz,
      details: {
        'Time Zone': carvedTz,
        'Carved Source': fileName,
      },
      isSuspicious: false,
      rawText: `TimeZoneKeyName: ${carvedTz}`,
    });
  }

  // 3. Carve ProductType / Role
  const carvedProdType = carveStringNearKeyword(buf, 'ProductType', 80);
  if (carvedProdType && /^(WinNT|ServerNT|LanmanNT)$/i.test(carvedProdType) && !artifacts.some((a) => a.name.includes('OS Role'))) {
    let roleDesc = 'Windows Workstation (WinNT)';
    if (carvedProdType.toLowerCase() === 'servernt') roleDesc = 'Windows Server (ServerNT)';
    if (carvedProdType.toLowerCase() === 'lanmannt') roleDesc = 'Windows Domain Controller (LanmanNT)';

    artifacts.push({
      id: `art-sys-carved-prod-${crypto.randomUUID().slice(0, 8)}`,
      category: 'system_info',
      name: `OS Role: ${roleDesc}`,
      timestamp: formatIsoUtc(new Date(lastModified)),
      sourceFile: fileName,
      sourceLocation: `${fileName} > Carved Binary Stream`,
      description: `Operating system role carved from ProductType: ${carvedProdType}`,
      value: roleDesc,
      details: {
        'Product Type': carvedProdType,
        'Role Description': roleDesc,
      },
      isSuspicious: false,
      rawText: `ProductType: ${carvedProdType}`,
    });
  }

  // 4. Carve USBSTOR devices
  const usbRegex = /USBSTOR\\([A-Za-z0-9&_]+)\\([A-Za-z0-9&_]+)/gi;
  let uMatch;
  let uCount = 0;
  while ((uMatch = usbRegex.exec(text)) !== null && uCount < maxCarved) {
    uCount++;
    const dev = uMatch[1];
    const serial = uMatch[2];
    if (!artifacts.some((a) => a.rawText?.includes(dev))) {
      artifacts.push({
        id: `art-usb-carved-${uCount}-${crypto.randomUUID().slice(0, 6)}`,
        category: 'usb_connect',
        name: `USB Storage: ${dev}`,
        timestamp: formatIsoUtc(new Date(lastModified)),
        sourceFile: fileName,
        sourceLocation: `${fileName} > Carved Cell Offset 0x${uMatch.index.toString(16)}`,
        description: 'USB mass storage device identifier carved from registry stream',
        value: `${dev} (S/N: ${serial})`,
        details: {
          'Device Descriptor': dev,
          'Serial Number': serial,
          'Offset': `0x${uMatch.index.toString(16)}`,
        },
        isSuspicious: false,
        rawText: uMatch[0],
      });
    }
  }
}

/**
 * Parses all Named Keys (nk) and Value Keys (vk) from registry hive bins (hbin)
 */
function parseAllHiveKeysAndValues(
  buf: Buffer,
  fileName: string,
  lastModified: number
): Map<string, RegistryKeyNode> {
  const keysMap = new Map<string, RegistryKeyNode>();
  if (buf.length < 4096) return keysMap;

  // The first hbin starts at 4096 (0x1000)
  let offset = 4096;
  const hbinMagic = 'hbin';

  // Step 1: Discover all 'nk' cells and 'vk' cells across all hbins
  interface RawNkCell {
    offset: number;
    name: string;
    lastWritten: string;
    parentOffset: number;
    subkeysCount: number;
    subkeyListOffset: number;
    valuesCount: number;
    valuesListOffset: number;
  }

  interface RawVkCell {
    offset: number;
    name: string;
    type: number;
    data: string | number | Buffer | string[];
    rawBytes?: Buffer;
  }

  const nkByOffset = new Map<number, RawNkCell>();
  const vkByOffset = new Map<number, RawVkCell>();

  while (offset + 32 <= buf.length) {
    const magic = buf.subarray(offset, offset + 4).toString('ascii');
    if (magic !== hbinMagic) {
      // Advance to next 4KB boundary
      offset += 4096;
      continue;
    }

    const hbinSize = buf.readUInt32LE(offset + 8);
    if (hbinSize < 32 || offset + hbinSize > buf.length) {
      offset += 4096;
      continue;
    }

    // Iterate cells inside this hbin
    let cellOffset = offset + 32;
    const hbinEnd = offset + hbinSize;

    while (cellOffset + 4 < hbinEnd) {
      const rawCellSize = buf.readInt32LE(cellOffset);
      const cellSize = Math.abs(rawCellSize);
      if (cellSize < 4 || cellOffset + cellSize > hbinEnd) {
        break;
      }

      // Check signature at cellOffset + 4
      if (cellOffset + 6 <= hbinEnd) {
        const sig = buf.subarray(cellOffset + 4, cellOffset + 6).toString('ascii');

        // Named Key cell: 'nk'
        if (sig === 'nk' && cellSize >= 76) {
          try {
            const flags = buf.readUInt16LE(cellOffset + 6);
            const fileTime = buf.readBigUInt64LE(cellOffset + 8);
            const parentOffset = buf.readUInt32LE(cellOffset + 20);
            const subkeysCount = buf.readUInt32LE(cellOffset + 24);
            const subkeyListOffset = buf.readUInt32LE(cellOffset + 32);
            const valuesCount = buf.readUInt32LE(cellOffset + 40);
            const valuesListOffset = buf.readUInt32LE(cellOffset + 44);
            const nameLen = buf.readUInt16LE(cellOffset + 76);

            let keyName = '';
            if (nameLen > 0 && cellOffset + 80 + nameLen <= buf.length) {
              const nameBuf = buf.subarray(cellOffset + 80, cellOffset + 80 + nameLen);
              // If flags & 0x20 is set, name is ASCII; otherwise UTF-16LE or ASCII fallback
              if ((flags & 0x20) !== 0) {
                keyName = nameBuf.toString('ascii');
              } else {
                keyName = nameBuf.toString('utf16le');
                if (keyName.includes('\x00') || !/^[\w\-_. $\\{}()]+$/.test(keyName)) {
                  keyName = nameBuf.toString('ascii');
                }
              }
            }

            // Cell offset relative to hive bins start (offset 4096)
            const relOffset = cellOffset - 4096;
            const lastWritten = formatIsoUtc(fileTimeToDate(fileTime));

            nkByOffset.set(relOffset, {
              offset: relOffset,
              name: keyName || 'Key',
              lastWritten,
              parentOffset,
              subkeysCount,
              subkeyListOffset,
              valuesCount,
              valuesListOffset,
            });
          } catch {
            // Skip corrupted cell
          }
        }

        // Value Key cell: 'vk'
        else if (sig === 'vk' && cellSize >= 20) {
          try {
            const nameLen = buf.readUInt16LE(cellOffset + 6);
            const dataLenRaw = buf.readUInt32LE(cellOffset + 8);
            const dataOffsetRaw = buf.readUInt32LE(cellOffset + 12);
            const valType = buf.readUInt32LE(cellOffset + 16);
            const flags = buf.readUInt16LE(cellOffset + 20);

            // Extract value name
            let valName = '(Default)';
            if (nameLen > 0 && cellOffset + 24 + nameLen <= buf.length) {
              const nameBuf = buf.subarray(cellOffset + 24, cellOffset + 24 + nameLen);
              valName = (flags & 0x01) ? nameBuf.toString('ascii') : nameBuf.toString('utf16le');
              if (valName.includes('\x00')) {
                valName = nameBuf.toString('ascii').replace(/\x00/g, '');
              }
            }

            // Extract value data
            // If high bit 0x80000000 of dataLenRaw is set, data is stored inline in dataOffsetRaw!
            const isInline = (dataLenRaw & 0x80000000) !== 0;
            const dataLen = dataLenRaw & 0x7fffffff;
            let valData: string | number | Buffer | string[] = '';
            let valRawBytes: Buffer | undefined;

            if (isInline) {
              // 4 bytes inline data at cellOffset + 12
              const inlineBuf = buf.subarray(cellOffset + 12, cellOffset + 12 + Math.min(dataLen, 4));
              valRawBytes = inlineBuf;
              if (valType === 4) {
                // REG_DWORD
                valData = inlineBuf.readUInt32LE(0);
              } else {
                valData = inlineBuf.toString('ascii').replace(/\x00/g, '');
              }
            } else if (dataOffsetRaw > 0 && 4096 + dataOffsetRaw < buf.length) {
              const absDataOffset = 4096 + dataOffsetRaw;
              // Data cell has 4-byte size header
              const dataCellSize = Math.abs(buf.readInt32LE(absDataOffset));
              const actualLen = Math.min(dataLen, dataCellSize - 4, 65536);
              if (actualLen > 0 && absDataOffset + 4 + actualLen <= buf.length) {
                valRawBytes = buf.subarray(absDataOffset + 4, absDataOffset + 4 + actualLen);

                if (valType === 1 || valType === 2) {
                  // REG_SZ or REG_EXPAND_SZ (UTF-16LE)
                  const str = valRawBytes.toString('utf16le');
                  valData = str.replace(/\x00+$/, '');
                } else if (valType === 4) {
                  // REG_DWORD
                  valData = valRawBytes.length >= 4 ? valRawBytes.readUInt32LE(0) : 0;
                } else if (valType === 11) {
                  // REG_QWORD
                  valData = valRawBytes.length >= 8 ? String(valRawBytes.readBigUInt64LE(0)) : '0';
                } else if (valType === 7) {
                  // REG_MULTI_SZ
                  const str = valRawBytes.toString('utf16le');
                  valData = str.split('\x00').filter((s) => s.length > 0);
                } else {
                  // REG_BINARY or other
                  valData = valRawBytes.toString('hex').slice(0, 100);
                }
              }
            }

            const relOffset = cellOffset - 4096;
            vkByOffset.set(relOffset, {
              offset: relOffset,
              name: valName,
              type: valType,
              data: valData,
              rawBytes: valRawBytes,
            });
          } catch {
            // Skip corrupted cell
          }
        }
      }

      cellOffset += cellSize;
    }

    offset += hbinSize;
  }

  // Step 2: Build parent-child path hierarchy
  // Helper to build path recursively
  const pathCache = new Map<number, string>();
  function resolvePath(nk: RawNkCell, depth = 0): string {
    if (depth > 20) return nk.name;
    if (pathCache.has(nk.offset)) return pathCache.get(nk.offset)!;

    const parent = nkByOffset.get(nk.parentOffset);
    let fullPath = nk.name;
    if (parent && parent.offset !== nk.offset && parent.name && parent.name !== nk.name) {
      const parentPath = resolvePath(parent, depth + 1);
      fullPath = `${parentPath}\\${nk.name}`;
    }

    pathCache.set(nk.offset, fullPath);
    return fullPath;
  }

  // Step 3: Populate keysMap with resolved values and subkeys
  for (const nk of nkByOffset.values()) {
    const fullPath = resolvePath(nk);
    const values: Record<string, RegistryValue> = {};

    // Resolve values list for this nk
    if (nk.valuesCount > 0 && nk.valuesListOffset > 0) {
      const absValListOffset = 4096 + nk.valuesListOffset;
      if (absValListOffset + 4 <= buf.length) {
        const valListCellSize = Math.abs(buf.readInt32LE(absValListOffset));
        const maxVals = Math.min(nk.valuesCount, Math.floor((valListCellSize - 4) / 4), 256);

        for (let i = 0; i < maxVals; i++) {
          const entryOffset = absValListOffset + 4 + i * 4;
          if (entryOffset + 4 <= buf.length) {
            const vkRelOffset = buf.readUInt32LE(entryOffset);
            const vk = vkByOffset.get(vkRelOffset);
            if (vk) {
              values[vk.name] = {
                name: vk.name,
                type: vk.type,
                typeName: REG_TYPES[vk.type] || `REG_${vk.type}`,
                data: vk.data,
                rawBytes: vk.rawBytes,
              };
            }
          }
        }
      }
    }

    const node: RegistryKeyNode = {
      name: nk.name,
      path: fullPath,
      lastWritten: nk.lastWritten,
      values,
      subkeys: [],
    };

    keysMap.set(fullPath.toLowerCase(), node);
    if (!keysMap.has(nk.name.toLowerCase())) {
      keysMap.set(nk.name.toLowerCase(), node);
    }
  }

  return keysMap;
}

/**
 * Finds a single key matching a regex in the keys map
 */
function findKey(keysMap: Map<string, RegistryKeyNode>, regex: RegExp): RegistryKeyNode | undefined {
  for (const [pathLower, node] of keysMap.entries()) {
    if (regex.test(pathLower) || regex.test(node.path) || regex.test(node.name)) {
      return node;
    }
  }
  return undefined;
}

/**
 * Finds all keys matching a regex in the keys map
 */
function findKeyMatches(keysMap: Map<string, RegistryKeyNode>, regex: RegExp): RegistryKeyNode[] {
  const matches: RegistryKeyNode[] = [];
  const seenPaths = new Set<string>();
  for (const [pathLower, node] of keysMap.entries()) {
    if (regex.test(pathLower) || regex.test(node.path) || regex.test(node.name)) {
      if (!seenPaths.has(node.path)) {
        seenPaths.add(node.path);
        matches.push(node);
      }
    }
  }
  return matches;
}
