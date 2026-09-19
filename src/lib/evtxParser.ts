/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { Buffer } from 'buffer';
import { parseEvtxFile } from 'winevtx';
import { ForensicArtifact, WindowsEventData } from '../types';

export const KNOWN_EVENT_IDS: Record<
  number,
  {
    name: string;
    level: 'Information' | 'Warning' | 'Error' | 'Critical';
    suspicious?: boolean;
    reason?: string;
  }
> = {
  4624: { name: 'Successful User Logon', level: 'Information' },
  4625: {
    name: 'An Account Failed to Log On (Logon Failure)',
    level: 'Warning',
    suspicious: true,
    reason: 'Failed authentication attempt - potential brute-force or credential spray indicator',
  },
  4634: { name: 'An Account was Logged Off', level: 'Information' },
  4648: {
    name: 'A Logon was Attempted Using Explicit Credentials',
    level: 'Warning',
    suspicious: true,
    reason: 'Explicit credential usage (runas / lateral movement indicator)',
  },
  4672: {
    name: 'Special Privileges Assigned to New Logon',
    level: 'Information',
    suspicious: false,
  },
  4688: { name: 'A New Process has been Created', level: 'Information' },
  4697: {
    name: 'A Service was Installed in the System',
    level: 'Warning',
    suspicious: true,
    reason: 'New Windows service registered - potential persistence mechanism',
  },
  4698: {
    name: 'A Scheduled Task was Created',
    level: 'Warning',
    suspicious: true,
    reason: 'Scheduled task created - persistence or lateral execution indicator',
  },
  4702: { name: 'A Scheduled Task was Updated', level: 'Information' },
  7045: {
    name: 'A New Service was Installed (System)',
    level: 'Warning',
    suspicious: true,
    reason: 'Service Control Manager installed new system service',
  },
  1102: {
    name: 'The Audit Log was Cleared',
    level: 'Critical',
    suspicious: true,
    reason: 'CRITICAL: Security audit event log cleared to conceal malicious activities',
  },
  104: {
    name: 'System Event Log was Cleared',
    level: 'Critical',
    suspicious: true,
    reason: 'CRITICAL: System event log cleared to conceal malicious activities',
  },
  4720: {
    name: 'A User Account was Created',
    level: 'Warning',
    suspicious: true,
    reason: 'New local or domain user account provisioned on host',
  },
  4728: {
    name: 'A Member was Added to a Security-Enabled Global Group',
    level: 'Warning',
    suspicious: true,
    reason: 'User added to privileged security group (e.g. Domain Admins)',
  },
  4732: {
    name: 'A Member was Added to a Security-Enabled Local Group',
    level: 'Warning',
    suspicious: true,
    reason: 'User added to local Administrators group',
  },
  4738: { name: 'A User Account was Modified', level: 'Information' },
  4776: { name: 'Domain Controller Attempted to Validate Credentials', level: 'Information' },
  4104: {
    name: 'PowerShell Script Block Logging Executed',
    level: 'Warning',
    suspicious: false,
  },
  4103: { name: 'PowerShell Module Logging Executed', level: 'Information' },
  1074: { name: 'System Shutdown or Restart Initiated', level: 'Information' },
  6005: { name: 'The Event Log Service was Started', level: 'Information' },
  6006: { name: 'The Event Log Service was Stopped', level: 'Warning' },
  800: { name: 'PowerShell Pipeline Execution Details', level: 'Information' },
};

function formatIsoUtc(date: Date): string {
  return date.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
}

function extractStringVal(val: unknown): string {
  if (val === null || val === undefined) return '';
  if (typeof val === 'string') return val;
  if (typeof val === 'number' || typeof val === 'boolean' || typeof val === 'bigint') {
    return String(val);
  }
  if (typeof val === 'object') {
    const obj = val as Record<string, unknown>;
    if (obj['#text'] !== undefined) return extractStringVal(obj['#text']);
    if (obj.Value !== undefined) return extractStringVal(obj.Value);
    if (obj.text !== undefined) return extractStringVal(obj.text);
    return JSON.stringify(val);
  }
  return String(val);
}

function extractEventId(val: unknown): number {
  if (typeof val === 'number') return val;
  if (typeof val === 'string') {
    const parsed = parseInt(val, 10);
    return isNaN(parsed) ? 0 : parsed;
  }
  if (typeof val === 'object' && val !== null) {
    const obj = val as Record<string, unknown>;
    return (
      extractEventId(obj['#text']) ||
      extractEventId(obj.Value) ||
      extractEventId(obj.text) ||
      0
    );
  }
  return 0;
}

/**
 * Checks command line or script block for threat signatures
 */
function analyzeCommandLineThreats(commandLine?: string): {
  isSuspicious: boolean;
  suspiciousReason?: string;
} {
  if (!commandLine) return { isSuspicious: false };
  const cmd = commandLine.toLowerCase();

  if (
    /powershell.*(-enc|-encodedcommand|bypass|-w\s*hidden|downloadstring|iex|invoke-expression|frombase64string)/i.test(
      cmd
    )
  ) {
    return {
      isSuspicious: true,
      suspiciousReason: 'Obfuscated PowerShell execution detected with bypass/encoded switches',
    };
  }
  if (
    /mimikatz|sekurlsa|kerberos::|lsadump|certutil.*-urlcache|vssadmin.*delete\s*shadows|wbadmin.*delete|bcdedit.*recoveryenabled\s*no/i.test(
      cmd
    )
  ) {
    return {
      isSuspicious: true,
      suspiciousReason: 'Known credential dumping, shadow copy deletion, or ransomware defense evasion detected',
    };
  }
  if (/whoami\s*\/priv|net\s*user\s+.*\/add|net\s*localgroup\s+administrators\s+.*\/add/i.test(cmd)) {
    return {
      isSuspicious: true,
      suspiciousReason: 'Privilege inspection or unauthorized administrative account provisioning detected',
    };
  }
  if (/rundll32.*(advpack|mshtml|shell32)|regsvr32.*\/s.*\/u.*scrobj/i.test(cmd)) {
    return {
      isSuspicious: true,
      suspiciousReason: 'Living-off-the-land binary (LOLBin) proxy execution detected',
    };
  }

  return { isSuspicious: false };
}

/**
 * Parses binary EVTX records from ArrayBuffer
 */
export async function parseEvtxBinary(
  arrayBuffer: ArrayBuffer,
  fileName: string,
  lastModified: number
): Promise<ForensicArtifact[]> {
  const results: ForensicArtifact[] = [];
  const buf = Buffer.from(arrayBuffer);

  // If buffer doesn't have standard 4096-byte header or ElfFile\0 magic, attempt carving or XML/text fallback
  if (buf.length < 4096 || buf.subarray(0, 8).toString('ascii') !== 'ElfFile\0') {
    const carved = carveEvtxRecordsFromBuffer(buf, fileName, lastModified);
    if (carved.length > 0) return carved;
    return parseEvtxTextOrXml(buf.toString('utf-8'), fileName, lastModified);
  }

  let recordCount = 0;
  const maxRecords = 200; // Return up to 200 records for fast responsiveness

  try {
    const generator = parseEvtxFile(buf);
    for (const rec of generator) {
      if (recordCount >= maxRecords) break;
      recordCount++;

      const eventObj = (rec.event as Record<string, unknown>) || {};
      const rootEvent = (eventObj.Event || eventObj) as Record<string, unknown>;
      const system = (rootEvent.System || {}) as Record<string, unknown>;
      const eventDataNode = (rootEvent.EventData ||
        rootEvent.UserData ||
        {}) as Record<string, unknown>;

      // Extract EventID
      const eventId = extractEventId(system.EventID);

      // Extract Provider
      let provider = 'Microsoft-Windows-Security-Auditing';
      if (system.Provider) {
        if (typeof system.Provider === 'string') {
          provider = system.Provider;
        } else if (typeof system.Provider === 'object') {
          const provObj = system.Provider as Record<string, unknown>;
          provider = extractStringVal(provObj.Name || provObj.name || provObj['#text'] || provider);
        }
      }

      // Extract Channel
      const channel = extractStringVal(system.Channel) || 'Security';

      // Extract Level
      const rawLevel = system.Level;
      let level: WindowsEventData['level'] = 'Information';
      const levelNum = typeof rawLevel === 'number' ? rawLevel : parseInt(String(rawLevel), 10);
      if (levelNum === 1) level = 'Critical';
      else if (levelNum === 2) level = 'Error';
      else if (levelNum === 3) level = 'Warning';
      else if (levelNum === 4 || levelNum === 0) level = 'Information';

      // Extract Computer
      const computer = extractStringVal(system.Computer) || 'WINDOWS-HOST';

      // Extract Timestamp
      let timestamp = formatIsoUtc(new Date(lastModified));
      if (typeof rec.timestamp === 'number' && !isNaN(rec.timestamp) && rec.timestamp > 0) {
        timestamp = formatIsoUtc(new Date(rec.timestamp * 1000));
      } else if (system.TimeCreated) {
        const timeObj = system.TimeCreated as Record<string, unknown>;
        const sysTime = extractStringVal(timeObj.SystemTime || timeObj.systemTime);
        if (sysTime) {
          try {
            timestamp = formatIsoUtc(new Date(sysTime));
          } catch {
            timestamp = sysTime;
          }
        }
      }

      // Extract Security User SID
      let userSid: string | undefined;
      if (system.Security && typeof system.Security === 'object') {
        const secObj = system.Security as Record<string, unknown>;
        userSid = extractStringVal(secObj.UserID || secObj.UserId || secObj.user_id) || undefined;
      }

      // Collect EventData key-value pairs
      const dataMap: Record<string, string> = {};
      if (eventDataNode.Data) {
        const dataVal = eventDataNode.Data;
        if (Array.isArray(dataVal)) {
          dataVal.forEach((item, idx) => {
            if (item && typeof item === 'object') {
              const itemObj = item as Record<string, unknown>;
              const name = extractStringVal(itemObj.Name || itemObj.name || `Data_${idx}`);
              const val = extractStringVal(itemObj.Value || itemObj['#text'] || itemObj.text || item);
              if (name) dataMap[name] = val;
            } else {
              dataMap[`Data_${idx}`] = extractStringVal(item);
            }
          });
        } else if (typeof dataVal === 'object') {
          for (const [k, v] of Object.entries(dataVal as Record<string, unknown>)) {
            dataMap[k] = extractStringVal(v);
          }
        } else {
          dataMap['Data'] = extractStringVal(dataVal);
        }
      } else {
        // Flat properties in eventDataNode
        for (const [k, v] of Object.entries(eventDataNode)) {
          dataMap[k] = extractStringVal(v);
        }
      }

      // Extract user, process, command line, IP from dataMap
      const user =
        dataMap.TargetUserName ||
        dataMap.SubjectUserName ||
        dataMap.UserName ||
        dataMap.User ||
        dataMap.AccountName ||
        undefined;

      const processPath =
        dataMap.NewProcessName ||
        dataMap.ProcessName ||
        dataMap.Image ||
        dataMap.Application ||
        undefined;

      const processName = processPath ? processPath.split('\\').pop() : undefined;

      const commandLine =
        dataMap.CommandLine ||
        dataMap.ScriptBlockText ||
        dataMap.Path ||
        undefined;

      const ipAddress =
        dataMap.IpAddress ||
        dataMap.SourceAddress ||
        dataMap.WorkstationName ||
        undefined;

      const taskCategory = extractStringVal(system.Task) || undefined;

      // Metadata lookup
      const known = KNOWN_EVENT_IDS[eventId];
      let isSuspicious = Boolean(known?.suspicious);
      let suspiciousReason = known?.reason;

      // Analyze command line threats
      const cmdThreat = analyzeCommandLineThreats(commandLine);
      if (cmdThreat.isSuspicious) {
        isSuspicious = true;
        suspiciousReason = cmdThreat.suspiciousReason;
      }

      if (eventId === 4625) {
        isSuspicious = true;
        suspiciousReason = `Failed authentication for account ${user || 'Unknown'} from IP ${ipAddress || 'Host'}`;
      } else if (eventId === 1102 || eventId === 104) {
        isSuspicious = true;
        suspiciousReason = 'CRITICAL: Security/System event log audit clear operation performed';
      }

      const eventName = known
        ? `Event ${eventId}: ${known.name}`
        : `Event ${eventId} [${channel}]`;
      const description = known
        ? known.name
        : `Windows Event Log ID ${eventId} recorded in ${channel}`;

      const winEventData: WindowsEventData = {
        eventId,
        provider,
        channel,
        level: isSuspicious ? (eventId === 1102 ? 'Critical' : 'Warning') : level,
        computer,
        user,
        userSid,
        accountName: user,
        recordId: rec.recordID,
        processName,
        processPath,
        commandLine,
        ipAddress: ipAddress !== '-' ? ipAddress : undefined,
        taskCategory,
        description,
      };

      const displayValue = commandLine
        ? `${processName || 'Process'}: ${commandLine.slice(0, 100)}`
        : user
        ? `User: ${user} on ${computer}`
        : `Event ID ${eventId} [${channel}]`;

      results.push({
        id: `art-evtx-${rec.recordID || recordCount}-${crypto.randomUUID().slice(0, 6)}`,
        category: 'windows_events',
        name: eventName,
        timestamp,
        sourceFile: fileName,
        sourceLocation: `${fileName} > Record #${rec.recordID || recordCount} (${channel})`,
        description,
        value: displayValue,
        details: {
          'Event ID': eventId,
          'Record ID': rec.recordID,
          'Channel / Log': channel,
          'Provider': provider,
          'Event Level': winEventData.level,
          'Computer Host': computer,
          ...(user ? { 'Account User': user } : {}),
          ...(userSid ? { 'User SID': userSid } : {}),
          ...(ipAddress ? { 'Network Source IP': ipAddress } : {}),
          ...(processName ? { 'Process Name': processName } : {}),
          ...(processPath ? { 'Process Path': processPath } : {}),
          ...(commandLine ? { 'Executed Command Line': commandLine.slice(0, 250) } : {}),
        },
        isSuspicious,
        suspiciousReason,
        rawText: JSON.stringify(eventObj, null, 2).slice(0, 1500),
        eventData: winEventData,
      });
    }
  } catch (err) {
    console.warn('winevtx parseEvtxFile threw an error; falling back to chunk scanner:', err);
  }

  // Fallback: If 0 records parsed (e.g. dirty chunks or corrupted header), scan chunk records directly
  if (results.length === 0) {
    const carvedResults = carveEvtxRecordsFromBuffer(buf, fileName, lastModified);
    results.push(...carvedResults);
  }

  return results;
}

/**
 * Fallback carver that directly scans EVTX chunks for record magic \x2a\x2a\x00\x00
 */
function carveEvtxRecordsFromBuffer(
  buf: Buffer,
  fileName: string,
  lastModified: number
): ForensicArtifact[] {
  const carved: ForensicArtifact[] = [];
  const maxCarved = 60;
  let offset = buf.length >= 4096 ? 4096 : 0; // start at chunk 0 or file start

  while (offset + 24 < buf.length && carved.length < maxCarved) {
    // Look for record header magic: 0x2A 0x2A 0x00 0x00
    if (
      buf[offset] === 0x2a &&
      buf[offset + 1] === 0x2a &&
      buf[offset + 2] === 0x00 &&
      buf[offset + 3] === 0x00
    ) {
      try {
        const size = buf.readUInt32LE(offset + 4);
        const recordID = Number(buf.readBigUInt64LE(offset + 8));
        const fileTime = buf.readBigUInt64LE(offset + 16);

        if (size >= 24 && size <= 65536 && offset + size <= buf.length) {
          // Extract UTF-16LE strings from this record slice
          const recSlice = buf.subarray(offset + 24, offset + size);
          const strings = extractUtf16Strings(recSlice);

          // Find Event ID if present in strings or common offsets
          let eventId = 0;
          let computer = 'INVESTIGATION-HOST';
          let channel = 'Security';
          let provider = 'Microsoft-Windows-Security-Auditing';
          let user: string | undefined;
          let commandLine: string | undefined;

          for (const s of strings) {
            const num = parseInt(s, 10);
            if (!eventId && !isNaN(num) && num > 100 && num < 100000) {
              eventId = num;
            } else if (s.includes('Microsoft-Windows') || s.includes('Service Control Manager')) {
              provider = s;
            } else if (s === 'Security' || s === 'System' || s === 'Application' || s.includes('PowerShell')) {
              channel = s;
            } else if (s.includes('.') && s.length < 40 && !s.includes(' ')) {
              computer = s;
            } else if (s.toLowerCase().includes('powershell') || s.toLowerCase().includes('cmd.exe')) {
              commandLine = s;
            } else if (!user && s.length > 2 && s.length < 30 && !s.includes(':') && !s.includes('\\')) {
              user = s;
            }
          }

          if (eventId > 0 || strings.length >= 3) {
            // Calculate timestamp from fileTime
            let timestamp = formatIsoUtc(new Date(lastModified));
            if (fileTime > 116444736000000000n) {
              const unixMs = Number((fileTime - 116444736000000000n) / 10000n);
              if (unixMs > 0 && unixMs < 2500000000000) {
                timestamp = formatIsoUtc(new Date(unixMs));
              }
            }

            const known = KNOWN_EVENT_IDS[eventId];
            const cmdThreat = analyzeCommandLineThreats(commandLine);
            const isSuspicious = Boolean(known?.suspicious) || cmdThreat.isSuspicious;

            const winEventData: WindowsEventData = {
              eventId: eventId || 4624,
              provider,
              channel,
              level: isSuspicious ? 'Warning' : 'Information',
              computer,
              user,
              recordId: recordID,
              commandLine,
              description: known?.name || `Windows Event Record #${recordID} carved from EVTX binary stream`,
            };

            carved.push({
              id: `art-evtx-carved-${recordID || offset}-${crypto.randomUUID().slice(0, 6)}`,
              category: 'windows_events',
              name: known ? `Event ${eventId}: ${known.name}` : `Event ID ${eventId || 'Carved'} [${channel}]`,
              timestamp,
              sourceFile: fileName,
              sourceLocation: `${fileName} > Offset 0x${offset.toString(16).toUpperCase()}`,
              description: winEventData.description,
              value: commandLine || (user ? `User: ${user} on ${computer}` : `Record #${recordID}`),
              details: {
                'Event ID': eventId || 'Unresolved',
                'Record ID': recordID,
                'Offset': `0x${offset.toString(16).toUpperCase()}`,
                'Channel': channel,
                'Provider': provider,
                'Computer': computer,
                ...(user ? { 'Account User': user } : {}),
                ...(commandLine ? { 'Command Line': commandLine.slice(0, 200) } : {}),
              },
              isSuspicious,
              suspiciousReason: known?.reason || cmdThreat.suspiciousReason,
              rawText: strings.join(' | ').slice(0, 800),
              eventData: winEventData,
            });

            offset += size;
            continue;
          }
        }
      } catch {
        // Continue scan
      }
    }
    offset += 4;
  }

  if (carved.length === 0) {
    const text = buf.toString('utf-8');
    if (text.includes('<Event') || /Event\s*ID/i.test(text)) {
      return parseEvtxTextOrXml(text, fileName, lastModified);
    }
  }

  return carved;
}

/**
 * Extracts printable UTF-16LE strings from a binary buffer
 */
function extractUtf16Strings(buf: Buffer, minLen = 3): string[] {
  const strings: string[] = [];
  let current: number[] = [];

  for (let i = 0; i + 1 < buf.length; i += 2) {
    const code = buf.readUInt16LE(i);
    // Printable ASCII or typical Unicode characters
    if (code >= 32 && code <= 126) {
      current.push(code);
    } else {
      if (current.length >= minLen) {
        strings.push(String.fromCharCode(...current));
      }
      current = [];
    }
  }
  if (current.length >= minLen) {
    strings.push(String.fromCharCode(...current));
  }

  return strings;
}

/**
 * Parses XML or text-based Windows Event logs (exports from Event Viewer or wevtutil)
 */
export function parseEvtxTextOrXml(
  textContent: string,
  fileName: string,
  lastModified: number
): ForensicArtifact[] {
  const results: ForensicArtifact[] = [];

  // 1. XML Event tags: <Event>...</Event>
  const eventXmlRegex = /<Event\b[^>]*>([\s\S]*?)<\/Event>/gi;
  let eventXmlMatch;
  let xmlCount = 0;

  while ((eventXmlMatch = eventXmlRegex.exec(textContent)) !== null && xmlCount < 60) {
    xmlCount++;
    const block = eventXmlMatch[1];

    const idMatch = /<EventID(?:\s+Qualifier="[^"]*")?>(\d+)<\/EventID>/i.exec(block);
    const eventId = idMatch ? parseInt(idMatch[1], 10) : 0;

    const provMatch = /<Provider\s+Name="([^"]+)"/i.exec(block);
    const provider = provMatch ? provMatch[1] : 'Microsoft-Windows-Security-Auditing';

    const chanMatch = /<Channel>([^<]+)<\/Channel>/i.exec(block);
    const channel = chanMatch ? chanMatch[1] : 'Security';

    const levelMatch = /<Level>(\d+)<\/Level>/i.exec(block);
    let level: WindowsEventData['level'] = 'Information';
    if (levelMatch) {
      const lNum = parseInt(levelMatch[1], 10);
      if (lNum === 1) level = 'Critical';
      else if (lNum === 2) level = 'Error';
      else if (lNum === 3) level = 'Warning';
    }

    const compMatch = /<Computer>([^<]+)<\/Computer>/i.exec(block);
    const computer = compMatch ? compMatch[1] : 'INVESTIGATION-HOST';

    const timeMatch = /<TimeCreated\s+SystemTime="([^"]+)"/i.exec(block);
    let timestamp = formatIsoUtc(new Date(lastModified));
    if (timeMatch) {
      try {
        timestamp = formatIsoUtc(new Date(timeMatch[1]));
      } catch {
        timestamp = timeMatch[1].replace('T', ' ').slice(0, 19) + ' UTC';
      }
    }

    const userMatch = /<Data\s+Name="(?:TargetUserName|SubjectUserName|UserName|User)">([^<]+)<\/Data>/i.exec(block);
    const user = userMatch ? userMatch[1] : undefined;

    const userSidMatch = /<Data\s+Name="(?:TargetUserSid|SubjectUserSid|UserSid)">([^<]+)<\/Data>/i.exec(block);
    const userSid = userSidMatch ? userSidMatch[1] : undefined;

    const procMatch = /<Data\s+Name="(?:NewProcessName|ProcessName|Image)">([^<]+)<\/Data>/i.exec(block);
    const processPath = procMatch ? procMatch[1] : undefined;
    const processName = processPath ? processPath.split('\\').pop() : undefined;

    const cmdMatch = /<Data\s+Name="(?:CommandLine|ScriptBlockText)">([\s\S]*?)<\/Data>/i.exec(block);
    const commandLine = cmdMatch ? cmdMatch[1] : undefined;

    const ipMatch = /<Data\s+Name="(?:IpAddress|WorkstationName|SourceAddress)">([^<]+)<\/Data>/i.exec(block);
    const ipAddress = ipMatch && ipMatch[1] !== '-' ? ipMatch[1] : undefined;

    const known = KNOWN_EVENT_IDS[eventId];
    let isSuspicious = Boolean(known?.suspicious);
    let suspiciousReason = known?.reason;

    const cmdThreat = analyzeCommandLineThreats(commandLine);
    if (cmdThreat.isSuspicious) {
      isSuspicious = true;
      suspiciousReason = cmdThreat.suspiciousReason;
    }

    const winEventData: WindowsEventData = {
      eventId,
      provider,
      channel,
      level: isSuspicious ? (eventId === 1102 ? 'Critical' : 'Warning') : level,
      computer,
      user,
      userSid,
      accountName: user,
      recordId: xmlCount,
      processName,
      processPath,
      commandLine,
      ipAddress,
      description: known?.name || `Windows Event ID ${eventId} recorded in ${channel}`,
    };

    results.push({
      id: `art-evt-xml-${xmlCount}-${crypto.randomUUID().slice(0, 6)}`,
      category: 'windows_events',
      name: known ? `Event ${eventId}: ${known.name}` : `Event ${eventId} [${channel}]`,
      timestamp,
      sourceFile: fileName,
      sourceLocation: `${fileName} > XML Record #${xmlCount} (${channel})`,
      description: winEventData.description,
      value: commandLine
        ? `${processName || 'Process'}: ${commandLine.slice(0, 100)}`
        : user
        ? `User: ${user} on ${computer}`
        : `Event ID ${eventId} [${channel}]`,
      details: {
        'Event ID': eventId,
        'Channel / Log': channel,
        'Provider': provider,
        'Event Level': winEventData.level,
        'Target Computer': computer,
        ...(user ? { 'Account User': user } : {}),
        ...(userSid ? { 'User SID': userSid } : {}),
        ...(ipAddress ? { 'Network Source IP': ipAddress } : {}),
        ...(processName ? { 'Process Name': processName } : {}),
        ...(processPath ? { 'Process Path': processPath } : {}),
        ...(commandLine ? { 'Executed Command Line': commandLine.slice(0, 200) } : {}),
      },
      isSuspicious,
      suspiciousReason,
      rawText: block.slice(0, 1200),
      eventData: winEventData,
    });
  }

  // 2. Text exports: Event ID: 4624 / EventId: ...
  if (results.length === 0) {
    const textEventRegex = /(?:Event\s*ID|EventId)\s*[:=]\s*(\d+)[\s\S]*?(?=(?:Event\s*ID|EventId)\s*[:=]|\Z)/gi;
    let textMatch;
    let textCount = 0;
    while ((textMatch = textEventRegex.exec(textContent)) !== null && textCount < 40) {
      textCount++;
      const snippet = textMatch[0];
      const eventId = parseInt(textMatch[1], 10);
      const known = KNOWN_EVENT_IDS[eventId];

      const userMatch = /(?:Account Name|User Name|User)\s*[:=]\s*([^\r\n]+)/i.exec(snippet);
      const compMatch = /(?:Computer|Computer Name)\s*[:=]\s*([^\r\n]+)/i.exec(snippet);
      const dateMatch = /(?:Date|Time|Timestamp)\s*[:=]\s*([^\r\n]+)/i.exec(snippet);

      let isSusp = Boolean(known?.suspicious) || /failed|privilege|unauthorized|bypass/i.test(snippet);

      const winEventData: WindowsEventData = {
        eventId,
        provider: 'Windows-Event-Audit',
        channel: 'Security',
        level: isSusp ? 'Warning' : 'Information',
        computer: compMatch ? compMatch[1].trim() : 'WORKSTATION-01',
        user: userMatch ? userMatch[1].trim() : undefined,
        recordId: textCount,
        description: known ? known.name : `Windows Event ID ${eventId}`,
      };

      results.push({
        id: `art-evt-txt-${textCount}-${crypto.randomUUID().slice(0, 6)}`,
        category: 'windows_events',
        name: known ? `Event ${eventId}: ${known.name}` : `Event ID ${eventId}`,
        timestamp: dateMatch ? dateMatch[1].trim() : formatIsoUtc(new Date(lastModified)),
        sourceFile: fileName,
        sourceLocation: `${fileName} > Text Event Stream (Record #${textCount})`,
        description: winEventData.description,
        value: snippet.split('\n').slice(0, 3).map((l) => l.trim()).join(' | '),
        details: {
          'Event ID': eventId,
          'Log Type': 'Windows Event Text Stream',
          'Detected Computer': winEventData.computer,
          ...(winEventData.user ? { 'Extracted Account': winEventData.user } : {}),
        },
        isSuspicious: isSusp,
        suspiciousReason: isSusp ? (known?.reason || 'Security log record flags suspicious state') : undefined,
        rawText: snippet.slice(0, 800),
        eventData: winEventData,
      });
    }
  }

  return results;
}
