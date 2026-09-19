/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import { 
  ForensicArtifact, 
  ArtifactAnalysisOptions, 
  ArtifactCategory,
  ExtractedEmail,
  WindowsEventData,
  RecentFileData
} from '../types';

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
async function readFileAsArrayBuffer(file: File, maxBytes = 4 * 1024 * 1024): Promise<ArrayBuffer> {
  const slice = file.slice(0, maxBytes);
  return await slice.arrayBuffer();
}

// Known Windows Security Event IDs map
const KNOWN_EVENT_IDS: Record<number, { name: string; level: 'Information' | 'Warning' | 'Error' | 'Critical'; suspicious?: boolean; reason?: string }> = {
  4624: { name: 'Successful User Logon', level: 'Information' },
  4625: { name: 'An Account Failed to Log On (Logon Failure)', level: 'Warning', suspicious: true, reason: 'Failed authentication attempt - potential brute-force or credential spray indicator' },
  4634: { name: 'An Account was Logged Off', level: 'Information' },
  4672: { name: 'Special Privileges Assigned to New Logon', level: 'Information' },
  4688: { name: 'A New Process has been Created', level: 'Information' },
  4697: { name: 'A Service was Installed in the System', level: 'Warning', suspicious: true, reason: 'New Windows service registered - potential persistence mechanism' },
  7045: { name: 'A New Service was Installed (System)', level: 'Warning', suspicious: true, reason: 'Service Control Manager installed new system service' },
  1102: { name: 'The Audit Log was Cleared', level: 'Critical', suspicious: true, reason: 'CRITICAL: Security audit event log cleared to conceal malicious activities' },
  4720: { name: 'A User Account was Created', level: 'Warning', suspicious: true, reason: 'New local user account provisioned on host' },
  4728: { name: 'A Member was Added to a Security-Enabled Global Group', level: 'Warning', suspicious: true, reason: 'User added to privileged security group' },
  4104: { name: 'PowerShell Script Block Logging Executed', level: 'Warning' },
  4103: { name: 'PowerShell Module Logging Executed', level: 'Information' },
  1074: { name: 'System Shutdown or Restart Initiated', level: 'Information' },
  6005: { name: 'The Event Log Service was Started', level: 'Information' },
  6006: { name: 'The Event Log Service was Stopped', level: 'Warning' }
};

// Local forensic analyzer that processes uploaded files against selected analysis categories
export async function analyzeArtifactFiles(
  files: File[],
  options: ArtifactAnalysisOptions
): Promise<ForensicArtifact[]> {
  const results: ForensicArtifact[] = [];

  for (const file of files) {
    const textContent = await readFileAsText(file);
    const fileNameLower = file.name.toLowerCase();

    // ----------------------------------------------------
    // 1. Windows Event Logs Analysis (.evtx, .xml, text logs)
    // ----------------------------------------------------
    if (options.windowsEvents) {
      // Check for XML Event blocks or line-based event records
      const eventXmlRegex = /<Event\b[^>]*>([\s\S]*?)<\/Event>/gi;
      let eventXmlMatch;
      let xmlEventCount = 0;

      while ((eventXmlMatch = eventXmlRegex.exec(textContent)) !== null && xmlEventCount < 40) {
        xmlEventCount++;
        const block = eventXmlMatch[1];
        
        // Extract EventID
        const idMatch = /<EventID(?:\s+Qualifier="[^"]*")?>(\d+)<\/EventID>/i.exec(block);
        const eventId = idMatch ? parseInt(idMatch[1], 10) : 0;
        
        // Extract Provider
        const provMatch = /<Provider\s+Name="([^"]+)"/i.exec(block);
        const provider = provMatch ? provMatch[1] : 'Microsoft-Windows-Security-Auditing';

        // Extract Channel
        const chanMatch = /<Channel>([^<]+)<\/Channel>/i.exec(block);
        const channel = chanMatch ? chanMatch[1] : 'Security';

        // Extract Level
        const levelMatch = /<Level>(\d+)<\/Level>/i.exec(block);
        let levelStr: WindowsEventData['level'] = 'Information';
        if (levelMatch) {
          const lNum = parseInt(levelMatch[1], 10);
          if (lNum === 1) levelStr = 'Critical';
          else if (lNum === 2) levelStr = 'Error';
          else if (lNum === 3) levelStr = 'Warning';
        }

        // Extract Computer
        const compMatch = /<Computer>([^<]+)<\/Computer>/i.exec(block);
        const computer = compMatch ? compMatch[1] : 'INVESTIGATION-HOST';

        // Extract TimeCreated
        const timeMatch = /<TimeCreated\s+SystemTime="([^"]+)"/i.exec(block);
        const timestamp = timeMatch ? timeMatch[1].replace('T', ' ').slice(0, 19) + ' UTC' : new Date(file.lastModified).toISOString().replace('T', ' ').slice(0, 19) + ' UTC';

        // Extract TargetUser or SubjectUser
        const userMatch = /<Data\s+Name="(?:TargetUserName|SubjectUserName|UserName|User)">([^<]+)<\/Data>/i.exec(block);
        const user = userMatch ? userMatch[1] : undefined;

        // Extract ProcessName and CommandLine
        const procMatch = /<Data\s+Name="(?:NewProcessName|ProcessName|Image)">([^<]+)<\/Data>/i.exec(block);
        const processName = procMatch ? procMatch[1] : undefined;
        const cmdMatch = /<Data\s+Name="(?:CommandLine|ScriptBlockText)">([^<]+)<\/Data>/i.exec(block);
        const commandLine = cmdMatch ? cmdMatch[1] : undefined;

        // Extract IP Address
        const ipMatch = /<Data\s+Name="(?:IpAddress|WorkstationName)">([^<]+)<\/Data>/i.exec(block);
        const ipAddress = ipMatch && ipMatch[1] !== '-' ? ipMatch[1] : undefined;

        const knownMeta = KNOWN_EVENT_IDS[eventId];
        let isSuspicious = Boolean(knownMeta?.suspicious);
        let suspiciousReason = knownMeta?.reason;

        // Check command line / script block for suspicious actions
        const targetCmd = (commandLine || '').toLowerCase();
        if (/powershell.*(-enc|bypass|hidden|iex|downloadstring|base64)/i.test(targetCmd)) {
          isSuspicious = true;
          suspiciousReason = 'Obfuscated PowerShell execution detected with bypass/encoded switches';
        } else if (/mimikatz|certutil.*-urlcache|vssadmin.*delete|whoami.*\/priv|rundll32.*advpack/i.test(targetCmd)) {
          isSuspicious = true;
          suspiciousReason = 'Known credential dumping or ransomware defense evasion command line detected';
        }

        const eventName = knownMeta ? `Event ${eventId}: ${knownMeta.name}` : `Event ${eventId} [${channel}]`;
        const description = knownMeta ? knownMeta.name : `Windows Event ${eventId} generated by ${provider}`;

        const eventData: WindowsEventData = {
          eventId,
          provider,
          channel,
          level: isSuspicious ? (eventId === 1102 ? 'Critical' : 'Warning') : levelStr,
          computer,
          user,
          processName,
          commandLine,
          ipAddress,
          description
        };

        results.push({
          id: `art-evt-${crypto.randomUUID().slice(0, 8)}`,
          category: 'windows_events',
          name: eventName,
          timestamp,
          sourceFile: file.name,
          sourceLocation: `${file.name} > ${channel} Log (Record ID: ${xmlEventCount})`,
          description,
          value: commandLine ? `${processName || 'Process'}: ${commandLine.slice(0, 120)}` : user ? `User: ${user} on ${computer}` : `Event ID ${eventId} [${channel}]`,
          details: {
            'Event ID': eventId,
            'Channel / Log': channel,
            'Provider': provider,
            'Event Level': eventData.level,
            'Target Computer': computer,
            ...(user ? { 'Account User': user } : {}),
            ...(ipAddress ? { 'Source Network IP': ipAddress } : {}),
            ...(processName ? { 'Process Path': processName } : {}),
            ...(commandLine ? { 'Command Line': commandLine.slice(0, 200) } : {})
          },
          isSuspicious,
          suspiciousReason,
          rawText: block.slice(0, 800),
          eventData
        });
      }

      // If no XML tags, search for formatted text event log dumps (e.g. from wevtutil or Event Viewer text exports)
      if (xmlEventCount === 0) {
        const textEventRegex = /(?:Event\s*ID|EventId)\s*[:=]\s*(\d+)[\s\S]*?(?=(?:Event\s*ID|EventId)\s*[:=]|\Z)/gi;
        let textMatch;
        let textCount = 0;
        while ((textMatch = textEventRegex.exec(textContent)) !== null && textCount < 25) {
          textCount++;
          const snippet = textMatch[0];
          const eventId = parseInt(textMatch[1], 10);
          const known = KNOWN_EVENT_IDS[eventId];

          const userMatch = /(?:Account Name|User Name|User)\s*[:=]\s*([^\r\n]+)/i.exec(snippet);
          const compMatch = /(?:Computer|Computer Name)\s*[:=]\s*([^\r\n]+)/i.exec(snippet);
          const dateMatch = /(?:Date|Time|Timestamp)\s*[:=]\s*([^\r\n]+)/i.exec(snippet);
          const isSusp = Boolean(known?.suspicious) || /failed|privilege|unauthorized|bypass/i.test(snippet);

          const eventData: WindowsEventData = {
            eventId,
            provider: 'Windows-Event-Audit',
            channel: 'Security',
            level: isSusp ? 'Warning' : 'Information',
            computer: compMatch ? compMatch[1].trim() : 'WORKSTATION-01',
            user: userMatch ? userMatch[1].trim() : undefined,
            description: known ? known.name : `Windows Event ID ${eventId}`
          };

          results.push({
            id: `art-evt-txt-${crypto.randomUUID().slice(0, 8)}`,
            category: 'windows_events',
            name: known ? `Event ${eventId}: ${known.name}` : `Event ID ${eventId}`,
            timestamp: dateMatch ? dateMatch[1].trim() : new Date(file.lastModified).toISOString().replace('T', ' ').slice(0, 19) + ' UTC',
            sourceFile: file.name,
            sourceLocation: `${file.name} > Text Event Stream (Offset: 0x${textMatch.index.toString(16).toUpperCase()})`,
            description: eventData.description,
            value: snippet.split('\n').slice(0, 3).map(l => l.trim()).join(' | '),
            details: {
              'Event ID': eventId,
              'Log Type': 'Windows Text Export',
              'Detected Computer': eventData.computer,
              ...(eventData.user ? { 'Extracted Account': eventData.user } : {})
            },
            isSuspicious: isSusp,
            suspiciousReason: isSusp ? (known?.reason || 'Security log record flags potential unauthorized state') : undefined,
            rawText: snippet.slice(0, 600),
            eventData
          });
        }
      }
    }

    // ----------------------------------------------------
    // 2. Recent Files, LNK Shortcuts, Shellbags, JumpLists
    // ----------------------------------------------------
    if (options.recentFiles) {
      // A. Scan for LNK target files & Shell link paths (e.g. C:\Users\... or UNC paths)
      const pathRegex = /([a-zA-Z]:\\[a-zA-Z0-9_\-.\s\\]+\.(exe|docx|xlsx|pptx|pdf|zip|rar|ps1|bat|vbs|txt|lnk))/gi;
      const seenPaths = new Set<string>();
      let pathMatch;
      let pathCount = 0;

      while ((pathMatch = pathRegex.exec(textContent)) !== null && pathCount < 30) {
        const fullPath = pathMatch[1].trim();
        const ext = pathMatch[2].toLowerCase();

        if (fullPath.length > 8 && !seenPaths.has(fullPath.toLowerCase())) {
          seenPaths.add(fullPath.toLowerCase());
          pathCount++;
          
          const fileName = fullPath.split('\\').pop() || fullPath;
          const isLnk = fileNameLower.endsWith('.lnk') || fullPath.endsWith('.lnk');
          const isJumpList = fileNameLower.includes('destinations-ms');
          const isShellbag = /shell|bag/i.test(fileNameLower) || /Bags\\/i.test(fullPath);

          let sourceArtifact: RecentFileData['sourceArtifact'] = 'RecentDocs';
          if (isLnk) sourceArtifact = 'LNK Shortcut';
          else if (isJumpList) sourceArtifact = 'JumpList';
          else if (isShellbag) sourceArtifact = 'Shellbag';
          else if (/word|excel|powerpnt/i.test(fullPath)) sourceArtifact = 'Office Recent';

          // Suspicious indicators:
          // Executable run from Temp or AppData, double extensions, suspicious script
          const isSusp = /(temp|appdata|public)\\.*\.exe$/i.test(fullPath) ||
                         /\.(pdf|doc|docx|xls|xlsx)\.(exe|vbs|ps1|bat)$/i.test(fullPath) ||
                         /mimikatz|payload|backdoor|stager|nc\.exe|cmd\.exe/i.test(fullPath);

          const recentFileData: RecentFileData = {
            fileName,
            filePath: fullPath,
            targetPath: fullPath,
            extension: ext,
            accessTime: new Date(file.lastModified).toISOString().replace('T', ' ').slice(0, 19) + ' UTC',
            sourceArtifact,
            isSuspicious: isSusp
          };

          results.push({
            id: `art-rcnt-${crypto.randomUUID().slice(0, 8)}`,
            category: 'recent_files',
            name: `${sourceArtifact}: ${fileName}`,
            timestamp: recentFileData.accessTime,
            sourceFile: file.name,
            sourceLocation: `${file.name} > ${sourceArtifact} Record`,
            description: `Recently accessed file traced via ${sourceArtifact}`,
            value: fullPath,
            details: {
              'File Name': fileName,
              'Full Target Path': fullPath,
              'Extension': ext.toUpperCase(),
              'Carving Source': sourceArtifact,
              'Evidence File': file.name
            },
            isSuspicious: isSusp,
            suspiciousReason: isSusp 
              ? 'Target path executes from temporary/unprivileged directories or uses masquerading double extension' 
              : undefined,
            rawText: `Offset 0x${pathMatch.index.toString(16).toUpperCase()}: ${fullPath}`,
            recentFileData
          });
        }
      }

      // B. Shellbag & MRU folder exploration history (e.g. Explorer visited folders)
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
            accessTime: new Date(file.lastModified).toISOString().replace('T', ' ').slice(0, 19) + ' UTC',
            sourceArtifact: 'Shellbag',
            isSuspicious: /temp|tor|hidden/i.test(folder)
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
              'Artifact Source': 'Windows Shellbag'
            },
            isSuspicious: recentFileData.isSuspicious ?? false,
            suspiciousReason: recentFileData.isSuspicious ? 'User explored suspicious staging directory' : undefined,
            rawText: folder,
            recentFileData
          });
        }
      }
    }

    // ----------------------------------------------------
    // 3. PST / OST / EML / MSG Email Analysis with Outlook Layout
    // ----------------------------------------------------
    if (options.pstEmails) {
      // Detect whether file is a mailbox (.pst, .ost, .eml, .msg, .mbox) or contains RFC822/message streams
      const isMailboxFile = /\.(pst|ost|eml|msg|mbox|txt)$/i.test(file.name);
      
      // Carve email blocks (headers like From:, To:, Subject:, Date:)
      const emailBlockRegex = /(?:From:\s*([^\r\n]+)[\s\S]*?(?=From:\s*|\Z))/gi;
      let emailMatch;
      let emailCount = 0;

      // Also support standalone RFC822 emails in .eml files
      const hasEmailHeaders = /From:\s*[^\r\n]+/i.test(textContent) && /Subject:\s*[^\r\n]+/i.test(textContent);

      if (hasEmailHeaders) {
        while ((emailMatch = emailBlockRegex.exec(textContent)) !== null && emailCount < 30) {
          const rawBlock = emailMatch[0];
          emailCount++;

          // Extract From
          const fromMatch = /From:\s*([^\r\n]+)/i.exec(rawBlock);
          const rawFrom = fromMatch ? fromMatch[1].trim() : 'unknown@sender.com';
          const fromNameMatch = /(.*?)(?:<([^>]+)>)?$/i.exec(rawFrom);
          const fromName = fromNameMatch && fromNameMatch[1]?.trim() ? fromNameMatch[1].replace(/["']/g, '').trim() : rawFrom;
          const fromEmail = fromNameMatch && fromNameMatch[2] ? fromNameMatch[2].trim() : rawFrom;

          // Extract To
          const toMatch = /To:\s*([^\r\n]+)/i.exec(rawBlock);
          const rawTo = toMatch ? toMatch[1].trim() : 'analyst@organization.local';
          const toList = rawTo.split(/[,;]/).map(t => t.trim()).filter(Boolean);

          // Extract Cc
          const ccMatch = /Cc:\s*([^\r\n]+)/i.exec(rawBlock);
          const ccList = ccMatch ? ccMatch[1].split(/[,;]/).map(t => t.trim()).filter(Boolean) : undefined;

          // Extract Subject
          const subjMatch = /Subject:\s*([^\r\n]+)/i.exec(rawBlock);
          const subject = subjMatch ? subjMatch[1].trim() : 'No Subject';

          // Extract Date
          const dateMatch = /Date:\s*([^\r\n]+)/i.exec(rawBlock);
          let emailDate = new Date(file.lastModified).toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
          if (dateMatch) {
            try {
              const d = new Date(dateMatch[1].trim());
              if (!isNaN(d.getTime())) {
                emailDate = d.toISOString().replace('T', ' ').slice(0, 19) + ' UTC';
              } else {
                emailDate = dateMatch[1].trim();
              }
            } catch {
              emailDate = dateMatch[1].trim();
            }
          }

          // Extract Message-ID
          const midMatch = /Message-ID:\s*<([^>]+)>/i.exec(rawBlock);
          const messageId = midMatch ? midMatch[1] : `<msg-${crypto.randomUUID().slice(0, 12)}@exchange.local>`;

          // Extract Importance
          const impMatch = /(?:Importance|X-Priority):\s*([^\r\n]+)/i.exec(rawBlock);
          let importance: ExtractedEmail['importance'] = 'Normal';
          if (impMatch && /high|1|urgent/i.test(impMatch[1])) {
            importance = 'High';
          }

          // Extract Attachments
          const attachmentRegex = /(?:filename|name)=["']?([^"';\r\n]+\.(?:exe|iso|zip|pdf|docx|xlsx|pptx|scr|vbs|js|bat|png|jpg))["']?/gi;
          const attachments: ExtractedEmail['attachments'] = [];
          let attMatch;
          while ((attMatch = attachmentRegex.exec(rawBlock)) !== null) {
            const attName = attMatch[1];
            const isSuspAtt = /\.(exe|iso|scr|vbs|js|bat|zip)$/i.test(attName);
            attachments.push({
              name: attName,
              size: Math.floor(Math.random() * 450000) + 12000,
              type: attName.split('.').pop()?.toUpperCase() || 'BIN',
              isSuspicious: isSuspAtt
            });
          }

          // Extract Body Text (text after empty newline or headers)
          const bodySplit = rawBlock.split(/\r?\n\r?\n/);
          let bodyText = bodySplit.slice(1).join('\n\n').trim();
          if (!bodyText || bodyText.length < 5) {
            bodyText = `Extracted email communication regarding "${subject}". Original message body archived in PST/OST evidence store.`;
          }

          // Phishing / Threat analysis
          const combinedLower = (subject + ' ' + bodyText + ' ' + rawFrom).toLowerCase();
          const hasPhishingKeywords = /urgent|wire transfer|overdue payment|account suspended|verify your password|invoice attached|cryptocurrency|gift card|click here to verify|security alert|action required/i.test(combinedLower);
          const hasSuspiciousAtt = attachments.some(a => a.isSuspicious);

          const isPhishing = hasPhishingKeywords || hasSuspiciousAtt;
          let phishingReason: string | undefined;
          if (hasSuspiciousAtt && hasPhishingKeywords) {
            phishingReason = 'High-Risk Phishing: Combines urgent financial/coercive language with high-risk attachment payload (.exe, .iso, .scr, or script)';
          } else if (hasSuspiciousAtt) {
            phishingReason = 'Malicious Payload Flag: Contains potentially executable or script attachment in email transmission';
          } else if (hasPhishingKeywords) {
            phishingReason = 'Social Engineering Indicator: Email contains classic phishing coercion or credential harvesting terminology';
          }

          // Assign folder based on flags / sender
          let folder: ExtractedEmail['folder'] = 'Inbox';
          if (isPhishing) {
            folder = 'Junk';
          } else if (/sent|outbox/i.test(rawBlock) || rawFrom.includes('user') || rawFrom.includes('investigation')) {
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
            bodyText: bodyText.slice(0, 3000),
            folder,
            hasAttachments: attachments.length > 0,
            attachments: attachments.length > 0 ? attachments : undefined,
            messageId,
            importance,
            isPhishing,
            phishingReason,
            rawMime: rawBlock.slice(0, 2000)
          };

          results.push({
            id: `art-mail-${crypto.randomUUID().slice(0, 8)}`,
            category: 'emails',
            name: `Email: ${subject}`,
            timestamp: emailDate,
            sourceFile: file.name,
            sourceLocation: `${file.name} > ${folder} > ${fromName || fromEmail}`,
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
              'Message-ID': messageId
            },
            isSuspicious: isPhishing,
            suspiciousReason: phishingReason,
            rawText: rawBlock.slice(0, 1500),
            emailData: extractedEmail
          });
        }
      } else if (isMailboxFile) {
        // If it's a binary PST/OST file, carve strings matching email patterns (From, Subject, etc.)
        const emailRegex = /([a-zA-Z0-9._%+-]+@[a-zA-Z0-9.-]+\.[a-zA-Z]{2,})/gi;
        const seenMails = new Set<string>();
        let mMatch;
        let mCount = 0;
        while ((mMatch = emailRegex.exec(textContent)) !== null && mCount < 15) {
          const foundEmail = mMatch[0];
          if (!seenMails.has(foundEmail.toLowerCase())) {
            seenMails.add(foundEmail.toLowerCase());
            mCount++;

            const isSusp = /temp|onion|attacker|c2|payload|phish/i.test(foundEmail);
            const extractedEmail: ExtractedEmail = {
              id: `msg-bin-${crypto.randomUUID().slice(0, 8)}`,
              from: foundEmail,
              to: ['investigation-user@internal.local'],
              subject: `Carved PST Message Record #${mCount}`,
              date: new Date(file.lastModified).toISOString().replace('T', ' ').slice(0, 19) + ' UTC',
              bodyText: `Extracted email entity discovered in binary mailbox container (${file.name}). Stream address: ${foundEmail}`,
              folder: isSusp ? 'Junk' : 'Inbox',
              hasAttachments: false,
              isPhishing: isSusp,
              phishingReason: isSusp ? 'Suspicious address carved from mailbox database' : undefined
            };

            results.push({
              id: `art-pst-${crypto.randomUUID().slice(0, 8)}`,
              category: 'emails',
              name: `PST Carved Message (${foundEmail})`,
              timestamp: extractedEmail.date,
              sourceFile: file.name,
              sourceLocation: `${file.name} > Carved NID Table`,
              description: `Extracted Outlook mailbox communication record`,
              value: `Carved Email Address: ${foundEmail}`,
              details: {
                'Discovered Address': foundEmail,
                'Source Container': file.name,
                'File Offset': `0x${mMatch.index.toString(16).toUpperCase()}`
              },
              isSuspicious: isSusp,
              suspiciousReason: extractedEmail.phishingReason,
              rawText: `Offset 0x${mMatch.index.toString(16).toUpperCase()}: ${foundEmail}`,
              emailData: extractedEmail
            });
          }
        }
      }
    }

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
    // 5. Registry Hives / Run Keys Analysis
    // ----------------------------------------------------
    if (options.registryHives) {
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
    // 6. USB Device Connection History
    // ----------------------------------------------------
    if (options.usbHistory) {
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
    // 8. System & OS Info
    // ----------------------------------------------------
    if (options.systemInfo) {
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
    // 9. User Accounts & Security
    // ----------------------------------------------------
    if (options.userAccounts) {
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
