/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

export interface ForensicFile {
  id: string;
  file: File;
  name: string;
  size: number;
  type: string;
  lastModified: number;
  hash?: string;
  signatureMatch?: string;
  status: 'pending' | 'analyzed' | 'error';
  extensionMismatch: boolean;
  path: string; // File path relative to source
  parentPath: string;
  // Forensic disk image properties
  isDeleted?: boolean;
  inode?: number | string;
  mftRecordId?: number;
  sectorOffset?: number;
  partitionName?: string;
  imageSource?: string;
  filesystem?: string;
  createdTime?: string;
  modifiedTime?: string;
  accessedTime?: string;
}

export interface FolderNode {
  id: string;
  name: string;
  path: string;
  children: string[]; // Child folder IDs
  fileIds: string[]; // File IDs in this folder
  isPartition?: boolean;
  isDiskImage?: boolean;
  partitionType?: string;
  filesystemType?: string;
  deletedFileCount?: number;
  totalSize?: number;
}

export interface PartitionInfo {
  id: string;
  name: string;
  type: string;
  filesystem: string;
  startSector: number;
  sectorCount: number;
  sizeBytes: number;
  bootable: boolean;
}

export interface DiskImageInfo {
  fileName: string;
  fileSize: number;
  format: 'E01' | 'DD' | 'RAW' | 'IMG' | 'ISO' | 'VMDK';
  totalSectors: number;
  bytesPerSector: number;
  caseInfo?: {
    caseNumber?: string;
    evidenceNumber?: string;
    examiner?: string;
    description?: string;
    notes?: string;
    acquisitionDate?: string;
    systemDate?: string;
  };
  partitions: PartitionInfo[];
  hashes?: {
    md5?: string;
    sha1?: string;
    sha256?: string;
  };
}

export interface DiskImageParseResult {
  imageInfo: DiskImageInfo;
  files: Record<string, ForensicFile>;
  folders: Record<string, FolderNode>;
  rootPaths: string[];
}

export type ViewMode = 'explorer' | 'hex' | 'metadata' | 'search';
export type ContentTab = 'hex' | 'text' | 'image' | 'properties';

export type ArtifactCategory = 
  | 'all'
  | 'browser_history'
  | 'user_activity'
  | 'system_info'
  | 'usb_connect'
  | 'run_keys'
  | 'user_accounts'
  | 'windows_events'
  | 'recent_files'
  | 'emails';

export interface ExtractedEmailAttachment {
  name: string;
  size: number;
  type?: string;
  isSuspicious?: boolean;
  suspiciousReason?: string;
}

export interface ExtractedEmail {
  id: string;
  from: string;
  fromName?: string;
  to: string[];
  cc?: string[];
  bcc?: string[];
  subject: string;
  date: string;
  bodyText: string;
  bodyHtml?: string;
  folder: 'Inbox' | 'Sent Items' | 'Deleted Items' | 'Drafts' | 'Junk' | 'Archive';
  hasAttachments: boolean;
  attachments?: ExtractedEmailAttachment[];
  messageId?: string;
  importance?: 'High' | 'Normal' | 'Low';
  isPhishing?: boolean;
  phishingReason?: string;
  headers?: Record<string, string>;
  rawMime?: string;
  read?: boolean;
}

export interface WindowsEventData {
  eventId: number;
  provider: string;
  channel: string;
  level: 'Information' | 'Warning' | 'Error' | 'Critical' | 'Audit Success' | 'Audit Failure';
  computer: string;
  user?: string;
  userSid?: string;
  accountName?: string;
  recordId?: number;
  processName?: string;
  processPath?: string;
  commandLine?: string;
  ipAddress?: string;
  taskCategory?: string;
  keywords?: string;
  description: string;
}

export interface RecentFileData {
  fileName: string;
  filePath: string;
  targetPath?: string;
  extension: string;
  fileExtension?: string;
  accessTime: string;
  creationTime?: string;
  fileSize?: number;
  sourceArtifact: 'LNK Shortcut' | 'JumpList' | 'Shellbag' | 'RecentDocs' | 'Office Recent' | 'OpenSaveMRU';
  volumeSerial?: string;
  workingDir?: string;
  mruIndex?: number;
  isSuspicious?: boolean;
}

export interface ForensicArtifact {
  id: string;
  category: ArtifactCategory;
  name: string;
  timestamp: string;
  sourceFile: string;
  sourceLocation: string; // e.g. HKLM\...\Run, or SQLite: visits table
  description: string;
  value: string;
  details: Record<string, string | number | boolean>;
  isSuspicious: boolean;
  suspiciousReason?: string;
  rawText?: string;
  rawBytesHex?: string;
  bookmarked?: boolean;
  emailData?: ExtractedEmail;
  eventData?: WindowsEventData;
  recentFileData?: RecentFileData;
}

export interface ArtifactAnalysisOptions {
  browserHistory: boolean;
  registryHives: boolean;
  userActivities: boolean;
  usbHistory: boolean;
  systemInfo: boolean;
  userAccounts: boolean;
  windowsEvents: boolean;
  recentFiles: boolean;
  pstEmails: boolean;
}

export type SidebarMode = 'tree' | 'artifacts';
