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
}

export interface FolderNode {
  id: string;
  name: string;
  path: string;
  children: string[]; // Child folder IDs
  fileIds: string[]; // File IDs in this folder
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
  processName?: string;
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
  accessTime: string;
  creationTime?: string;
  fileSize?: number;
  sourceArtifact: 'LNK Shortcut' | 'JumpList' | 'Shellbag' | 'RecentDocs' | 'Office Recent' | 'OpenSaveMRU';
  volumeSerial?: string;
  workingDir?: string;
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
