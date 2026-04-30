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
