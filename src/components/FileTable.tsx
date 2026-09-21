/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React from 'react';
import { ForensicFile } from '../types';
import { formatBytes } from '../lib/forensics';
import { File as FileIcon, AlertTriangle, CheckCircle2, Info, FileWarning } from 'lucide-react';

interface FileTableProps {
  files: ForensicFile[];
  selectedFileId: string | null;
  onSelectFile: (id: string) => void;
}

export default function FileTable({ files = [], selectedFileId, onSelectFile }: FileTableProps) {
  if (!files || files.length === 0) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-zinc-700 bg-zinc-950/50">
        <FileWarning className="w-12 h-12 mb-2 opacity-5" />
        <p className="text-[10px] font-bold uppercase tracking-widest opacity-20">Direct evidence stream empty</p>
      </div>
    );
  }

  return (
    <div className="h-full flex flex-col bg-zinc-950 font-mono text-[10px]">
      <div className="overflow-auto flex-1 custom-scrollbar">
        <table className="w-full text-left border-collapse">
          <thead className="sticky top-0 bg-zinc-900 border-b border-zinc-800 z-10">
            <tr className="text-zinc-500 uppercase font-black tracking-tighter">
              <th className="px-3 py-2 font-normal w-10">ID</th>
              <th className="px-3 py-2 font-normal">Object Name</th>
              <th className="px-3 py-2 font-normal text-right">Physical Size</th>
              <th className="px-3 py-2 font-normal">MIME/Type</th>
              <th className="px-3 py-2 font-normal">Signature Match</th>
              <th className="px-3 py-2 font-normal">Forensic Status / Alerts</th>
              <th className="px-3 py-2 font-normal">Sector / Inode</th>
              <th className="px-3 py-2 font-normal">SHA-256 Digest</th>
            </tr>
          </thead>
          <tbody className="divide-y divide-zinc-900/50">
            {files.filter(Boolean).map((file, index) => (
              <tr 
                key={file.id} 
                onClick={() => onSelectFile(file.id)}
                className={`group cursor-pointer transition-all ${
                  selectedFileId === file.id ? 'bg-blue-900/20' : 'hover:bg-zinc-900/40'
                } ${file.isDeleted ? 'bg-red-950/10' : ''}`}
              >
                <td className="px-3 py-1.5 text-zinc-700">{(index + 1).toString().padStart(3, '0')}</td>
                <td className="px-3 py-1.5 font-bold flex items-center gap-2">
                  <FileIcon className={`w-3 h-3 ${
                    file.isDeleted 
                      ? 'text-red-400' 
                      : selectedFileId === file.id 
                        ? 'text-blue-400' 
                        : 'text-zinc-600'
                  }`} />
                  <span className={`truncate max-w-[200px] ${
                    file.isDeleted
                      ? 'text-red-300 font-medium'
                      : selectedFileId === file.id 
                        ? 'text-blue-300' 
                        : 'text-zinc-400 group-hover:text-zinc-200'
                  }`}>
                    {file.name}
                  </span>
                  {file.isDeleted && (
                    <span className="px-1 py-0.2 rounded text-[8px] font-black bg-red-950 text-red-400 border border-red-900/60 uppercase tracking-tight">
                      DELETED
                    </span>
                  )}
                </td>
                <td className="px-3 py-1.5 text-right text-zinc-500 font-mono">{formatBytes(file.size)}</td>
                <td className="px-3 py-1.5 text-zinc-600 italic truncate max-w-[120px]">{file.type || 'RAW_BIN'}</td>
                <td className="px-3 py-1.5">
                  <span className={`px-1 rounded-sm text-[9px] font-black ${
                    file.signatureMatch ? 'text-green-500' : 'text-zinc-700'
                  }`}>
                    {file.signatureMatch || 'NO_MATCH'}
                  </span>
                </td>
                <td className="px-3 py-1.5">
                  {file.isDeleted ? (
                    <div className="flex items-center gap-1 text-red-400 font-bold">
                      <AlertTriangle className="w-2.5 h-2.5 text-red-500" />
                      <span>UNALLOC_RECOVERED</span>
                    </div>
                  ) : file.extensionMismatch ? (
                    <div className="flex items-center gap-1 text-amber-500 font-black animate-pulse">
                      <AlertTriangle className="w-2.5 h-2.5" />
                      <span>S_MISMATCH</span>
                    </div>
                  ) : (
                    <span className="text-zinc-700 font-mono text-[9px]">ALLOCATED</span>
                  )}
                </td>
                <td className="px-3 py-1.5 text-zinc-500 font-mono text-[9px] truncate max-w-[120px]">
                  {file.mftRecordId ? (
                    <span className="text-blue-400 font-bold">MFT #{file.mftRecordId}</span>
                  ) : file.inode ? (
                    <span className="text-emerald-400 font-bold">{file.inode}</span>
                  ) : file.sectorOffset ? (
                    <span>LBA {file.sectorOffset}</span>
                  ) : (
                    <span className="text-zinc-800">—</span>
                  )}
                </td>
                <td className="px-3 py-1.5 text-zinc-700 truncate max-w-[140px] group-hover:text-zinc-500 transition-colors">
                  {file.hash || 'CALCULATING...'}
                </td>
              </tr>
            ))}
          </tbody>
        </table>
      </div>
    </div>
  );
}
