/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect } from 'react';
import { FileCode, FileText, ImageIcon, Info, Search } from 'lucide-react';
import HexViewer from './HexViewer';
import { ForensicFile, ContentTab } from '../types';
import { formatBytes } from '../lib/forensics';

interface ContentViewerProps {
  file: ForensicFile | null;
}

export default function ContentViewer({ file }: ContentViewerProps) {
  const [activeTab, setActiveTab] = useState<ContentTab>('hex');
  const [textContent, setTextContent] = useState<string | null>(null);
  const [isTextLoading, setIsTextLoading] = useState(false);
  const [imageUrl, setImageUrl] = useState<string | null>(null);

  useEffect(() => {
    if (!file) {
      setTextContent(null);
      setImageUrl(null);
      return;
    }

    // Determine initial tab based on file type
    if (file.type.startsWith('image/')) {
      setActiveTab('image');
      setImageUrl(URL.createObjectURL(file.file));
    } else if (file.type.startsWith('text/') || file.name.match(/\.(txt|log|ini|json|xml|csv)$/i)) {
      setActiveTab('text');
    } else {
      setActiveTab('hex');
    }

    return () => {
      if (imageUrl) URL.revokeObjectURL(imageUrl);
    };
  }, [file]);

  useEffect(() => {
    if (activeTab === 'text' && file && !textContent) {
      setIsTextLoading(true);
      const reader = new FileReader();
      reader.onload = (e) => {
        setTextContent(e.target?.result as string);
        setIsTextLoading(false);
      };
      reader.readAsText(file.file.slice(0, 1024 * 50)); // Read first 50KB
    }
  }, [activeTab, file, textContent]);

  if (!file) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-zinc-700 bg-zinc-950 font-serif italic border-t border-zinc-900">
        <Search className="w-12 h-12 mb-4 opacity-10" />
        No target selected for extraction
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full bg-zinc-950 border-t border-zinc-900">
      {/* Tabs */}
      <div className="flex border-b border-zinc-900 bg-zinc-900/10">
        <ViewerTab label="Hex" active={activeTab === 'hex'} onClick={() => setActiveTab('hex')} icon={FileCode} />
        <ViewerTab label="Text" active={activeTab === 'text'} onClick={() => setActiveTab('text')} icon={FileText} />
        <ViewerTab label="Image" active={activeTab === 'image'} onClick={() => setActiveTab('image')} icon={ImageIcon} />
        <ViewerTab label="Properties" active={activeTab === 'properties'} onClick={() => setActiveTab('properties')} icon={Info} />
      </div>

      {/* Content */}
      <div className="flex-1 overflow-hidden relative">
        {activeTab === 'hex' && <HexViewer file={file.file} />}
        
        {activeTab === 'text' && (
          <div className="h-full overflow-auto p-6 font-mono text-xs text-zinc-400 bg-zinc-950 custom-scrollbar whitespace-pre-wrap">
            {isTextLoading ? (
              <div className="animate-pulse flex items-center justify-center h-full">Encoding text stream...</div>
            ) : (
              textContent || 'No text content available or binary data.'
            )}
          </div>
        )}

        {activeTab === 'image' && (
          <div className="h-full flex items-center justify-center bg-zinc-900 p-8">
            {imageUrl ? (
              <img 
                src={imageUrl} 
                alt="Evidence Preview" 
                className="max-w-full max-h-full object-contain shadow-2xl border border-zinc-800"
                referrerPolicy="no-referrer"
              />
            ) : (
              <div className="text-zinc-600">Not a valid image format for preview</div>
            )}
          </div>
        )}

        {activeTab === 'properties' && (
          <div className="h-full overflow-auto p-8 bg-zinc-950 custom-scrollbar">
            <h3 className="text-zinc-500 font-bold uppercase tracking-widest text-[10px] mb-6 flex items-center gap-2">
               Full Catalog Attributes
            </h3>
            <div className="grid grid-cols-2 gap-x-12 gap-y-6">
              <Attribute label="Object Name" value={file.name} />
              <Attribute label="Data Size" value={`${file.size} bytes (${formatBytes(file.size)})`} />
              <Attribute label="MIME Signature" value={file.type || 'None identified'} />
              <Attribute label="Path In Image" value={file.path} />
              <Attribute label="Time Stamp (MOD)" value={new Date(file.lastModified).toLocaleString()} />
              <Attribute label="Hash (SHA-256)" value={file.hash || 'Not calculated'} mono />
              <Attribute label="Magic Bytes Match" value={file.signatureMatch || 'Unknown'} highlight={!!file.signatureMatch} />
              <Attribute label="Entropy Warning" value={file.extensionMismatch ? 'SUSPICIOUS MISMATCH' : 'Normal'} alert={file.extensionMismatch} />
            </div>
          </div>
        )}
      </div>
    </div>
  );
}

function ViewerTab({ label, active, onClick, icon: Icon }: any) {
  return (
    <button 
      onClick={onClick}
      className={`flex items-center gap-2 px-4 py-2 text-[10px] uppercase font-bold tracking-tighter transition-all border-r border-zinc-900 ${
        active ? 'bg-zinc-900 text-blue-400' : 'text-zinc-600 hover:text-zinc-400 hover:bg-zinc-900/50'
      }`}
    >
      <Icon className="w-3 h-3" />
      {label}
    </button>
  );
}

function Attribute({ label, value, mono, highlight, alert }: any) {
  return (
    <div className="space-y-1">
      <p className="text-[10px] text-zinc-600 font-bold uppercase tracking-tight">{label}</p>
      <p className={`text-xs break-all ${mono ? 'font-mono' : ''} ${highlight ? 'text-green-500' : alert ? 'text-red-500 font-bold' : 'text-zinc-300'}`}>
        {value}
      </p>
    </div>
  );
}
