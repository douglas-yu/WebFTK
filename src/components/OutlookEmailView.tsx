/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useMemo } from 'react';
import { 
  Inbox, 
  Send, 
  Trash2, 
  FileEdit, 
  AlertOctagon, 
  Folder, 
  Search, 
  Paperclip, 
  AlertTriangle, 
  ShieldAlert, 
  CheckCircle2, 
  Mail, 
  Download, 
  Copy, 
  Check, 
  Calendar, 
  User, 
  FileText, 
  Code2, 
  Layers,
  Flag,
  Filter,
  ExternalLink,
  ShieldCheck,
  Table
} from 'lucide-react';
import { ForensicArtifact, ExtractedEmail } from '../types';

interface OutlookEmailViewProps {
  emailArtifacts: ForensicArtifact[];
  onSwitchToTableView?: () => void;
}

type FolderFilter = 'all' | 'Inbox' | 'Sent Items' | 'Deleted Items' | 'Drafts' | 'Junk';

export default function OutlookEmailView({ 
  emailArtifacts, 
  onSwitchToTableView 
}: OutlookEmailViewProps) {
  const [selectedFolder, setSelectedFolder] = useState<FolderFilter>('all');
  const [selectedArtifactId, setSelectedArtifactId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState<string>('');
  const [activeTab, setActiveTab] = useState<'message' | 'headers' | 'raw'>('message');
  const [filterSuspiciousOnly, setFilterSuspiciousOnly] = useState<boolean>(false);
  const [filterAttachmentsOnly, setFilterAttachmentsOnly] = useState<boolean>(false);
  const [copiedField, setCopiedField] = useState<string | null>(null);

  // Normalize artifacts into email objects
  const emailsWithArtifact = useMemo(() => {
    return emailArtifacts.map(art => {
      const artDetails = art.details || {};
      const email: ExtractedEmail = art.emailData || {
        id: art.id,
        from: (artDetails['From'] as string) || art.value || 'unknown@sender.com',
        fromName: (artDetails['From'] as string)?.split('<')[0]?.trim() || art.name,
        to: [(artDetails['To'] as string) || 'analyst@organization.local'],
        subject: art.name.replace(/^Email:\s*/i, '') || 'Extracted Message',
        date: art.timestamp,
        bodyText: art.rawText || art.value || art.description || '',
        folder: (artDetails['Folder'] as ExtractedEmail['folder']) || (art.isSuspicious ? 'Junk' : 'Inbox'),
        hasAttachments: Boolean(artDetails['Attachments Count'] && (artDetails['Attachments Count'] as number) > 0),
        isPhishing: art.isSuspicious,
        phishingReason: art.suspiciousReason
      };
      return { artifact: art, email };
    });
  }, [emailArtifacts]);

  // Folder counts
  const folderCounts = useMemo(() => {
    const counts: Record<FolderFilter, number> = {
      all: emailsWithArtifact.length,
      'Inbox': 0,
      'Sent Items': 0,
      'Deleted Items': 0,
      'Drafts': 0,
      'Junk': 0
    };
    for (const item of emailsWithArtifact) {
      const f = item.email.folder;
      if (counts[f] !== undefined) {
        counts[f]++;
      } else {
        counts['Inbox']++;
      }
    }
    return counts;
  }, [emailsWithArtifact]);

  // Suspicious & Attachments count
  const suspiciousCount = useMemo(() => {
    return emailsWithArtifact.filter(e => e.email.isPhishing || e.artifact.isSuspicious).length;
  }, [emailsWithArtifact]);

  const attachmentsCount = useMemo(() => {
    return emailsWithArtifact.filter(e => e.email.hasAttachments).length;
  }, [emailsWithArtifact]);

  // Filtered emails
  const filteredEmails = useMemo(() => {
    return emailsWithArtifact.filter(({ email, artifact }) => {
      // Folder filter
      if (selectedFolder !== 'all') {
        if (email.folder !== selectedFolder) return false;
      }
      // Suspicious filter
      if (filterSuspiciousOnly && !email.isPhishing && !artifact.isSuspicious) {
        return false;
      }
      // Attachments filter
      if (filterAttachmentsOnly && !email.hasAttachments) {
        return false;
      }
      // Search query
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const inSubj = (email.subject || '').toLowerCase().includes(q);
        const inFrom = (email.from || '').toLowerCase().includes(q);
        const inFromName = (email.fromName || '').toLowerCase().includes(q);
        const inBody = (email.bodyText || '').toLowerCase().includes(q);
        const inTo = Array.isArray(email.to) ? email.to.some(t => (t || '').toLowerCase().includes(q)) : false;
        if (!inSubj && !inFrom && !inFromName && !inBody && !inTo) return false;
      }
      return true;
    }).sort((a, b) => (b.email.date || '').localeCompare(a.email.date || ''));
  }, [emailsWithArtifact, selectedFolder, filterSuspiciousOnly, filterAttachmentsOnly, searchQuery]);

  // Current selected email
  const currentItem = useMemo(() => {
    if (filteredEmails.length === 0) return null;
    if (!selectedArtifactId) return filteredEmails[0];
    const found = filteredEmails.find(f => f.artifact.id === selectedArtifactId);
    return found || filteredEmails[0];
  }, [filteredEmails, selectedArtifactId]);

  const handleCopy = (text: string, fieldId: string) => {
    navigator.clipboard.writeText(text);
    setCopiedField(fieldId);
    setTimeout(() => setCopiedField(null), 1500);
  };

  const handleExportEML = (email: ExtractedEmail) => {
    const toRecipients = Array.isArray(email.to) ? email.to.join(', ') : (email.to || '');
    const ccRecipients = Array.isArray(email.cc) && email.cc.length > 0 ? `Cc: ${email.cc.join(', ')}` : '';
    const emlContent = [
      `From: ${email.fromName ? `"${email.fromName}" <${email.from}>` : (email.from || 'unknown@sender.com')}`,
      `To: ${toRecipients}`,
      ccRecipients,
      `Subject: ${email.subject || 'No Subject'}`,
      `Date: ${email.date || new Date().toISOString()}`,
      `Message-ID: ${email.messageId || `<${crypto.randomUUID()}@forensic.local>`}`,
      'MIME-Version: 1.0',
      'Content-Type: text/plain; charset=utf-8',
      'X-Forensic-Source: PST/OST Extracted Mailbox',
      '',
      email.bodyText || ''
    ].filter(Boolean).join('\r\n');

    const blob = new Blob([emlContent], { type: 'message/rfc822' });
    const url = URL.createObjectURL(blob);
    const link = document.createElement('a');
    link.href = url;
    link.download = `${email.subject.replace(/[^a-zA-Z0-9_-]/g, '_').slice(0, 40) || 'extracted_message'}.eml`;
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
    URL.revokeObjectURL(url);
  };

  return (
    <div className="flex-1 flex flex-col min-h-0 bg-zinc-950 font-sans">
      {/* Top Outlook Ribbon Toolbar */}
      <div className="h-11 bg-zinc-900/90 border-b border-zinc-800 flex items-center justify-between px-4 shrink-0 select-none">
        <div className="flex items-center gap-3">
          <div className="flex items-center gap-2">
            <div className="w-6 h-6 rounded bg-blue-600/30 border border-blue-500/40 flex items-center justify-center text-blue-400">
              <Mail className="w-3.5 h-3.5" />
            </div>
            <span className="text-xs font-bold text-zinc-200 uppercase tracking-wider">
              Outlook Mailbox Inspector
            </span>
            <span className="text-[10px] text-zinc-500 font-mono px-1.5 py-0.5 rounded bg-zinc-800">
              PST / OST / EML Mode
            </span>
          </div>

          <div className="h-4 w-px bg-zinc-800 mx-1" />

          {/* Quick Filter Buttons */}
          <div className="flex items-center gap-1.5">
            <button
              onClick={() => setFilterSuspiciousOnly(!filterSuspiciousOnly)}
              className={`px-2 py-1 rounded text-[10px] font-bold uppercase tracking-wider flex items-center gap-1 transition-all ${
                filterSuspiciousOnly
                  ? 'bg-red-950/80 text-red-300 border border-red-800'
                  : 'bg-zinc-800/80 hover:bg-zinc-800 text-zinc-400 border border-zinc-700/50'
              }`}
            >
              <ShieldAlert className="w-3 h-3 text-red-400" />
              <span>Phishing Alerts ({suspiciousCount})</span>
            </button>

            <button
              onClick={() => setFilterAttachmentsOnly(!filterAttachmentsOnly)}
              className={`px-2 py-1 rounded text-[10px] font-bold uppercase tracking-wider flex items-center gap-1 transition-all ${
                filterAttachmentsOnly
                  ? 'bg-blue-950/80 text-blue-300 border border-blue-800'
                  : 'bg-zinc-800/80 hover:bg-zinc-800 text-zinc-400 border border-zinc-700/50'
              }`}
            >
              <Paperclip className="w-3 h-3 text-blue-400" />
              <span>Attachments ({attachmentsCount})</span>
            </button>
          </div>
        </div>

        {/* Right Action Bar */}
        <div className="flex items-center gap-2">
          {currentItem && (
            <button
              onClick={() => handleExportEML(currentItem.email)}
              className="px-2.5 py-1 rounded text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5 bg-zinc-800 hover:bg-zinc-700 text-zinc-200 border border-zinc-700 transition-colors"
              title="Export active message to .EML (RFC 822)"
            >
              <Download className="w-3 h-3 text-blue-400" />
              <span>Export .EML</span>
            </button>
          )}

          {onSwitchToTableView && (
            <button
              onClick={onSwitchToTableView}
              className="px-2.5 py-1 rounded text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5 bg-zinc-800/60 hover:bg-zinc-800 text-zinc-400 hover:text-zinc-200 border border-zinc-800 transition-colors"
              title="Switch back to standard forensic artifact grid"
            >
              <Table className="w-3 h-3" />
              <span>Table View</span>
            </button>
          )}
        </div>
      </div>

      {/* Main 3-Pane Outlook Layout */}
      <div className="flex-1 flex min-h-0 overflow-hidden">
        {/* Pane 1: Left Navigation / Folders Tree */}
        <div className="w-56 bg-zinc-950 border-r border-zinc-900 flex flex-col shrink-0 select-none">
          {/* Account Header */}
          <div className="p-3 border-b border-zinc-900 bg-zinc-900/20">
            <div className="flex items-center gap-2">
              <div className="w-7 h-7 rounded-full bg-blue-950/80 border border-blue-800/60 flex items-center justify-center text-blue-400 font-bold text-xs">
                @
              </div>
              <div className="min-w-0">
                <p className="text-xs font-bold text-zinc-200 truncate">
                  Evidence Mailbox
                </p>
                <p className="text-[10px] text-zinc-500 font-mono truncate">
                  {emailsWithArtifact.length} Total Messages
                </p>
              </div>
            </div>
          </div>

          {/* Folder List */}
          <div className="flex-1 overflow-y-auto p-2 space-y-0.5 custom-scrollbar">
            <div className="px-2 py-1 text-[10px] font-bold uppercase tracking-wider text-zinc-600">
              Folders
            </div>

            <button
              onClick={() => setSelectedFolder('all')}
              className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded text-xs transition-colors ${
                selectedFolder === 'all'
                  ? 'bg-blue-900/30 text-blue-300 font-semibold'
                  : 'text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200'
              }`}
            >
              <div className="flex items-center gap-2">
                <Layers className="w-3.5 h-3.5 text-zinc-400" />
                <span>All Extracted Items</span>
              </div>
              <span className="text-[10px] font-mono text-zinc-500 bg-zinc-900 px-1.5 py-0.5 rounded">
                {folderCounts.all}
              </span>
            </button>

            <button
              onClick={() => setSelectedFolder('Inbox')}
              className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded text-xs transition-colors ${
                selectedFolder === 'Inbox'
                  ? 'bg-blue-900/30 text-blue-300 font-semibold'
                  : 'text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200'
              }`}
            >
              <div className="flex items-center gap-2">
                <Inbox className="w-3.5 h-3.5 text-blue-400" />
                <span>Inbox</span>
              </div>
              <span className="text-[10px] font-mono text-zinc-500 bg-zinc-900 px-1.5 py-0.5 rounded">
                {folderCounts['Inbox']}
              </span>
            </button>

            <button
              onClick={() => setSelectedFolder('Sent Items')}
              className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded text-xs transition-colors ${
                selectedFolder === 'Sent Items'
                  ? 'bg-blue-900/30 text-blue-300 font-semibold'
                  : 'text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200'
              }`}
            >
              <div className="flex items-center gap-2">
                <Send className="w-3.5 h-3.5 text-emerald-400" />
                <span>Sent Items</span>
              </div>
              <span className="text-[10px] font-mono text-zinc-500 bg-zinc-900 px-1.5 py-0.5 rounded">
                {folderCounts['Sent Items']}
              </span>
            </button>

            <button
              onClick={() => setSelectedFolder('Junk')}
              className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded text-xs transition-colors ${
                selectedFolder === 'Junk'
                  ? 'bg-red-950/40 text-red-300 font-semibold'
                  : 'text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200'
              }`}
            >
              <div className="flex items-center gap-2">
                <AlertOctagon className="w-3.5 h-3.5 text-red-400" />
                <span>Junk / Phishing</span>
              </div>
              <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
                folderCounts['Junk'] > 0 ? 'bg-red-950/80 text-red-400 font-bold border border-red-900/50' : 'text-zinc-500 bg-zinc-900'
              }`}>
                {folderCounts['Junk']}
              </span>
            </button>

            <button
              onClick={() => setSelectedFolder('Drafts')}
              className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded text-xs transition-colors ${
                selectedFolder === 'Drafts'
                  ? 'bg-blue-900/30 text-blue-300 font-semibold'
                  : 'text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200'
              }`}
            >
              <div className="flex items-center gap-2">
                <FileEdit className="w-3.5 h-3.5 text-amber-400" />
                <span>Drafts</span>
              </div>
              <span className="text-[10px] font-mono text-zinc-500 bg-zinc-900 px-1.5 py-0.5 rounded">
                {folderCounts['Drafts']}
              </span>
            </button>

            <button
              onClick={() => setSelectedFolder('Deleted Items')}
              className={`w-full flex items-center justify-between px-2.5 py-1.5 rounded text-xs transition-colors ${
                selectedFolder === 'Deleted Items'
                  ? 'bg-blue-900/30 text-blue-300 font-semibold'
                  : 'text-zinc-400 hover:bg-zinc-900 hover:text-zinc-200'
              }`}
            >
              <div className="flex items-center gap-2">
                <Trash2 className="w-3.5 h-3.5 text-zinc-500" />
                <span>Deleted Items</span>
              </div>
              <span className="text-[10px] font-mono text-zinc-500 bg-zinc-900 px-1.5 py-0.5 rounded">
                {folderCounts['Deleted Items']}
              </span>
            </button>
          </div>

          {/* Quick Forensic Stats Box */}
          <div className="p-3 border-t border-zinc-900 bg-zinc-900/20 text-[10px] space-y-1.5">
            <span className="font-bold text-zinc-500 uppercase tracking-wider block">
              Mailbox Evidence Summary
            </span>
            <div className="flex justify-between text-zinc-400">
              <span>Phishing Detections:</span>
              <span className="font-mono text-red-400 font-bold">{suspiciousCount}</span>
            </div>
            <div className="flex justify-between text-zinc-400">
              <span>With Attachments:</span>
              <span className="font-mono text-blue-400 font-bold">{attachmentsCount}</span>
            </div>
          </div>
        </div>

        {/* Pane 2: Middle Message List Pane */}
        <div className="w-80 md:w-96 bg-zinc-950/80 border-r border-zinc-900 flex flex-col shrink-0">
          {/* Search in folder */}
          <div className="p-2 border-b border-zinc-900 bg-zinc-900/10">
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-500" />
              <input
                type="text"
                value={searchQuery}
                onChange={(e) => setSearchQuery(e.target.value)}
                placeholder="Search subject, sender, body..."
                className="w-full bg-zinc-900/80 border border-zinc-800 rounded pl-8 pr-3 py-1.5 text-xs text-zinc-200 placeholder-zinc-500 focus:outline-none focus:border-blue-500 transition-colors"
              />
            </div>
          </div>

          {/* Message List Header */}
          <div className="px-3 py-1.5 bg-zinc-900/30 border-b border-zinc-900 flex items-center justify-between text-[11px] text-zinc-500 select-none">
            <span className="font-semibold uppercase tracking-wider text-[10px]">
              {selectedFolder === 'all' ? 'All Folders' : selectedFolder} ({filteredEmails.length})
            </span>
            <span className="font-mono text-[10px]">Newest first</span>
          </div>

          {/* Email Items List */}
          <div className="flex-1 overflow-y-auto divide-y divide-zinc-900/70 custom-scrollbar">
            {filteredEmails.map(({ artifact, email }) => {
              const isSelected = currentItem?.artifact.id === artifact.id;
              const isPhish = email.isPhishing || artifact.isSuspicious;

              return (
                <div
                  key={artifact.id}
                  onClick={() => setSelectedArtifactId(artifact.id)}
                  className={`p-3 cursor-pointer transition-all relative border-l-4 ${
                    isSelected
                      ? 'bg-blue-900/20 border-blue-500 text-white'
                      : isPhish
                      ? 'border-red-600/80 bg-red-950/10 hover:bg-zinc-900/60 text-zinc-300'
                      : 'border-transparent hover:bg-zinc-900/40 text-zinc-300'
                  }`}
                >
                  {/* Sender & Timestamp */}
                  <div className="flex items-center justify-between gap-2 mb-1">
                    <span className={`text-xs truncate font-medium ${isSelected ? 'text-blue-300 font-bold' : isPhish ? 'text-red-300 font-semibold' : 'text-zinc-200'}`}>
                      {email.fromName || email.from}
                    </span>
                    <span className="text-[10px] text-zinc-500 font-mono shrink-0">
                      {email.date.slice(5, 16)}
                    </span>
                  </div>

                  {/* Subject Line */}
                  <div className="flex items-center gap-1.5 mb-1">
                    {isPhish && (
                      <AlertTriangle className="w-3 h-3 text-red-400 shrink-0" />
                    )}
                    {email.importance === 'High' && (
                      <span className="text-red-500 font-black text-xs font-mono shrink-0">!</span>
                    )}
                    <span className={`text-xs truncate ${isSelected ? 'text-zinc-100 font-semibold' : 'text-zinc-300'}`}>
                      {email.subject}
                    </span>
                  </div>

                  {/* Snippet preview */}
                  <p className="text-[11px] text-zinc-500 line-clamp-2 leading-tight">
                    {(email.bodyText || '').slice(0, 140)}
                  </p>

                  {/* Badges / indicators */}
                  <div className="mt-2 flex items-center gap-1.5">
                    {email.hasAttachments && (
                      <span className="inline-flex items-center gap-1 text-[9px] px-1.5 py-0.5 rounded bg-zinc-900 text-zinc-400 border border-zinc-800">
                        <Paperclip className="w-2.5 h-2.5 text-blue-400" />
                        <span>{email.attachments?.length || 1} att</span>
                      </span>
                    )}

                    {isPhish && (
                      <span className="text-[9px] font-bold px-1.5 py-0.5 rounded bg-red-950/90 text-red-400 border border-red-800/60">
                        PHISHING FLAG
                      </span>
                    )}

                    <span className="text-[9px] font-mono px-1 py-0.5 rounded bg-zinc-900/80 text-zinc-500 ml-auto">
                      {email.folder}
                    </span>
                  </div>
                </div>
              );
            })}

            {filteredEmails.length === 0 && (
              <div className="p-8 text-center text-zinc-600 italic text-xs">
                No emails matching active folder or filter criteria
              </div>
            )}
          </div>
        </div>

        {/* Pane 3: Right Reading Pane (Full Outlook Message Inspector) */}
        <div className="flex-1 bg-zinc-950 flex flex-col min-w-0 overflow-hidden">
          {currentItem ? (
            <div className="flex-1 flex flex-col min-h-0">
              {/* Message Header Strip */}
              <div className="p-4 border-b border-zinc-900 bg-zinc-900/20 space-y-3">
                {/* Subject and Action buttons */}
                <div className="flex items-start justify-between gap-4">
                  <h2 className="text-base md:text-lg font-bold text-zinc-100 leading-snug">
                    {currentItem.email.subject}
                  </h2>
                  <div className="flex items-center gap-1.5 shrink-0">
                    <button
                      onClick={() => handleExportEML(currentItem.email)}
                      className="p-1.5 rounded hover:bg-zinc-800 text-zinc-400 hover:text-white transition-colors"
                      title="Export .EML"
                    >
                      <Download className="w-4 h-4" />
                    </button>
                    <button
                      onClick={() => handleCopy(currentItem.email.bodyText, 'body')}
                      className="p-1.5 rounded hover:bg-zinc-800 text-zinc-400 hover:text-white transition-colors"
                      title="Copy Body"
                    >
                      {copiedField === 'body' ? <Check className="w-4 h-4 text-emerald-400" /> : <Copy className="w-4 h-4" />}
                    </button>
                  </div>
                </div>

                {/* Sender Identity & Metadata */}
                <div className="flex items-start gap-3">
                  <div className="w-10 h-10 rounded-full bg-blue-900/40 border border-blue-700/50 flex items-center justify-center text-blue-300 font-bold text-sm shrink-0 uppercase">
                    {(currentItem.email.fromName || currentItem.email.from || 'EM').slice(0, 2)}
                  </div>
                  <div className="flex-1 min-w-0 space-y-0.5 text-xs">
                    <div className="flex items-baseline gap-2 flex-wrap">
                      <span className="font-bold text-zinc-100">
                        {currentItem.email.fromName || currentItem.email.from || 'Unknown Sender'}
                      </span>
                      <span className="text-zinc-500 font-mono text-[11px]">
                        &lt;{currentItem.email.from || 'unknown@sender.com'}&gt;
                      </span>
                    </div>

                    <div className="flex items-center gap-2 text-zinc-400 text-[11px]">
                      <span className="text-zinc-500">To:</span>
                      <span className="font-mono text-zinc-300">
                        {Array.isArray(currentItem.email.to) ? currentItem.email.to.join(', ') : (currentItem.email.to || '')}
                      </span>
                      {currentItem.email.cc && Array.isArray(currentItem.email.cc) && currentItem.email.cc.length > 0 && (
                        <>
                          <span className="text-zinc-500 ml-2">Cc:</span>
                          <span className="font-mono text-zinc-300">{currentItem.email.cc.join(', ')}</span>
                        </>
                      )}
                    </div>

                    <div className="flex items-center gap-3 text-[10px] text-zinc-500 pt-0.5">
                      <span className="font-mono flex items-center gap-1">
                        <Calendar className="w-3 h-3 text-zinc-500" />
                        {currentItem.email.date}
                      </span>
                      <span>•</span>
                      <span className="font-mono">
                        Source: {currentItem.artifact.sourceFile}
                      </span>
                    </div>
                  </div>
                </div>

                {/* Phishing / Threat Alert Banner */}
                {(currentItem.email.isPhishing || currentItem.artifact.isSuspicious) && (
                  <div className="p-3 rounded-lg bg-red-950/30 border border-red-900/60 flex items-start gap-3">
                    <ShieldAlert className="w-4 h-4 text-red-400 shrink-0 mt-0.5" />
                    <div className="space-y-0.5">
                      <span className="text-xs font-bold text-red-400 block">
                        Forensic Warning: Suspicious / Phishing Threat Detected
                      </span>
                      <p className="text-[11px] text-red-300/90 leading-relaxed">
                        {currentItem.email.phishingReason || currentItem.artifact.suspiciousReason || 'Contains suspicious indicators indicative of social engineering or malware distribution.'}
                      </p>
                    </div>
                  </div>
                )}

                {/* Attachments Section */}
                {currentItem.email.hasAttachments && (
                  <div className="pt-2 border-t border-zinc-900/80">
                    <span className="text-[10px] font-bold uppercase tracking-wider text-zinc-500 block mb-1.5">
                      Attached Files ({currentItem.email.attachments?.length || 1})
                    </span>
                    <div className="flex flex-wrap gap-2">
                      {currentItem.email.attachments && currentItem.email.attachments.length > 0 ? (
                        currentItem.email.attachments.map((att, idx) => (
                          <div 
                            key={idx}
                            className={`flex items-center gap-2 px-2.5 py-1.5 rounded border text-xs font-mono transition-colors ${
                              att.isSuspicious
                                ? 'bg-red-950/40 text-red-300 border-red-800'
                                : 'bg-zinc-900/90 text-zinc-300 border-zinc-800 hover:border-zinc-700'
                            }`}
                          >
                            <Paperclip className={`w-3.5 h-3.5 ${att.isSuspicious ? 'text-red-400' : 'text-blue-400'}`} />
                            <span className="font-medium">{att.name || (att as any).filename || 'Attachment'}</span>
                            <span className="text-[10px] text-zinc-500">
                              ({att.size ? `${Math.round(att.size / 1024)} KB` : 'Payload'})
                            </span>
                            {att.isSuspicious && (
                              <span className="px-1 py-0.5 rounded bg-red-900/80 text-red-300 font-bold text-[8px]">
                                SUSPICIOUS
                              </span>
                            )}
                          </div>
                        ))
                      ) : (
                        <div className="flex items-center gap-1.5 px-2 py-1 rounded bg-zinc-900 text-zinc-300 border border-zinc-800 text-xs font-mono">
                          <Paperclip className="w-3.5 h-3.5 text-blue-400" />
                          <span>Extracted Binary Attachment</span>
                        </div>
                      )}
                    </div>
                  </div>
                )}

                {/* View Tabs */}
                <div className="flex items-center gap-2 pt-1">
                  <button
                    onClick={() => setActiveTab('message')}
                    className={`px-3 py-1 text-[11px] font-bold uppercase tracking-wider rounded transition-colors ${
                      activeTab === 'message'
                        ? 'bg-blue-600 text-white'
                        : 'bg-zinc-900 text-zinc-400 hover:text-zinc-200'
                    }`}
                  >
                    Message Body
                  </button>
                  <button
                    onClick={() => setActiveTab('headers')}
                    className={`px-3 py-1 text-[11px] font-bold uppercase tracking-wider rounded transition-colors ${
                      activeTab === 'headers'
                        ? 'bg-blue-600 text-white'
                        : 'bg-zinc-900 text-zinc-400 hover:text-zinc-200'
                    }`}
                  >
                    Headers & RFC822
                  </button>
                  <button
                    onClick={() => setActiveTab('raw')}
                    className={`px-3 py-1 text-[11px] font-bold uppercase tracking-wider rounded transition-colors ${
                      activeTab === 'raw'
                        ? 'bg-blue-600 text-white'
                        : 'bg-zinc-900 text-zinc-400 hover:text-zinc-200'
                    }`}
                  >
                    Raw Stream
                  </button>
                </div>
              </div>

              {/* Message Content Viewer */}
              <div className="flex-1 overflow-auto p-5 custom-scrollbar">
                {activeTab === 'message' && (
                  <div className="max-w-3xl space-y-4">
                    <div className="text-sm text-zinc-200 leading-relaxed font-sans whitespace-pre-wrap select-text">
                      {currentItem.email.bodyText}
                    </div>
                  </div>
                )}

                {activeTab === 'headers' && (
                  <div className="space-y-3 font-mono text-xs max-w-3xl">
                    <div className="p-3 rounded bg-zinc-900/40 border border-zinc-800 space-y-2">
                      <div className="flex justify-between border-b border-zinc-900 pb-1.5">
                        <span className="text-zinc-500 font-bold uppercase text-[10px]">Message-ID:</span>
                        <span className="text-zinc-300 break-all">{currentItem.email.messageId || 'None'}</span>
                      </div>
                      <div className="flex justify-between border-b border-zinc-900 pb-1.5">
                        <span className="text-zinc-500 font-bold uppercase text-[10px]">Importance / Priority:</span>
                        <span className="text-zinc-300">{currentItem.email.importance || 'Normal'}</span>
                      </div>
                      <div className="flex justify-between border-b border-zinc-900 pb-1.5">
                        <span className="text-zinc-500 font-bold uppercase text-[10px]">Original PST Container:</span>
                        <span className="text-zinc-300">{currentItem.artifact.sourceFile}</span>
                      </div>
                      <div className="flex justify-between">
                        <span className="text-zinc-500 font-bold uppercase text-[10px]">Carving Location:</span>
                        <span className="text-zinc-300">{currentItem.artifact.sourceLocation}</span>
                      </div>
                    </div>
                  </div>
                )}

                {activeTab === 'raw' && (
                  <div className="h-full font-mono text-xs text-zinc-400 bg-zinc-950 p-3 rounded border border-zinc-900 whitespace-pre-wrap select-all">
                    {currentItem.email.rawMime || currentItem.artifact.rawText || currentItem.email.bodyText}
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="flex-1 flex flex-col items-center justify-center p-8 text-center select-none">
              <div className="w-12 h-12 rounded-full bg-zinc-900 flex items-center justify-center text-zinc-600 mb-3">
                <Mail className="w-6 h-6" />
              </div>
              <p className="text-xs font-semibold text-zinc-400">
                Select an email from the list
              </p>
              <p className="text-[11px] text-zinc-600 mt-1">
                View headers, attachment records, and formatted message body
              </p>
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
