/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useMemo } from 'react';
import { 
  Search, 
  ShieldAlert, 
  Download, 
  Bookmark, 
  FileText, 
  Terminal, 
  ExternalLink, 
  Filter, 
  AlertTriangle, 
  CheckCircle2, 
  ArrowUpDown,
  Tag,
  Copy,
  Check,
  Code2,
  Info,
  FolderArchive,
  Mail,
  Table,
  FolderGit2,
  Activity,
  Layers
} from 'lucide-react';
import { ForensicArtifact, ArtifactCategory } from '../types';
import { ARTIFACT_CATEGORIES } from '../lib/artifactParser';
import OutlookEmailView from './OutlookEmailView';

interface ArtifactsViewProps {
  artifacts: ForensicArtifact[];
  activeCategory: ArtifactCategory;
  onSelectCategory: (category: ArtifactCategory) => void;
  onToggleBookmark?: (artifactId: string) => void;
  onOpenLoadModal?: () => void;
}

export default function ArtifactsView({
  artifacts,
  activeCategory,
  onSelectCategory,
  onToggleBookmark,
  onOpenLoadModal
}: ArtifactsViewProps) {
  const [selectedArtifactId, setSelectedArtifactId] = useState<string | null>(null);
  const [searchQuery, setSearchQuery] = useState('');
  const [suspiciousOnly, setSuspiciousOnly] = useState(false);
  const [sortField, setSortField] = useState<'timestamp' | 'name' | 'category'>('timestamp');
  const [sortAsc, setSortAsc] = useState(false);
  const [activeDetailTab, setActiveDetailTab] = useState<'properties' | 'analysis' | 'raw'>('properties');
  const [copied, setCopied] = useState(false);
  const [emailViewMode, setEmailViewMode] = useState<'outlook' | 'table'>('outlook');

  // Active category meta
  const currentCategoryMeta = useMemo(() => {
    return ARTIFACT_CATEGORIES.find(c => c.id === activeCategory) || ARTIFACT_CATEGORIES[0];
  }, [activeCategory]);

  // Filtering
  const filteredArtifacts = useMemo(() => {
    return artifacts.filter(art => {
      // Category match
      if (activeCategory !== 'all' && art.category !== activeCategory) {
        return false;
      }
      // Suspicious only match
      if (suspiciousOnly && !art.isSuspicious) {
        return false;
      }
      // Search query match
      if (searchQuery.trim()) {
        const q = searchQuery.toLowerCase();
        const inName = art.name.toLowerCase().includes(q);
        const inVal = art.value.toLowerCase().includes(q);
        const inSrc = art.sourceFile.toLowerCase().includes(q) || art.sourceLocation.toLowerCase().includes(q);
        const inDesc = art.description.toLowerCase().includes(q);
        const inDetails = Object.entries(art.details).some(
          ([k, v]) => k.toLowerCase().includes(q) || String(v).toLowerCase().includes(q)
        );
        if (!inName && !inVal && !inSrc && !inDesc && !inDetails) return false;
      }
      return true;
    }).sort((a, b) => {
      let cmp = 0;
      if (sortField === 'timestamp') {
        cmp = a.timestamp.localeCompare(b.timestamp);
      } else if (sortField === 'name') {
        cmp = a.name.localeCompare(b.name);
      } else {
        cmp = a.category.localeCompare(b.category);
      }
      return sortAsc ? cmp : -cmp;
    });
  }, [artifacts, activeCategory, suspiciousOnly, searchQuery, sortField, sortAsc]);

  // Selected artifact
  const selectedArtifact = useMemo(() => {
    if (!selectedArtifactId && filteredArtifacts.length > 0) {
      return filteredArtifacts[0];
    }
    return artifacts.find(a => a.id === selectedArtifactId) || filteredArtifacts[0] || null;
  }, [selectedArtifactId, filteredArtifacts, artifacts]);

  // Counts
  const totalCount = artifacts.length;
  const suspiciousCount = useMemo(() => artifacts.filter(a => a.isSuspicious).length, [artifacts]);

  // Export handlers
  const handleExportCSV = () => {
    if (filteredArtifacts.length === 0) return;
    const headers = ['Category', 'Timestamp', 'Name', 'Value', 'SourceFile', 'SourceLocation', 'Suspicious', 'Reason'];
    const rows = filteredArtifacts.map(a => [
      `"${a.category}"`,
      `"${a.timestamp}"`,
      `"${a.name.replace(/"/g, '""')}"`,
      `"${a.value.replace(/"/g, '""')}"`,
      `"${a.sourceFile.replace(/"/g, '""')}"`,
      `"${a.sourceLocation.replace(/"/g, '""')}"`,
      a.isSuspicious ? 'TRUE' : 'FALSE',
      `"${(a.suspiciousReason || '').replace(/"/g, '""')}"`
    ]);
    const csvContent = 'data:text/csv;charset=utf-8,' + [headers.join(','), ...rows.map(r => r.join(','))].join('\n');
    const encodedUri = encodeURI(csvContent);
    const link = document.createElement('a');
    link.setAttribute('href', encodedUri);
    link.setAttribute('download', `forensic_artifacts_${activeCategory}_${Date.now()}.csv`);
    document.body.appendChild(link);
    link.click();
    document.body.removeChild(link);
  };

  const handleCopyValue = (val: string) => {
    navigator.clipboard.writeText(val);
    setCopied(true);
    setTimeout(() => setCopied(false), 1500);
  };

  const toggleSort = (field: 'timestamp' | 'name' | 'category') => {
    if (sortField === field) {
      setSortAsc(!sortAsc);
    } else {
      setSortField(field);
      setSortAsc(false);
    }
  };

  const emailArtifacts = useMemo(() => artifacts.filter(a => a.category === 'emails'), [artifacts]);

  // If user selected emails and is in Outlook view mode, display the 3-pane Outlook viewer
  if (activeCategory === 'emails' && emailViewMode === 'outlook' && emailArtifacts.length > 0) {
    return (
      <div className="flex-1 flex flex-col min-h-0">
        <OutlookEmailView
          emailArtifacts={emailArtifacts}
          onSwitchToTableView={() => setEmailViewMode('table')}
        />
      </div>
    );
  }

  if (artifacts.length === 0) {
    return (
      <div className="flex-1 flex flex-col items-center justify-center p-8 bg-zinc-950 text-center font-sans">
        <div className="w-16 h-16 rounded-full bg-zinc-900 border border-zinc-800 flex items-center justify-center mb-4 text-zinc-600">
          <Terminal className="w-8 h-8 opacity-40" />
        </div>
        <h3 className="text-sm font-bold text-zinc-300 uppercase tracking-widest mb-1">
          No Forensic Artifacts Collected
        </h3>
        <p className="text-xs text-zinc-500 max-w-sm mb-5 leading-relaxed">
          Use the <strong className="text-zinc-400">Load Artifact File</strong> button to import files and run automated artifact extraction engines.
        </p>
        {onOpenLoadModal && (
          <button
            onClick={onOpenLoadModal}
            className="px-4 py-2 rounded text-xs font-bold uppercase tracking-wider text-white bg-blue-600 hover:bg-blue-500 transition-colors shadow-md shadow-blue-900/20 flex items-center gap-2"
          >
            <FolderArchive className="w-3.5 h-3.5" />
            Load Artifact File
          </button>
        )}
      </div>
    );
  }

  return (
    <div className="flex-1 flex flex-col min-h-0 bg-zinc-950 font-sans text-xs">
      {/* Top Controls & Category Ribbon */}
      <div className="border-b border-zinc-900 bg-zinc-900/20 px-4 py-2 flex flex-wrap items-center justify-between gap-3 shrink-0">
        <div className="flex items-center gap-2">
          <span className="font-bold text-white text-xs uppercase tracking-wider flex items-center gap-2">
            {currentCategoryMeta.label}
          </span>
          <span className="px-2 py-0.5 rounded-full text-[10px] font-mono font-bold bg-zinc-900 text-zinc-400 border border-zinc-800">
            {filteredArtifacts.length} record{filteredArtifacts.length !== 1 ? 's' : ''}
          </span>
          {activeCategory !== 'all' && (
            <button
              onClick={() => onSelectCategory('all')}
              className="text-[10px] text-blue-400 hover:text-blue-300 underline underline-offset-2 ml-1"
            >
              View All
            </button>
          )}
        </div>

        {/* Search, Filter, Export Bar */}
        <div className="flex items-center gap-2">
          {/* Search Input */}
          <div className="relative">
            <Search className="w-3.5 h-3.5 absolute left-2.5 top-1/2 -translate-y-1/2 text-zinc-600" />
            <input
              type="text"
              value={searchQuery}
              onChange={(e) => setSearchQuery(e.target.value)}
              placeholder="Search artifacts, keys, URLs..."
              className="bg-zinc-950 border border-zinc-800 focus:border-blue-500 rounded pl-8 pr-3 py-1 text-xs text-zinc-300 placeholder-zinc-600 w-52 focus:outline-none transition-colors"
            />
          </div>

          {/* Suspicious Only Toggle */}
          <button
            onClick={() => setSuspiciousOnly(!suspiciousOnly)}
            className={`px-2.5 py-1 rounded text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5 border transition-all ${
              suspiciousOnly
                ? 'bg-red-950/80 text-red-300 border-red-800 shadow-sm'
                : 'bg-zinc-900 hover:bg-zinc-800 text-zinc-500 hover:text-zinc-300 border-zinc-800'
            }`}
            title="Filter by suspicious / flagged IOC indicators"
          >
            <ShieldAlert className="w-3 h-3 text-red-400" />
            <span>Alerts Only</span>
            <span className="ml-0.5 font-mono px-1 rounded bg-black/40 text-[9px]">
              {suspiciousCount}
            </span>
          </button>

          {/* Outlook 3-Pane View Toggle if Emails exist */}
          {activeCategory === 'emails' ? (
            <button
              onClick={() => setEmailViewMode('outlook')}
              className="px-2.5 py-1 rounded text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5 bg-blue-600 hover:bg-blue-500 text-white shadow-sm transition-colors"
              title="Open Outlook 3-pane email client layout"
            >
              <Mail className="w-3 h-3" />
              <span>Outlook View</span>
            </button>
          ) : emailArtifacts.length > 0 ? (
            <button
              onClick={() => {
                onSelectCategory('emails');
                setEmailViewMode('outlook');
              }}
              className="px-2.5 py-1 rounded text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5 bg-blue-950/60 hover:bg-blue-900 text-blue-300 border border-blue-800 transition-colors"
              title="Switch to extracted mailbox in Outlook 3-pane layout"
            >
              <Mail className="w-3 h-3 text-blue-400" />
              <span>Outlook Mailbox ({emailArtifacts.length})</span>
            </button>
          ) : null}

          {/* Export CSV Button */}
          <button
            onClick={handleExportCSV}
            className="px-2.5 py-1 rounded text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5 bg-zinc-900 hover:bg-zinc-800 text-zinc-300 border border-zinc-800 transition-colors"
            title="Export filtered artifacts to CSV evidence report"
          >
            <Download className="w-3 h-3" />
            <span>Export CSV</span>
          </button>
        </div>
      </div>

      {/* Main Dual-Panel View (EnCase / FTK Style Split) */}
      <div className="flex-1 flex flex-col min-h-0">
        {/* Top Half: Artifacts Listing Table */}
        <div className="flex-[0.55] min-h-0 overflow-hidden flex flex-col border-b border-zinc-900">
          <div className="overflow-auto flex-1 custom-scrollbar">
            <table className="w-full text-left border-collapse text-[11px] font-mono">
              <thead className="sticky top-0 bg-zinc-900 border-b border-zinc-800 z-10 select-none">
                <tr className="text-zinc-500 font-bold uppercase tracking-tighter text-[10px]">
                  <th 
                    onClick={() => toggleSort('timestamp')}
                    className="px-3 py-2 cursor-pointer hover:text-zinc-300 w-44"
                  >
                    <div className="flex items-center gap-1">
                      <span>Timestamp (UTC)</span>
                      <ArrowUpDown className="w-2.5 h-2.5 opacity-60" />
                    </div>
                  </th>
                  <th 
                    onClick={() => toggleSort('name')}
                    className="px-3 py-2 cursor-pointer hover:text-zinc-300"
                  >
                    <div className="flex items-center gap-1">
                      <span>Artifact Name / Identifier</span>
                      <ArrowUpDown className="w-2.5 h-2.5 opacity-60" />
                    </div>
                  </th>
                  <th className="px-3 py-2">Primary Extracted Value</th>
                  <th 
                    onClick={() => toggleSort('category')}
                    className="px-3 py-2 cursor-pointer hover:text-zinc-300 w-28"
                  >
                    <div className="flex items-center gap-1">
                      <span>Category</span>
                      <ArrowUpDown className="w-2.5 h-2.5 opacity-60" />
                    </div>
                  </th>
                  <th className="px-3 py-2 w-44">Source Location</th>
                  <th className="px-3 py-2 w-20 text-center">Alert</th>
                </tr>
              </thead>
              <tbody className="divide-y divide-zinc-900/60">
                {filteredArtifacts.map((art) => {
                  const isSelected = selectedArtifact?.id === art.id;
                  const catMeta = ARTIFACT_CATEGORIES.find(c => c.id === art.category);

                  return (
                    <tr
                      key={art.id}
                      onClick={() => setSelectedArtifactId(art.id)}
                      className={`cursor-pointer transition-colors ${
                        isSelected 
                          ? 'bg-blue-900/25 text-white' 
                          : 'hover:bg-zinc-900/50 text-zinc-300'
                      }`}
                    >
                      <td className="px-3 py-2 text-zinc-400 truncate whitespace-nowrap">
                        {art.timestamp}
                      </td>
                      <td className="px-3 py-2 font-medium font-sans truncate max-w-xs">
                        <div className="flex items-center gap-1.5">
                          {art.isSuspicious && (
                            <AlertTriangle className="w-3 h-3 text-red-400 shrink-0" />
                          )}
                          <span className={`truncate ${isSelected ? 'text-blue-300 font-semibold' : 'text-zinc-200'}`} title={art.name}>
                            {art.name}
                          </span>
                        </div>
                      </td>
                      <td className="px-3 py-2 text-zinc-400 truncate max-w-md font-mono text-[10px]" title={art.value}>
                        {art.value}
                      </td>
                      <td className="px-3 py-2 whitespace-nowrap">
                        <span className={`px-1.5 py-0.5 rounded text-[9px] font-bold font-sans uppercase ${catMeta?.badgeColor || 'bg-zinc-800 text-zinc-400'}`}>
                          {catMeta?.shortLabel || art.category}
                        </span>
                      </td>
                      <td className="px-3 py-2 text-zinc-500 truncate max-w-[180px] text-[10px]" title={art.sourceLocation}>
                        {art.sourceLocation}
                      </td>
                      <td className="px-3 py-2 text-center whitespace-nowrap">
                        {art.isSuspicious ? (
                          <span className="px-1.5 py-0.5 rounded text-[9px] font-black bg-red-950/90 text-red-400 border border-red-800/60">
                            FLAGGED
                          </span>
                        ) : (
                          <span className="text-zinc-600 text-[9px] font-mono">NORMAL</span>
                        )}
                      </td>
                    </tr>
                  );
                })}

                {filteredArtifacts.length === 0 && (
                  <tr>
                    <td colSpan={6} className="text-center py-10 text-zinc-600 italic font-sans">
                      No artifacts matching active filter criteria
                    </td>
                  </tr>
                )}
              </tbody>
            </table>
          </div>
        </div>

        {/* Bottom Half: Artifact Details Inspector (EnCase / FTK Bottom Pane) */}
        <div className="flex-[0.45] min-h-0 bg-zinc-950 flex flex-col overflow-hidden">
          {selectedArtifact ? (
            <div className="flex-1 flex flex-col min-h-0">
              {/* Tab Header for Detail Pane */}
              <div className="h-8 border-b border-zinc-900 bg-zinc-900/30 flex items-center justify-between px-4 shrink-0">
                <div className="flex items-center gap-1">
                  <button
                    onClick={() => setActiveDetailTab('properties')}
                    className={`px-3 py-1.5 text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5 border-b-2 transition-all ${
                      activeDetailTab === 'properties'
                        ? 'border-blue-500 text-blue-400 bg-zinc-900/60'
                        : 'border-transparent text-zinc-500 hover:text-zinc-300'
                    }`}
                  >
                    <Info className="w-3 h-3" />
                    <span>Attributes</span>
                  </button>
                  <button
                    onClick={() => setActiveDetailTab('analysis')}
                    className={`px-3 py-1.5 text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5 border-b-2 transition-all ${
                      activeDetailTab === 'analysis'
                        ? 'border-blue-500 text-blue-400 bg-zinc-900/60'
                        : 'border-transparent text-zinc-500 hover:text-zinc-300'
                    }`}
                  >
                    <ShieldAlert className="w-3 h-3" />
                    <span>Forensic Interpretation</span>
                  </button>
                  <button
                    onClick={() => setActiveDetailTab('raw')}
                    className={`px-3 py-1.5 text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5 border-b-2 transition-all ${
                      activeDetailTab === 'raw'
                        ? 'border-blue-500 text-blue-400 bg-zinc-900/60'
                        : 'border-transparent text-zinc-500 hover:text-zinc-300'
                    }`}
                  >
                    <Code2 className="w-3 h-3" />
                    <span>Raw Stream</span>
                  </button>
                </div>

                <div className="flex items-center gap-3">
                  <button
                    onClick={() => handleCopyValue(selectedArtifact.value)}
                    className="text-[10px] text-zinc-500 hover:text-zinc-300 flex items-center gap-1 font-mono"
                    title="Copy extracted value to clipboard"
                  >
                    {copied ? <Check className="w-3 h-3 text-green-400" /> : <Copy className="w-3 h-3" />}
                    <span>{copied ? 'Copied' : 'Copy Value'}</span>
                  </button>
                  <span className="text-[10px] text-zinc-600 font-mono">
                    ID: {selectedArtifact.id}
                  </span>
                </div>
              </div>

              {/* Detail Content */}
              <div className="flex-1 overflow-auto p-4 custom-scrollbar">
                {activeDetailTab === 'properties' && (
                  <div className="space-y-4">
                    {/* Specialized Windows Event Card */}
                    {selectedArtifact.eventData && (
                      <div className="p-3.5 rounded-lg bg-zinc-900/60 border border-zinc-800 space-y-3 font-sans">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-emerald-950 text-emerald-300 border border-emerald-800">
                              Event ID {selectedArtifact.eventData.eventId}
                            </span>
                            <span className={`px-2 py-0.5 rounded text-[10px] font-bold uppercase ${
                              selectedArtifact.eventData.level === 'Critical' ? 'bg-red-950 text-red-300 border border-red-800' :
                              selectedArtifact.eventData.level === 'Error' ? 'bg-rose-950 text-rose-300 border border-rose-800' :
                              selectedArtifact.eventData.level === 'Warning' ? 'bg-amber-950 text-amber-300 border border-amber-800' :
                              'bg-zinc-800 text-zinc-300 border border-zinc-700'
                            }`}>
                              {selectedArtifact.eventData.level}
                            </span>
                            <span className="text-xs font-bold text-zinc-300">{selectedArtifact.eventData.taskCategory}</span>
                          </div>
                          <span className="text-[10px] font-mono text-zinc-500">
                            Channel: {selectedArtifact.eventData.channel}
                          </span>
                        </div>

                        <div className="grid grid-cols-2 md:grid-cols-4 gap-2 text-xs">
                          <div className="p-2 rounded bg-zinc-950 border border-zinc-900">
                            <span className="text-[10px] uppercase font-bold text-zinc-500 block mb-0.5">Computer</span>
                            <span className="font-mono text-xs text-zinc-300 break-all">{selectedArtifact.eventData.computer}</span>
                          </div>
                          <div className="p-2 rounded bg-zinc-950 border border-zinc-900">
                            <span className="text-[10px] uppercase font-bold text-zinc-500 block mb-0.5">Account / SID</span>
                            <span className="font-mono text-xs text-zinc-300 break-all">{selectedArtifact.eventData.userSid || selectedArtifact.eventData.accountName || 'N/A'}</span>
                          </div>
                          <div className="p-2 rounded bg-zinc-950 border border-zinc-900">
                            <span className="text-[10px] uppercase font-bold text-zinc-500 block mb-0.5">Provider</span>
                            <span className="font-mono text-xs text-zinc-300 break-all">{selectedArtifact.eventData.provider}</span>
                          </div>
                          <div className="p-2 rounded bg-zinc-950 border border-zinc-900">
                            <span className="text-[10px] uppercase font-bold text-zinc-500 block mb-0.5">Record ID</span>
                            <span className="font-mono text-xs text-zinc-300">{selectedArtifact.eventData.recordId}</span>
                          </div>
                        </div>

                        {selectedArtifact.eventData.commandLine && (
                          <div className="p-2.5 rounded bg-zinc-950 border border-zinc-900 space-y-1">
                            <span className="text-[10px] uppercase font-bold text-amber-400 flex items-center gap-1.5">
                              <Terminal className="w-3 h-3" />
                              Executed Command Line / Script Block
                            </span>
                            <pre className="text-xs font-mono text-amber-200 whitespace-pre-wrap break-all p-2 bg-black/40 rounded border border-zinc-900 select-all">
                              {selectedArtifact.eventData.commandLine}
                            </pre>
                          </div>
                        )}

                        {selectedArtifact.eventData.processName && (
                          <div className="text-xs font-mono text-zinc-400 flex items-center gap-2">
                            <span className="text-zinc-500 font-bold uppercase text-[10px]">Process:</span>
                            <span className="text-zinc-300 select-all">{selectedArtifact.eventData.processPath || selectedArtifact.eventData.processName}</span>
                          </div>
                        )}
                      </div>
                    )}

                    {/* Specialized Recent File / Shellbag Card */}
                    {selectedArtifact.recentFileData && (
                      <div className="p-3.5 rounded-lg bg-zinc-900/60 border border-zinc-800 space-y-2.5 font-sans">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-teal-950 text-teal-300 border border-teal-800">
                              {selectedArtifact.recentFileData.sourceArtifact}
                            </span>
                            <span className="text-xs font-bold text-zinc-200">{selectedArtifact.recentFileData.fileName}</span>
                          </div>
                          <span className="text-[10px] font-mono text-zinc-500 uppercase px-1.5 py-0.5 rounded bg-zinc-900 border border-zinc-800">
                            .{selectedArtifact.recentFileData.fileExtension}
                          </span>
                        </div>
                        <div className="p-2.5 rounded bg-zinc-950 border border-zinc-900 space-y-1">
                          <span className="text-[10px] uppercase font-bold text-zinc-500 block">Resolved File Target Path</span>
                          <p className="font-mono text-xs text-teal-300 select-all break-all">{selectedArtifact.recentFileData.targetPath}</p>
                        </div>
                        {selectedArtifact.recentFileData.mruIndex !== undefined && (
                          <div className="text-[11px] font-mono text-zinc-400">
                            MRU Position Index: <span className="text-zinc-200 font-bold">{selectedArtifact.recentFileData.mruIndex}</span>
                          </div>
                        )}
                      </div>
                    )}

                    {/* Specialized Email Card */}
                    {selectedArtifact.emailData && (
                      <div className="p-3.5 rounded-lg bg-zinc-900/60 border border-zinc-800 space-y-3 font-sans">
                        <div className="flex items-center justify-between">
                          <div className="flex items-center gap-2">
                            <span className="px-2 py-0.5 rounded text-xs font-mono font-bold bg-blue-950 text-blue-300 border border-blue-800">
                              {selectedArtifact.emailData.mailboxSource}
                            </span>
                            <span className="text-xs font-bold text-zinc-200 truncate max-w-md">{selectedArtifact.emailData.subject}</span>
                          </div>
                          <button
                            onClick={() => {
                              onSelectCategory('emails');
                              setEmailViewMode('outlook');
                            }}
                            className="px-2.5 py-1 rounded bg-blue-600 hover:bg-blue-500 text-white text-[10px] font-bold uppercase tracking-wider flex items-center gap-1.5 transition-colors shadow-sm"
                          >
                            <Mail className="w-3 h-3" />
                            Open In Outlook Layout
                          </button>
                        </div>
                        <div className="grid grid-cols-2 gap-2 text-xs">
                          <div className="p-2 rounded bg-zinc-950 border border-zinc-900">
                            <span className="text-[10px] uppercase font-bold text-zinc-500 block mb-0.5">Sender</span>
                            <span className="font-mono text-xs text-zinc-300 break-all">{selectedArtifact.emailData.from}</span>
                          </div>
                          <div className="p-2 rounded bg-zinc-950 border border-zinc-900">
                            <span className="text-[10px] uppercase font-bold text-zinc-500 block mb-0.5">Recipient(s)</span>
                            <span className="font-mono text-xs text-zinc-300 break-all">{selectedArtifact.emailData.to.join(', ')}</span>
                          </div>
                        </div>
                        {selectedArtifact.emailData.attachments.length > 0 && (
                          <div className="p-2 rounded bg-zinc-950 border border-zinc-900 space-y-1">
                            <span className="text-[10px] uppercase font-bold text-zinc-500 block">
                              Extracted Attachments ({selectedArtifact.emailData.attachments.length})
                            </span>
                            <div className="flex flex-wrap gap-1.5">
                              {selectedArtifact.emailData.attachments.map((att, i) => (
                                <span key={i} className={`px-2 py-0.5 rounded text-[11px] font-mono border ${
                                  att.isSuspicious 
                                    ? 'bg-red-950/80 text-red-300 border-red-800' 
                                    : 'bg-zinc-900 text-zinc-300 border-zinc-800'
                                }`}>
                                  {att.filename} ({att.size})
                                </span>
                              ))}
                            </div>
                          </div>
                        )}
                      </div>
                    )}

                    <div className="p-3 rounded bg-zinc-900/40 border border-zinc-800 space-y-1">
                      <div className="flex items-center justify-between">
                        <span className="text-[10px] font-bold uppercase tracking-wider text-zinc-500 font-sans">
                          Primary Extracted Artifact Value
                        </span>
                        <span className="text-[10px] text-zinc-500 font-mono">
                          Source: {selectedArtifact.sourceFile}
                        </span>
                      </div>
                      <p className="font-mono text-xs text-blue-300 break-all select-all bg-zinc-950 p-2 rounded border border-zinc-900">
                        {selectedArtifact.value}
                      </p>
                    </div>

                    <div className="grid grid-cols-2 md:grid-cols-3 gap-3 font-sans">
                      <div className="p-2.5 rounded bg-zinc-900/20 border border-zinc-900">
                        <span className="text-[10px] font-bold uppercase text-zinc-500 block mb-0.5">
                          Evidence Container
                        </span>
                        <span className="font-mono text-xs text-zinc-300 break-all">
                          {selectedArtifact.sourceFile}
                        </span>
                      </div>
                      <div className="p-2.5 rounded bg-zinc-900/20 border border-zinc-900">
                        <span className="text-[10px] font-bold uppercase text-zinc-500 block mb-0.5">
                          Internal Hive/Table Node
                        </span>
                        <span className="font-mono text-xs text-zinc-300 break-all">
                          {selectedArtifact.sourceLocation}
                        </span>
                      </div>
                      <div className="p-2.5 rounded bg-zinc-900/20 border border-zinc-900">
                        <span className="text-[10px] font-bold uppercase text-zinc-500 block mb-0.5">
                          Event Timestamp (UTC)
                        </span>
                        <span className="font-mono text-xs text-zinc-300">
                          {selectedArtifact.timestamp}
                        </span>
                      </div>
                    </div>

                    {/* Extracted Key-Value Properties */}
                    <div>
                      <h4 className="text-[10px] font-bold uppercase tracking-wider text-zinc-500 mb-2 font-sans">
                        Structured Metadata Fields ({Object.keys(selectedArtifact.details).length})
                      </h4>
                      <div className="grid grid-cols-1 md:grid-cols-2 gap-2 font-mono text-xs">
                        {Object.entries(selectedArtifact.details).map(([key, val]) => (
                          <div 
                            key={key} 
                            className="flex items-baseline justify-between p-2 rounded bg-zinc-900/30 border border-zinc-900"
                          >
                            <span className="text-zinc-500 text-[10px] uppercase font-bold shrink-0 mr-2">
                              {key}:
                            </span>
                            <span className="text-zinc-300 break-all text-right font-medium">
                              {String(val)}
                            </span>
                          </div>
                        ))}
                      </div>
                    </div>
                  </div>
                )}

                {activeDetailTab === 'analysis' && (
                  <div className="space-y-4 font-sans">
                    {selectedArtifact.isSuspicious ? (
                      <div className="p-4 rounded-lg bg-red-950/20 border border-red-900/50 space-y-2">
                        <div className="flex items-center gap-2 text-red-400 font-bold text-xs">
                          <AlertTriangle className="w-4 h-4" />
                          <span>Forensic Incident Flag Triggered</span>
                        </div>
                        <p className="text-xs text-red-300/90 leading-relaxed font-sans">
                          {selectedArtifact.suspiciousReason}
                        </p>
                      </div>
                    ) : (
                      <div className="p-3 rounded-lg bg-emerald-950/20 border border-emerald-900/40 flex items-center gap-2 text-emerald-400 text-xs">
                        <CheckCircle2 className="w-4 h-4" />
                        <span>Standard Operating Baseline — No anomalous or suspicious indicators flagged on this record.</span>
                      </div>
                    )}

                    <div className="p-3 rounded bg-zinc-900/30 border border-zinc-800 space-y-1.5">
                      <h4 className="text-[10px] font-bold uppercase tracking-wider text-zinc-400">
                        Artifact Context & Evidentiary Value
                      </h4>
                      <p className="text-xs text-zinc-400 leading-relaxed">
                        {selectedArtifact.description}
                      </p>
                    </div>

                    <div className="p-3 rounded bg-zinc-900/20 border border-zinc-900 space-y-1">
                      <span className="text-[10px] font-bold uppercase text-zinc-500 block">
                        Investigative Recommendation
                      </span>
                      <p className="text-xs text-zinc-400 leading-relaxed">
                        {selectedArtifact.isSuspicious 
                          ? 'Cross-reference timestamp with Prefetch execution logs, USB device connection history, and proxy network logs to establish full kill chain execution.' 
                          : 'Retain as baseline activity confirmation to verify normal user presence and standard workstation configuration.'}
                      </p>
                    </div>
                  </div>
                )}

                {activeDetailTab === 'raw' && (
                  <div className="h-full font-mono text-xs text-zinc-400 bg-zinc-950 p-3 rounded border border-zinc-900 overflow-auto whitespace-pre-wrap select-all">
                    {selectedArtifact.rawText || selectedArtifact.value}
                  </div>
                )}
              </div>
            </div>
          ) : (
            <div className="flex-1 flex items-center justify-center text-zinc-600 italic font-serif">
              Select an artifact above to examine detailed forensic attributes
            </div>
          )}
        </div>
      </div>
    </div>
  );
}
