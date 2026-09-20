/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useRef } from 'react';
import { 
  X, 
  Upload, 
  FolderArchive, 
  Globe, 
  PlaySquare, 
  Clock, 
  Usb, 
  Cpu, 
  Users, 
  CheckSquare, 
  Square, 
  FileText, 
  ShieldCheck, 
  Loader2,
  Trash2,
  CheckCircle2,
  AlertCircle,
  Terminal,
  Mail,
  FolderGit2,
  Sparkles
} from 'lucide-react';
import { ArtifactAnalysisOptions, ForensicArtifact } from '../types';
import { analyzeArtifactFiles } from '../lib/artifactParser';
import { formatBytes } from '../lib/forensics';
import { createSampleForensicFiles } from '../lib/sampleEvidence';

interface LoadArtifactModalProps {
  isOpen: boolean;
  onClose: () => void;
  onArtifactsLoaded: (artifacts: ForensicArtifact[], sourceFilesCount: number) => void;
}

export default function LoadArtifactModal({
  isOpen,
  onClose,
  onArtifactsLoaded
}: LoadArtifactModalProps) {
  const [selectedFiles, setSelectedFiles] = useState<File[]>([]);
  const [isProcessing, setIsProcessing] = useState<boolean>(false);
  const [progressStage, setProgressStage] = useState<string>('');
  const [progressPercent, setProgressPercent] = useState<number>(0);
  const fileInputRef = useRef<HTMLInputElement>(null);

  const [options, setOptions] = useState<ArtifactAnalysisOptions>({
    windowsEvents: true,
    recentFiles: true,
    pstEmails: true,
    browserHistory: true,
    registryHives: true,
    userActivities: true,
    usbHistory: true,
    systemInfo: true,
    userAccounts: true
  });

  if (!isOpen) return null;

  const toggleOption = (key: keyof ArtifactAnalysisOptions) => {
    setOptions(prev => ({ ...prev, [key]: !prev[key] }));
  };

  const selectAllOptions = (val: boolean) => {
    setOptions({
      windowsEvents: val,
      recentFiles: val,
      pstEmails: val,
      browserHistory: val,
      registryHives: val,
      userActivities: val,
      usbHistory: val,
      systemInfo: val,
      userAccounts: val
    });
  };

  const handleFileChange = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      const added = Array.from(e.target.files);
      setSelectedFiles(prev => [...prev, ...added]);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const dropped = Array.from(e.dataTransfer.files);
      setSelectedFiles(prev => [...prev, ...dropped]);
    }
  };

  const removeFile = (index: number) => {
    setSelectedFiles(prev => prev.filter((_, i) => i !== index));
  };

  const handleLoadSamples = () => {
    const samples = createSampleForensicFiles();
    setSelectedFiles(samples);
    setOptions({
      windowsEvents: true,
      recentFiles: true,
      pstEmails: true,
      browserHistory: true,
      registryHives: true,
      userActivities: true,
      usbHistory: true,
      systemInfo: true,
      userAccounts: true,
    });
  };

  const hasAnyOptionSelected = Object.values(options).some(Boolean);
  const canStart = selectedFiles.length > 0 && hasAnyOptionSelected && !isProcessing;

  const handleStartAnalysis = async () => {
    if (!canStart) return;
    setIsProcessing(true);
    setProgressPercent(10);
    setProgressStage('Initializing local forensic sandbox...');

    await new Promise(r => setTimeout(r, 250));
    setProgressPercent(30);
    setProgressStage('Extracting file streams and validating integrity...');

    await new Promise(r => setTimeout(r, 300));
    setProgressPercent(60);
    setProgressStage('Parsing registry hives, database tables, and USBSTOR keys...');

    await new Promise(r => setTimeout(r, 350));
    setProgressPercent(85);
    setProgressStage('Correlating timeline & flagging suspicious IOCs...');

    const extracted: ForensicArtifact[] = await analyzeArtifactFiles(selectedFiles, options);

    await new Promise(r => setTimeout(r, 200));
    setProgressPercent(100);
    setProgressStage('Extraction complete.');

    setIsProcessing(false);
    onArtifactsLoaded(extracted, selectedFiles.length);
    onClose();
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 overflow-y-auto animate-in fade-in duration-150">
      <div 
        className="w-full max-w-3xl bg-zinc-950 border border-zinc-800 rounded-xl shadow-2xl overflow-hidden flex flex-col text-zinc-300 font-sans my-8"
        onDragOver={(e) => e.preventDefault()}
        onDrop={handleDrop}
      >
        {/* Modal Header */}
        <div className="px-6 py-4 border-b border-zinc-900 bg-zinc-900/40 flex items-center justify-between">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-blue-600/20 border border-blue-500/30 flex items-center justify-center text-blue-400">
              <FolderArchive className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                Load Artifact File for Examination
                <span className="text-[10px] px-2 py-0.5 rounded bg-emerald-950/80 text-emerald-400 border border-emerald-800/40 font-mono lowercase">
                  local-only sandbox
                </span>
              </h2>
              <p className="text-xs text-zinc-500">
                Select forensic files/hives to parse & choose artifact analysis engines to execute.
              </p>
            </div>
          </div>
          <button 
            onClick={onClose}
            disabled={isProcessing}
            className="text-zinc-500 hover:text-zinc-300 p-1.5 rounded-lg hover:bg-zinc-900 transition-colors disabled:opacity-30"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Modal Body */}
        <div className="p-6 space-y-6 max-h-[75vh] overflow-y-auto custom-scrollbar">
          {/* Section 1: File Selection */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs font-bold uppercase tracking-wider text-zinc-400 flex items-center gap-2">
                <FileText className="w-3.5 h-3.5 text-blue-400" />
                1. Select Evidence / Artifact Files
              </label>
              <div className="flex items-center gap-3">
                <button
                  type="button"
                  onClick={handleLoadSamples}
                  className="text-xs text-blue-400 hover:text-blue-300 font-medium flex items-center gap-1.5 px-2.5 py-1 rounded bg-blue-500/10 hover:bg-blue-500/20 border border-blue-500/30 transition-colors"
                >
                  <Sparkles className="w-3.5 h-3.5" />
                  Load Sample Evidence (EVTX, PST, LNK)
                </button>
                <span className="text-[11px] text-zinc-500">
                  Local-only sandbox
                </span>
              </div>
            </div>

            <div>
              <div 
                onClick={() => fileInputRef.current?.click()}
                className="border-2 border-dashed border-zinc-800 hover:border-zinc-700 bg-zinc-900/20 hover:bg-zinc-900/40 rounded-lg p-5 text-center cursor-pointer transition-all flex flex-col items-center justify-center gap-2 group"
              >
                <div className="w-10 h-10 rounded-full bg-zinc-900 flex items-center justify-center text-zinc-500 group-hover:text-blue-400 transition-colors">
                  <Upload className="w-5 h-5" />
                </div>
                <div>
                  <p className="text-xs font-semibold text-zinc-300">
                    Click to choose artifact files or drag & drop here
                  </p>
                  <p className="text-[11px] text-zinc-500 mt-0.5">
                    Supports Windows Event Logs (.evtx, .xml), Recent Shellbags & LNK, Outlook Mailboxes (.pst, .ost, .eml, .msg), Registry Hives, and SQLite
                  </p>
                </div>
                <input 
                  type="file" 
                  ref={fileInputRef} 
                  multiple 
                  onChange={handleFileChange} 
                  className="hidden" 
                />
              </div>

              {selectedFiles.length > 0 && (
                  <div className="mt-3 space-y-1.5 max-h-36 overflow-y-auto custom-scrollbar">
                    <p className="text-[10px] uppercase font-bold text-zinc-500 tracking-wider">
                      Selected Files ({selectedFiles.length}):
                    </p>
                    {selectedFiles.map((f, idx) => (
                      <div 
                        key={idx} 
                        className="flex items-center justify-between px-3 py-1.5 rounded bg-zinc-900/60 border border-zinc-800 text-xs"
                      >
                        <div className="flex items-center gap-2 truncate">
                          <FileText className="w-3.5 h-3.5 text-zinc-500 shrink-0" />
                          <span className="font-mono text-zinc-300 truncate">{f.name}</span>
                          <span className="text-[10px] text-zinc-500 font-mono">({formatBytes(f.size)})</span>
                        </div>
                        <button
                          type="button"
                          onClick={() => removeFile(idx)}
                          className="text-zinc-600 hover:text-red-400 p-1"
                        >
                          <Trash2 className="w-3.5 h-3.5" />
                        </button>
                      </div>
                    ))}
                  </div>
                )}
              </div>
          </div>

          {/* Section 2: Artifact Analysis Options */}
          <div>
            <div className="flex items-center justify-between mb-2">
              <label className="text-xs font-bold uppercase tracking-wider text-zinc-400 flex items-center gap-2">
                <CheckSquare className="w-3.5 h-3.5 text-blue-400" />
                2. Choose Artifact Analysis To Perform
              </label>
              <div className="flex gap-2 text-[11px]">
                <button
                  type="button"
                  onClick={() => selectAllOptions(true)}
                  className="text-blue-400 hover:text-blue-300 underline underline-offset-2"
                >
                  Select All
                </button>
                <span className="text-zinc-700">|</span>
                <button
                  type="button"
                  onClick={() => selectAllOptions(false)}
                  className="text-zinc-500 hover:text-zinc-300 underline underline-offset-2"
                >
                  Clear All
                </button>
              </div>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-2.5">
              {/* Option 1: Windows Event Logs */}
              <AnalysisCheckboxCard
                checked={options.windowsEvents}
                onChange={() => toggleOption('windowsEvents')}
                icon={Terminal}
                iconColor="text-emerald-400"
                title="Windows Event Logs (EVTX / XML)"
                description="Security audit (4624 logon, 4625 brute force, 4688 process creation), 1102 log cleared, and PowerShell 4104 blocks."
              />

              {/* Option 2: Recent Files & Shellbags */}
              <AnalysisCheckboxCard
                checked={options.recentFiles}
                onChange={() => toggleOption('recentFiles')}
                icon={FolderGit2}
                iconColor="text-teal-400"
                title="Recent Files & Shellbags"
                description="LNK shortcuts, JumpLists (Destinations-ms), Shellbags folder navigation, RecentDocs MRU, and office documents."
              />

              {/* Option 3: PST / OST / EML Email Mailbox */}
              <AnalysisCheckboxCard
                checked={options.pstEmails}
                onChange={() => toggleOption('pstEmails')}
                icon={Mail}
                iconColor="text-blue-400"
                title="Outlook PST / OST / EML Mailbox"
                description="Extract emails, senders, recipients, subjects, attachments, and detect phishing threats with 3-pane Outlook view."
              />

              {/* Option 4: Browser History */}
              <AnalysisCheckboxCard
                checked={options.browserHistory}
                onChange={() => toggleOption('browserHistory')}
                icon={Globe}
                iconColor="text-sky-400"
                title="Internet & Browser History"
                description="Visits, typed URLs, downloads, search queries, web cache from Chrome, Edge & Firefox."
              />

              {/* Option 5: Registry Hives / Run Keys */}
              <AnalysisCheckboxCard
                checked={options.registryHives}
                onChange={() => toggleOption('registryHives')}
                icon={PlaySquare}
                iconColor="text-rose-400"
                title="Registry Hive Analysis (Run / RunOnce)"
                description="Auto-start persistence, Shell folders, Run/RunOnce keys, and suspicious startup commands."
              />

              {/* Option 6: Recent User Activities */}
              <AnalysisCheckboxCard
                checked={options.userActivities}
                onChange={() => toggleOption('userActivities')}
                icon={Clock}
                iconColor="text-purple-400"
                title="Recent User Activities"
                description="UserAssist ROT13, Prefetch execution traces, application launches, and system interaction history."
              />

              {/* Option 7: USB Connect History */}
              <AnalysisCheckboxCard
                checked={options.usbHistory}
                onChange={() => toggleOption('usbHistory')}
                icon={Usb}
                iconColor="text-amber-400"
                title="USB Device Connection History"
                description="USBSTOR removable storage devices, serial numbers, VID/PID, and MountedDevices drive letters."
              />

              {/* Option 8: System & OS Info */}
              <AnalysisCheckboxCard
                checked={options.systemInfo}
                onChange={() => toggleOption('systemInfo')}
                icon={Cpu}
                iconColor="text-emerald-400"
                title="System & OS Information"
                description="CurrentControlSet, computer hostname, OS build version, time zone bias, and network adapters."
              />

              {/* Option 9: User Accounts & Security */}
              <AnalysisCheckboxCard
                checked={options.userAccounts}
                onChange={() => toggleOption('userAccounts')}
                icon={Users}
                iconColor="text-indigo-400"
                title="User Accounts & Security"
                description="SAM database accounts, Relative Identifiers (RIDs), account privileges, and logon profiles."
              />
            </div>
          </div>

          {/* Privacy & Engine Badge */}
          <div className="p-3 bg-zinc-900/30 border border-zinc-900 rounded-lg flex items-center gap-3 text-zinc-500 text-xs">
            <ShieldCheck className="w-4 h-4 text-emerald-500 shrink-0" />
            <span className="leading-relaxed">
              <strong>Local Forensic Privacy:</strong> Parsing executes client-side in WebAssembly/JavaScript. No evidence, hashes, or decrypted artifacts are sent to external servers.
            </span>
          </div>

          {/* Progress Indicator (when running) */}
          {isProcessing && (
            <div className="space-y-2 p-3 bg-zinc-900/60 rounded-lg border border-zinc-800">
              <div className="flex justify-between text-xs font-mono">
                <span className="text-zinc-300 flex items-center gap-2">
                  <Loader2 className="w-3.5 h-3.5 animate-spin text-blue-400" />
                  {progressStage}
                </span>
                <span className="text-blue-400 font-bold">{progressPercent}%</span>
              </div>
              <div className="w-full bg-zinc-800 h-1.5 rounded-full overflow-hidden">
                <div 
                  className="bg-blue-500 h-full transition-all duration-300 rounded-full"
                  style={{ width: `${progressPercent}%` }}
                />
              </div>
            </div>
          )}
        </div>

        {/* Modal Footer */}
        <div className="px-6 py-3.5 border-t border-zinc-900 bg-zinc-900/30 flex items-center justify-between">
          <span className="text-xs text-zinc-500 font-mono">
            {selectedFiles.length === 0 ? 'No files queued' : `${selectedFiles.length} file(s) queued for extraction`}
          </span>
          <div className="flex gap-2.5">
            <button
              type="button"
              onClick={onClose}
              disabled={isProcessing}
              className="px-4 py-2 rounded text-xs font-semibold text-zinc-400 hover:text-white bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 transition-colors disabled:opacity-40"
            >
              Cancel
            </button>
            <button
              type="button"
              onClick={handleStartAnalysis}
              disabled={!canStart || isProcessing}
              className="px-5 py-2 rounded text-xs font-bold uppercase tracking-wider text-white bg-blue-600 hover:bg-blue-500 disabled:bg-zinc-800 disabled:text-zinc-600 disabled:cursor-not-allowed transition-all shadow-lg shadow-blue-900/20 flex items-center gap-2"
            >
              {isProcessing ? (
                <>
                  <Loader2 className="w-4 h-4 animate-spin" />
                  Analyzing Artifacts...
                </>
              ) : (
                <>
                  <FolderArchive className="w-4 h-4" />
                  Start Forensic Extraction
                </>
              )}
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}

function AnalysisCheckboxCard({
  checked,
  onChange,
  icon: Icon,
  iconColor,
  title,
  description
}: {
  checked: boolean;
  onChange: () => void;
  icon: any;
  iconColor: string;
  title: string;
  description: string;
}) {
  return (
    <div
      onClick={onChange}
      className={`p-3 rounded-lg border cursor-pointer transition-all flex items-start gap-3 select-none ${
        checked
          ? 'bg-zinc-900/80 border-blue-500/50 text-white shadow-sm'
          : 'bg-zinc-900/20 border-zinc-800/70 text-zinc-500 hover:border-zinc-700'
      }`}
    >
      <div className="pt-0.5 shrink-0">
        {checked ? (
          <CheckSquare className="w-4 h-4 text-blue-400" />
        ) : (
          <Square className="w-4 h-4 text-zinc-600" />
        )}
      </div>
      <div className="space-y-0.5">
        <div className="flex items-center gap-1.5">
          <Icon className={`w-3.5 h-3.5 ${iconColor}`} />
          <span className={`text-xs font-bold ${checked ? 'text-zinc-200' : 'text-zinc-400'}`}>
            {title}
          </span>
        </div>
        <p className="text-[11px] text-zinc-500 leading-snug">
          {description}
        </p>
      </div>
    </div>
  );
}
