/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useRef } from 'react';
import {
  HardDrive,
  FolderArchive,
  Upload,
  FileCheck,
  AlertCircle,
  X,
  FileSearch,
  Sparkles,
  Layers,
  Database,
  Calendar,
  User,
  Hash,
  ShieldCheck,
  Cpu
} from 'lucide-react';
import {
  parseForensicDiskImage,
  createSampleE01ImageFile,
  createSampleDdImageFile,
  isDiskImageFile
} from '../lib/diskImageParser';
import { DiskImageParseResult } from '../types';
import { formatBytes } from '../lib/forensics';

interface LoadDiskImageModalProps {
  isOpen: boolean;
  onClose: () => void;
  onDiskImageLoaded: (result: DiskImageParseResult) => void;
}

export default function LoadDiskImageModal({
  isOpen,
  onClose,
  onDiskImageLoaded,
}: LoadDiskImageModalProps) {
  const [selectedFile, setSelectedFile] = useState<File | null>(null);
  const [isParsing, setIsParsing] = useState(false);
  const [progressStage, setProgressStage] = useState<string>('');
  const [progressPercent, setProgressPercent] = useState<number>(0);
  const [errorMessage, setErrorMessage] = useState<string | null>(null);

  const fileInputRef = useRef<HTMLInputElement>(null);

  if (!isOpen) return null;

  const handleFileSelect = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files && e.target.files.length > 0) {
      const file = e.target.files[0];
      setSelectedFile(file);
      setErrorMessage(null);
    }
  };

  const handleDrop = (e: React.DragEvent) => {
    e.preventDefault();
    if (e.dataTransfer.files && e.dataTransfer.files.length > 0) {
      const file = e.dataTransfer.files[0];
      setSelectedFile(file);
      setErrorMessage(null);
    }
  };

  const handleMountImage = async (fileToParse?: File) => {
    const targetFile = fileToParse || selectedFile;
    if (!targetFile) return;

    setIsParsing(true);
    setErrorMessage(null);
    setProgressPercent(10);
    setProgressStage('Reading forensic image header...');

    try {
      const result = await parseForensicDiskImage(targetFile, (stage, pct) => {
        setProgressStage(stage);
        setProgressPercent(pct);
      });

      onDiskImageLoaded(result);
      onClose();
    } catch (err: any) {
      console.error('Error parsing disk image:', err);
      setErrorMessage(err?.message || 'Failed to parse forensic disk image structure');
    } finally {
      setIsParsing(false);
    }
  };

  const loadSampleE01 = () => {
    const sample = createSampleE01ImageFile();
    setSelectedFile(sample);
    handleMountImage(sample);
  };

  const loadSampleDd = () => {
    const sample = createSampleDdImageFile();
    setSelectedFile(sample);
    handleMountImage(sample);
  };

  return (
    <div className="fixed inset-0 z-50 flex items-center justify-center bg-black/80 backdrop-blur-sm p-4 animate-in fade-in duration-200">
      <div className="bg-zinc-950 border border-zinc-800 rounded-xl shadow-2xl max-w-2xl w-full flex flex-col max-h-[90vh] overflow-hidden text-zinc-300 font-sans">
        {/* Header */}
        <div className="px-6 py-4 border-b border-zinc-900 flex items-center justify-between bg-zinc-900/30">
          <div className="flex items-center gap-3">
            <div className="w-9 h-9 rounded-lg bg-blue-600/20 border border-blue-500/40 flex items-center justify-center text-blue-400">
              <HardDrive className="w-5 h-5" />
            </div>
            <div>
              <h2 className="text-sm font-bold text-white uppercase tracking-wider flex items-center gap-2">
                Load Forensic Disk Image
                <span className="px-2 py-0.5 rounded text-[9px] bg-blue-900/50 text-blue-300 border border-blue-800/50">
                  E01 / DD / RAW
                </span>
              </h2>
              <p className="text-[11px] text-zinc-500">
                Mount Expert Witness (E01) or Bitstream (DD/RAW) images into the Filesystem Tree
              </p>
            </div>
          </div>
          <button
            onClick={onClose}
            disabled={isParsing}
            className="text-zinc-500 hover:text-zinc-300 p-1.5 rounded-lg hover:bg-zinc-900 transition-colors"
          >
            <X className="w-5 h-5" />
          </button>
        </div>

        {/* Content Body */}
        <div className="p-6 overflow-y-auto space-y-6 custom-scrollbar text-xs">
          {/* Quick Pre-loaded Samples */}
          <div>
            <div className="flex items-center justify-between mb-2.5">
              <span className="font-bold text-zinc-300 uppercase text-[10px] tracking-wider flex items-center gap-1.5">
                <Sparkles className="w-3.5 h-3.5 text-blue-400" />
                Ready-to-Explore Sample Evidence Images
              </span>
              <span className="text-[10px] text-zinc-500">1-Click Instant Mounting</span>
            </div>

            <div className="grid grid-cols-1 md:grid-cols-2 gap-3">
              {/* E01 Sample Card */}
              <button
                type="button"
                onClick={loadSampleE01}
                disabled={isParsing}
                className="text-left p-3.5 rounded-lg border border-zinc-800 bg-zinc-900/40 hover:bg-zinc-900/80 hover:border-blue-500/50 transition-all group flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="font-bold text-white text-xs flex items-center gap-1.5">
                      <HardDrive className="w-3.5 h-3.5 text-blue-400 group-hover:scale-110 transition-transform" />
                      EnCase Evidence (E01)
                    </span>
                    <span className="px-1.5 py-0.5 rounded bg-blue-950 text-blue-400 font-mono text-[9px] font-bold border border-blue-900/40">
                      E01 Image
                    </span>
                  </div>
                  <p className="text-[11px] text-zinc-400 leading-relaxed mb-2">
                    Expert Witness Format with Case metadata, MBR, NTFS System volume, and recovered deleted malware traces.
                  </p>
                </div>
                <div className="flex items-center gap-2 pt-2 border-t border-zinc-800/60 text-[10px] text-zinc-500 font-mono">
                  <span>Case: 2026-CYBER-891</span>
                  <span>•</span>
                  <span>NTFS + FAT32</span>
                  <span>•</span>
                  <span className="text-red-400 font-bold">Deleted Files</span>
                </div>
              </button>

              {/* DD Sample Card */}
              <button
                type="button"
                onClick={loadSampleDd}
                disabled={isParsing}
                className="text-left p-3.5 rounded-lg border border-zinc-800 bg-zinc-900/40 hover:bg-zinc-900/80 hover:border-emerald-500/50 transition-all group flex flex-col justify-between"
              >
                <div>
                  <div className="flex items-center justify-between mb-1.5">
                    <span className="font-bold text-white text-xs flex items-center gap-1.5">
                      <Database className="w-3.5 h-3.5 text-emerald-400 group-hover:scale-110 transition-transform" />
                      Raw Bitstream Disk (.dd)
                    </span>
                    <span className="px-1.5 py-0.5 rounded bg-emerald-950 text-emerald-400 font-mono text-[9px] font-bold border border-emerald-900/40">
                      RAW / DD
                    </span>
                  </div>
                  <p className="text-[11px] text-zinc-400 leading-relaxed mb-2">
                    Raw sector physical disk image containing MBR partition tables, user profile data, and unallocated clusters.
                  </p>
                </div>
                <div className="flex items-center gap-2 pt-2 border-t border-zinc-800/60 text-[10px] text-zinc-500 font-mono">
                  <span>MBR Partitioned</span>
                  <span>•</span>
                  <span>Sector by Sector</span>
                  <span>•</span>
                  <span className="text-emerald-400 font-bold">Dual Partition</span>
                </div>
              </button>
            </div>
          </div>

          <div className="relative flex py-1 items-center">
            <div className="flex-grow border-t border-zinc-900"></div>
            <span className="flex-shrink mx-4 text-zinc-600 uppercase text-[9px] font-bold tracking-widest">
              Or Ingest Local Disk Image File
            </span>
            <div className="flex-grow border-t border-zinc-900"></div>
          </div>

          {/* Upload Dropzone */}
          <div>
            <div
              onDragOver={(e) => e.preventDefault()}
              onDrop={handleDrop}
              onClick={() => fileInputRef.current?.click()}
              className={`border-2 border-dashed rounded-xl p-6 text-center cursor-pointer transition-all ${
                selectedFile
                  ? 'border-blue-500/60 bg-blue-950/10'
                  : 'border-zinc-800 hover:border-zinc-700 bg-zinc-900/20 hover:bg-zinc-900/40'
              }`}
            >
              <input
                ref={fileInputRef}
                type="file"
                accept=".e01,.ex01,.dd,.raw,.img,.iso,.vmdk,.001"
                onChange={handleFileSelect}
                className="hidden"
              />

              {selectedFile ? (
                <div className="flex flex-col items-center">
                  <div className="w-10 h-10 rounded-full bg-blue-600/20 text-blue-400 flex items-center justify-center mb-2">
                    <FileCheck className="w-5 h-5" />
                  </div>
                  <span className="font-bold text-white text-xs">{selectedFile.name}</span>
                  <span className="text-[10px] font-mono text-zinc-500 mt-1">
                    {formatBytes(selectedFile.size)} • Format:{' '}
                    {selectedFile.name.split('.').pop()?.toUpperCase() || 'RAW'}
                  </span>
                  <span className="text-[10px] text-blue-400 mt-2 font-medium">Click to select a different file</span>
                </div>
              ) : (
                <div className="flex flex-col items-center">
                  <div className="w-10 h-10 rounded-full bg-zinc-900 text-zinc-500 flex items-center justify-center mb-2">
                    <Upload className="w-5 h-5" />
                  </div>
                  <span className="font-bold text-zinc-300 text-xs">Drag & drop forensic disk image here</span>
                  <p className="text-[11px] text-zinc-500 mt-1">
                    Supports <span className="text-zinc-300">.E01, .Ex01, .dd, .raw, .img, .iso, .001</span>
                  </p>
                  <p className="text-[10px] text-zinc-600 mt-2">
                    Parses MBR / GPT partition schemes, NTFS ($MFT), and FAT32 directory trees into the evidence tree.
                  </p>
                </div>
              )}
            </div>
          </div>

          {/* Progress / Status Display */}
          {isParsing && (
            <div className="p-4 rounded-lg bg-zinc-900/80 border border-blue-900/40 space-y-2">
              <div className="flex justify-between items-center text-[11px]">
                <span className="text-blue-400 font-medium flex items-center gap-1.5">
                  <Cpu className="w-3.5 h-3.5 animate-spin" />
                  {progressStage}
                </span>
                <span className="font-mono text-zinc-400">{progressPercent}%</span>
              </div>
              <div className="h-1.5 w-full bg-zinc-800 rounded-full overflow-hidden">
                <div
                  className="h-full bg-blue-600 transition-all duration-300 ease-out"
                  style={{ width: `${progressPercent}%` }}
                />
              </div>
            </div>
          )}

          {errorMessage && (
            <div className="p-3 rounded-lg bg-red-950/40 border border-red-900/50 flex items-center gap-2.5 text-red-400 text-xs">
              <AlertCircle className="w-4 h-4 shrink-0" />
              <span>{errorMessage}</span>
            </div>
          )}
        </div>

        {/* Footer */}
        <div className="px-6 py-3.5 border-t border-zinc-900 bg-zinc-900/30 flex items-center justify-between">
          <div className="text-[10px] text-zinc-500 font-mono flex items-center gap-1.5">
            <ShieldCheck className="w-3.5 h-3.5 text-zinc-600" />
            <span>Read-only bitstream parsing preserving original image integrity</span>
          </div>

          <div className="flex gap-2">
            <button
              onClick={onClose}
              disabled={isParsing}
              className="px-4 py-1.5 rounded text-xs font-bold uppercase tracking-wider text-zinc-400 hover:text-white bg-zinc-900 hover:bg-zinc-800 border border-zinc-800 transition-all"
            >
              Cancel
            </button>
            <button
              onClick={() => handleMountImage()}
              disabled={!selectedFile || isParsing}
              className={`px-4 py-1.5 rounded text-xs font-bold uppercase tracking-wider text-white flex items-center gap-1.5 transition-all shadow-md ${
                !selectedFile || isParsing
                  ? 'bg-zinc-800 text-zinc-500 cursor-not-allowed border border-zinc-700/50'
                  : 'bg-blue-600 hover:bg-blue-500 border border-blue-500/50 shadow-blue-900/30'
              }`}
            >
              <HardDrive className="w-3.5 h-3.5" />
              Mount to Evidence Tree
            </button>
          </div>
        </div>
      </div>
    </div>
  );
}
