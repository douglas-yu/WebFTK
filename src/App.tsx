/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useCallback, useEffect, useRef } from 'react';
import { motion, AnimatePresence } from 'motion/react';
import { 
  Plus, 
  FolderSearch, 
  FileSearch, 
  Settings, 
  LayoutDashboard, 
  Database, 
  Activity, 
  Search,
  HardDrive,
  Info,
  Terminal,
  Clock,
  ChevronRight,
  Filter
} from 'lucide-react';

import { ForensicFile, FolderNode, ViewMode } from './types';
import { calculateHash, getFileHead, detectSignature, formatBytes } from './lib/forensics';
import FileTable from './components/FileTable';
import SidebarTree from './components/SidebarTree';
import ContentViewer from './components/ContentViewer';

export default function App() {
  const [files, setFiles] = useState<Record<string, ForensicFile>>({});
  const [folders, setFolders] = useState<Record<string, FolderNode>>({});
  const [rootPaths, setRootPaths] = useState<string[]>([]);
  const [selectedFolderId, setSelectedFolderId] = useState<string>('');
  const [selectedFileId, setSelectedFileId] = useState<string | null>(null);
  const [viewMode, setViewMode] = useState<ViewMode>('explorer');
  const [isAnalyzing, setIsAnalyzing] = useState(false);
  const fileInputRef = useRef<HTMLInputElement>(null);
  const dirInputRef = useRef<HTMLInputElement>(null);

  // Helper to process added files into a tree
  const processFiles = useCallback(async (newFiles: FileList) => {
    setIsAnalyzing(true);
    const newFilesMap: Record<string, ForensicFile> = { ...files };
    const newFoldersMap: Record<string, FolderNode> = { ...folders };
    const newRootPaths: string[] = [...rootPaths];

    for (let i = 0; i < newFiles.length; i++) {
      const file = newFiles[i];
      const id = crypto.randomUUID();
      const relativePath = (file as any).webkitRelativePath || file.name;
      const pathParts = relativePath.split('/');
      
      // Handle the tree structure
      let currentPath = '';
      pathParts.forEach((part: string, idx: number) => {
        const isFile = idx === pathParts.length - 1;
        const parentPath = currentPath;
        currentPath = currentPath ? `${currentPath}/${part}` : part;

        if (isFile) {
          newFilesMap[id] = {
            id,
            file,
            name: file.name,
            size: file.size,
            type: file.type,
            lastModified: file.lastModified,
            status: 'pending',
            extensionMismatch: false,
            path: relativePath,
            parentPath
          };
          if (newFoldersMap[parentPath]) {
            newFoldersMap[parentPath].fileIds.push(id);
          }
        } else {
          if (!newFoldersMap[currentPath]) {
            newFoldersMap[currentPath] = {
              id: currentPath,
              name: part,
              path: currentPath,
              children: [],
              fileIds: []
            };
            if (parentPath && newFoldersMap[parentPath]) {
              newFoldersMap[parentPath].children.push(currentPath);
            } else if (!parentPath && !newRootPaths.includes(currentPath)) {
              newRootPaths.push(currentPath);
            }
          }
        }
      });
    }

    setFiles(newFilesMap);
    setFolders(newFoldersMap);
    setRootPaths(newRootPaths);
    
    // Auto-select first root if none selected
    if (!selectedFolderId && newRootPaths.length > 0) {
      setSelectedFolderId(newRootPaths[0]);
    }
    
    setIsAnalyzing(false);
  }, [files, folders, rootPaths, selectedFolderId]);

  const onDrop = (e: React.DragEvent) => {
    e.preventDefault();
    if (e.dataTransfer.files) processFiles(e.dataTransfer.files);
  };

  const handleAddFiles = (e: React.ChangeEvent<HTMLInputElement>) => {
    if (e.target.files) processFiles(e.target.files);
  };

  // Analysis Logic for pending files
  useEffect(() => {
    const pendingIds = Object.keys(files).filter(id => files[id].status === 'pending');
    if (pendingIds.length === 0) return;

    const analyzeBatch = async () => {
      for (const id of pendingIds) {
        const f = files[id];
        const head = await getFileHead(f.file, 32);
        const signature = detectSignature(head);
        const ext = f.name.split('.').pop()?.toLowerCase();
        let mismatch = false;
        if (signature && ext && signature.extension !== ext) {
          const aliases: Record<string, string[]> = {
            'jpg': ['jpeg'], 'jpeg': ['jpg'], 'exe': ['bin', 'dll']
          };
          if (!aliases[signature.extension]?.includes(ext)) {
            mismatch = true;
          }
        }

        const hash = await calculateHash(f.file, 'SHA-256');

        setFiles(prev => ({
          ...prev,
          [id]: {
            ...prev[id],
            status: 'analyzed',
            hash,
            signatureMatch: signature?.name,
            extensionMismatch: mismatch
          }
        }));
      }
    };

    analyzeBatch();
  }, [files]);

  // Derived data
  const currentFolder = folders[selectedFolderId];
  const filesInView = currentFolder ? currentFolder.fileIds.map(id => files[id]) : [];
  const selectedFile = selectedFileId ? files[selectedFileId] : null;

  return (
    <div className="flex h-screen bg-zinc-950 text-zinc-300 font-sans select-none overflow-hidden">
      {/* Sidebar Toolstrip */}
      <aside className="w-14 flex flex-col items-center py-4 border-r border-zinc-900 bg-zinc-950/80 gap-6 shrink-0">
        <div className="w-9 h-9 bg-blue-600 rounded flex items-center justify-center mb-4 shadow-lg shadow-blue-900/40">
           <Database className="text-white w-5 h-5 shadow-inner" />
        </div>
        <NavIcon icon={LayoutDashboard} active={viewMode === 'explorer'} onClick={() => setViewMode('explorer')} title="Case Explorer" />
        <NavIcon icon={Activity} active={false} onClick={() => {}} title="Active Registry" />
        <NavIcon icon={Terminal} active={false} onClick={() => {}} title="Triage Tools" />
        <div className="mt-auto flex flex-col gap-4">
          <NavIcon icon={Settings} active={false} onClick={() => {}} title="Preferences" />
        </div>
      </aside>

      {/* Main Framework */}
      <div className="flex-1 flex flex-col min-w-0">
        {/* Superior Control Bar */}
        <header className="h-12 border-b border-zinc-900 flex items-center justify-between px-6 bg-zinc-900/10 shrink-0">
          <div className="flex items-center gap-6">
            <h1 className="font-serif italic font-black text-lg text-white tracking-tight flex items-center gap-2">
              OpenCase <span className="h-4 w-px bg-zinc-800" /> <span className="text-zinc-600 font-sans not-italic text-[10px] uppercase font-bold tracking-widest">Digital Forensics Engine</span>
            </h1>
            <div className="flex gap-2">
              <button onClick={() => dirInputRef.current?.click()} className="bg-zinc-900 hover:bg-zinc-800 text-zinc-400 hover:text-white px-3 py-1 rounded text-[10px] font-bold uppercase transition-all flex items-center gap-2 border border-zinc-800">
                <FolderSearch className="w-3.5 h-3.5" /> Load Folder
              </button>
              <button onClick={() => fileInputRef.current?.click()} className="bg-zinc-900 hover:bg-zinc-800 text-zinc-400 hover:text-white px-3 py-1 rounded text-[10px] font-bold uppercase transition-all flex items-center gap-2 border border-zinc-800">
                <Plus className="w-3.5 h-3.5" /> Ad-hoc Image
              </button>
              <input type="file" multiple ref={fileInputRef} onChange={handleAddFiles} className="hidden" />
              <input type="file" multiple ref={dirInputRef} onChange={handleAddFiles} className="hidden" {...{ webkitdirectory: "", directory: "" } as any} />
            </div>
          </div>

          <div className="flex items-center gap-4">
            <div className="relative">
              <Search className="w-3.5 h-3.5 absolute left-3 top-1/2 -translate-y-1/2 text-zinc-600" />
              <input type="text" placeholder="Global filter..." className="bg-zinc-950 border border-zinc-900 rounded py-1 pl-9 pr-4 text-xs w-56 focus:outline-none focus:border-zinc-700 transition-colors" />
            </div>
            <div className={`px-2 py-0.5 rounded text-[9px] font-bold tracking-widest ${isAnalyzing ? 'bg-amber-900/40 text-amber-500 animate-pulse' : 'bg-green-900/20 text-green-500'}`}>
              {isAnalyzing ? 'ANALYZING' : 'IDLE'}
            </div>
          </div>
        </header>

        {/* Triple Panel Workspace */}
        <div 
          className="flex-1 flex min-h-0 bg-zinc-950 relative"
          onDragOver={(e) => e.preventDefault()}
          onDrop={onDrop}
        >
          {rootPaths.length === 0 ? (
            <div className="absolute inset-0 flex flex-col items-center justify-center p-12 text-center bg-zinc-950 z-50">
              <div className="w-24 h-24 bg-blue-600/10 rounded-full flex items-center justify-center mb-6 animate-pulse">
                <Database className="w-10 h-10 text-blue-500" />
              </div>
              <h2 className="text-2xl font-serif italic text-white mb-2">Initialize Forensic Workspace</h2>
              <p className="text-zinc-500 max-w-md text-sm mb-8 leading-relaxed">
                Drag and drop evidence files, logical images, or entire directory trees to begin your investigation. All processing occurs locally in your secure sandbox.
              </p>
              <div className="flex gap-4">
                <button onClick={() => dirInputRef.current?.click()} className="bg-blue-600 hover:bg-blue-500 text-white px-6 py-2 rounded font-bold uppercase text-[10px] tracking-widest transition-all">
                  Ingest Directory
                </button>
                <button onClick={() => fileInputRef.current?.click()} className="bg-zinc-800 hover:bg-zinc-700 text-zinc-300 px-6 py-2 rounded font-bold uppercase text-[10px] tracking-widest transition-all">
                  Select Files
                </button>
              </div>
            </div>
          ) : (
            <>
              {/* Panel 1: Tree Browser */}
          <aside className="w-72 border-r border-zinc-900 overflow-hidden flex flex-col shrink-0">
            <SidebarTree 
              folders={folders} 
              rootPaths={rootPaths} 
              selectedPath={selectedFolderId} 
              onSelectPath={setSelectedFolderId} 
            />
          </aside>

          {/* Right Container: Dual Vertical split */}
          <div className="flex-1 flex flex-col min-w-0">
            {/* Panel 2: File Listing (Encase Top view) */}
            <div className="flex-[0.5] min-h-0 flex flex-col">
              <div className="h-8 bg-zinc-900/30 flex items-center px-4 border-b border-zinc-900 text-[10px] font-bold text-zinc-500 gap-2">
                <div className="flex items-center gap-1">
                  <HardDrive className="w-3 h-3" />
                  <span>C:</span>
                </div>
                {selectedFolderId.split('/').map((part, i) => (
                  <React.Fragment key={i}>
                    <ChevronRight className="w-3 h-3 text-zinc-700" />
                    <span>{part}</span>
                  </React.Fragment>
                ))}
                <div className="ml-auto flex items-center gap-2">
                   <Filter className="w-3 h-3" />
                   <span>{filesInView.length} objects</span>
                </div>
              </div>
              <div className="flex-1 overflow-hidden p-0">
                <FileTable 
                  files={filesInView} 
                  selectedFileId={selectedFileId} 
                  onSelectFile={setSelectedFileId} 
                />
              </div>
            </div>

            {/* Panel 3: Content Preview (Encase Bottom view) */}
            <div className="flex-[0.5] min-h-0">
              <ContentViewer file={selectedFile} />
            </div>
          </div>
        </>
      )}
    </div>

    {/* Global Footer */}
        <footer className="h-6 border-t border-zinc-900 bg-zinc-950 shrink-0 px-4 flex items-center justify-between text-[10px] text-zinc-600 font-mono tracking-tighter">
          <div className="flex gap-4 items-center">
            <span className="flex items-center gap-1.5"><Terminal className="w-3 h-3" /> SYSTEM STATUS: READY</span>
            <div className="h-3 w-px bg-zinc-900" />
            <span>ALERTS: {Object.values(files).filter(f => f.extensionMismatch).length}</span>
          </div>
          <div className="flex gap-4">
            <span className="text-zinc-500">USER: ANALYST-01</span>
            <span className="text-zinc-400">BUILD: 1.4-LATEST</span>
          </div>
        </footer>
      </div>
    </div>
  );
}

function NavIcon({ icon: Icon, active, onClick, title }: any) {
  return (
    <button 
      onClick={onClick}
      title={title}
      className={`w-9 h-9 rounded flex items-center justify-center transition-all ${
        active ? 'bg-zinc-900 text-white border border-zinc-800' : 'text-zinc-700 hover:text-zinc-400 hover:bg-zinc-900/40'
      }`}
    >
      <Icon className="w-5 h-5 stroke-[1.5]" />
    </button>
  );
}

