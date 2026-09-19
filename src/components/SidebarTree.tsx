/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { 
  Folder, 
  FolderOpen, 
  ChevronRight, 
  ChevronDown, 
  HardDrive,
  Layers,
  Globe,
  Clock,
  Cpu,
  Usb,
  PlaySquare,
  Users,
  PlusCircle,
  ShieldAlert,
  Terminal,
  FolderGit2,
  Mail
} from 'lucide-react';
import { FolderNode, ArtifactCategory, SidebarMode, ForensicArtifact } from '../types';

interface SidebarTreeProps {
  folders: Record<string, FolderNode>;
  rootPaths: string[];
  selectedPath: string;
  onSelectPath: (path: string) => void;
  sidebarMode: SidebarMode;
  onSelectSidebarMode: (mode: SidebarMode) => void;
  artifacts: ForensicArtifact[];
  activeArtifactCategory: ArtifactCategory;
  onSelectArtifactCategory: (category: ArtifactCategory) => void;
  onOpenLoadModal: () => void;
}

export default function SidebarTree({ 
  folders, 
  rootPaths, 
  selectedPath, 
  onSelectPath,
  sidebarMode,
  onSelectSidebarMode,
  artifacts,
  activeArtifactCategory,
  onSelectArtifactCategory,
  onOpenLoadModal
}: SidebarTreeProps) {
  // Category counts
  const categoryCounts = React.useMemo(() => {
    const counts: Record<string, number> = {
      all: artifacts.length,
      windows_events: 0,
      recent_files: 0,
      emails: 0,
      browser_history: 0,
      user_activity: 0,
      system_info: 0,
      usb_connect: 0,
      run_keys: 0,
      user_accounts: 0
    };
    for (const art of artifacts) {
      if (counts[art.category] !== undefined) {
        counts[art.category]++;
      }
    }
    return counts;
  }, [artifacts]);

  const suspiciousCount = React.useMemo(() => {
    return artifacts.filter(a => a.isSuspicious).length;
  }, [artifacts]);

  return (
    <div className="flex flex-col h-full bg-zinc-950 font-sans text-xs">
      {/* Top Sidebar Mode Navigation */}
      <div className="flex border-b border-zinc-900 bg-zinc-900/40 p-1 gap-1">
        <button
          onClick={() => onSelectSidebarMode('tree')}
          className={`flex-1 py-1.5 px-2 rounded font-bold uppercase tracking-wider text-[10px] flex items-center justify-center gap-1.5 transition-all ${
            sidebarMode === 'tree'
              ? 'bg-zinc-800 text-white shadow-sm'
              : 'text-zinc-500 hover:text-zinc-300 hover:bg-zinc-900/50'
          }`}
        >
          <HardDrive className="w-3.5 h-3.5" />
          <span>Evidence Tree</span>
        </button>
        <button
          onClick={() => onSelectSidebarMode('artifacts')}
          className={`flex-1 py-1.5 px-2 rounded font-bold uppercase tracking-wider text-[10px] flex items-center justify-center gap-1.5 transition-all ${
            sidebarMode === 'artifacts'
              ? 'bg-zinc-800 text-white shadow-sm'
              : 'text-zinc-500 hover:text-zinc-300 hover:bg-zinc-900/50'
          }`}
        >
          <Layers className="w-3.5 h-3.5 text-blue-400" />
          <span>Artifacts</span>
          {artifacts.length > 0 && (
            <span className="px-1.5 py-0.2 rounded-full bg-blue-950 text-blue-300 text-[9px] font-mono">
              {artifacts.length}
            </span>
          )}
        </button>
      </div>

      {/* Mode 1: Directory Tree */}
      {sidebarMode === 'tree' && (
        <div className="flex-1 flex flex-col min-h-0">
          <div className="px-3 py-2 border-b border-zinc-900/60 flex items-center justify-between bg-zinc-950 text-[10px] text-zinc-500 font-bold uppercase tracking-wider">
            <span>Filesystem Hierarchies</span>
            <span>{rootPaths.length} Root{rootPaths.length !== 1 ? 's' : ''}</span>
          </div>

          <div className="flex-1 overflow-auto py-2 custom-scrollbar">
            {rootPaths.map(path => (
              <TreeNode 
                key={path}
                node={folders[path]}
                folders={folders}
                selectedPath={selectedPath}
                onSelectPath={onSelectPath}
                depth={0}
              />
            ))}
            {rootPaths.length === 0 && (
              <div className="px-4 py-8 text-center text-zinc-600 italic">
                No filesystem evidence loaded
              </div>
            )}
          </div>

          {/* Quick Artifact Access Banner in Tree Mode */}
          <div className="p-2 border-t border-zinc-900 bg-zinc-900/20">
            <button
              onClick={() => onSelectSidebarMode('artifacts')}
              className="w-full py-1.5 px-2.5 rounded bg-zinc-900 hover:bg-zinc-850 border border-zinc-800 text-zinc-300 hover:text-white flex items-center justify-between text-[11px] font-medium transition-all group"
            >
              <div className="flex items-center gap-2">
                <Layers className="w-3.5 h-3.5 text-blue-400 group-hover:scale-110 transition-transform" />
                <span>Forensic Artifacts</span>
              </div>
              <span className="text-[10px] font-mono px-1.5 py-0.5 rounded bg-zinc-800 text-zinc-400">
                {artifacts.length}
              </span>
            </button>
          </div>
        </div>
      )}

      {/* Mode 2: Categorized Artifacts Explorer */}
      {sidebarMode === 'artifacts' && (
        <div className="flex-1 flex flex-col min-h-0">
          <div className="px-3 py-2 border-b border-zinc-900/60 flex items-center justify-between bg-zinc-950 text-[10px] text-zinc-500 font-bold uppercase tracking-wider">
            <span>Artifact Categories</span>
            {suspiciousCount > 0 && (
              <span className="flex items-center gap-1 text-red-400 font-mono text-[9px] bg-red-950/60 px-1.5 py-0.5 rounded border border-red-900/40">
                <ShieldAlert className="w-3 h-3" />
                {suspiciousCount} Flagged
              </span>
            )}
          </div>

          <div className="flex-1 overflow-auto py-1 custom-scrollbar space-y-0.5 px-1.5">
            <CategoryItem
              active={activeArtifactCategory === 'all'}
              onClick={() => onSelectArtifactCategory('all')}
              icon={Layers}
              iconColor="text-zinc-400"
              label="All Collected Artifacts"
              count={categoryCounts.all}
            />
            <CategoryItem
              active={activeArtifactCategory === 'windows_events'}
              onClick={() => onSelectArtifactCategory('windows_events')}
              icon={Terminal}
              iconColor="text-emerald-400"
              label="Windows Event Logs"
              count={categoryCounts.windows_events}
            />
            <CategoryItem
              active={activeArtifactCategory === 'recent_files'}
              onClick={() => onSelectArtifactCategory('recent_files')}
              icon={FolderGit2}
              iconColor="text-teal-400"
              label="Recent Files & Shellbags"
              count={categoryCounts.recent_files}
            />
            <CategoryItem
              active={activeArtifactCategory === 'emails'}
              onClick={() => onSelectArtifactCategory('emails')}
              icon={Mail}
              iconColor="text-blue-400"
              label="Emails & PST Mailbox"
              count={categoryCounts.emails}
            />
            <CategoryItem
              active={activeArtifactCategory === 'browser_history'}
              onClick={() => onSelectArtifactCategory('browser_history')}
              icon={Globe}
              iconColor="text-sky-400"
              label="Browser History"
              count={categoryCounts.browser_history}
            />
            <CategoryItem
              active={activeArtifactCategory === 'user_activity'}
              onClick={() => onSelectArtifactCategory('user_activity')}
              icon={Clock}
              iconColor="text-purple-400"
              label="Recent User Activities"
              count={categoryCounts.user_activity}
            />
            <CategoryItem
              active={activeArtifactCategory === 'system_info'}
              onClick={() => onSelectArtifactCategory('system_info')}
              icon={Cpu}
              iconColor="text-emerald-400"
              label="System & OS Info"
              count={categoryCounts.system_info}
            />
            <CategoryItem
              active={activeArtifactCategory === 'usb_connect'}
              onClick={() => onSelectArtifactCategory('usb_connect')}
              icon={Usb}
              iconColor="text-amber-400"
              label="USB Connection History"
              count={categoryCounts.usb_connect}
            />
            <CategoryItem
              active={activeArtifactCategory === 'run_keys'}
              onClick={() => onSelectArtifactCategory('run_keys')}
              icon={PlaySquare}
              iconColor="text-rose-400"
              label="Run & Auto-Start Keys"
              count={categoryCounts.run_keys}
            />
            <CategoryItem
              active={activeArtifactCategory === 'user_accounts'}
              onClick={() => onSelectArtifactCategory('user_accounts')}
              icon={Users}
              iconColor="text-indigo-400"
              label="User Accounts & Security"
              count={categoryCounts.user_accounts}
            />
          </div>

          {/* Load / Import Artifact File Action in Sidebar */}
          <div className="p-2 border-t border-zinc-900 bg-zinc-900/30">
            <button
              onClick={onOpenLoadModal}
              className="w-full py-1.5 px-3 rounded bg-blue-600 hover:bg-blue-500 text-white font-bold uppercase tracking-wider text-[10px] flex items-center justify-center gap-1.5 transition-all shadow-md shadow-blue-900/20"
            >
              <PlusCircle className="w-3.5 h-3.5" />
              <span>Load Artifact File</span>
            </button>
          </div>
        </div>
      )}
    </div>
  );
}

function CategoryItem({
  active,
  onClick,
  icon: Icon,
  iconColor,
  label,
  count
}: {
  active: boolean;
  onClick: () => void;
  icon: any;
  iconColor: string;
  label: string;
  count: number;
}) {
  return (
    <button
      onClick={onClick}
      className={`w-full flex items-center justify-between px-2.5 py-2 rounded text-left transition-all ${
        active
          ? 'bg-blue-900/30 text-white border border-blue-500/30 font-medium'
          : 'text-zinc-400 hover:text-zinc-200 hover:bg-zinc-900/60'
      }`}
    >
      <div className="flex items-center gap-2 truncate">
        <Icon className={`w-3.5 h-3.5 shrink-0 ${iconColor}`} />
        <span className="truncate text-xs">{label}</span>
      </div>
      <span className={`text-[10px] font-mono px-1.5 py-0.5 rounded ${
        active 
          ? 'bg-blue-500/20 text-blue-300 font-bold' 
          : 'bg-zinc-900 text-zinc-500'
      }`}>
        {count}
      </span>
    </button>
  );
}

function TreeNode({ node, folders, selectedPath, onSelectPath, depth }: any) {
  const [isOpen, setIsOpen] = useState(depth === 0);
  const isSelected = selectedPath === node.path;
  const hasChildren = node.children.length > 0;

  return (
    <div>
      <div 
        onClick={() => {
          onSelectPath(node.path);
          if (hasChildren) setIsOpen(!isOpen);
        }}
        className={`flex items-center gap-1 py-1.5 px-2 cursor-pointer transition-colors ${
          isSelected ? 'bg-blue-900/30 text-blue-400 border-r-2 border-blue-500' : 'hover:bg-zinc-900 text-zinc-400'
        }`}
        style={{ paddingLeft: `${(depth * 12) + 8}px` }}
      >
        <span className="w-4 flex items-center justify-center">
          {hasChildren ? (
            isOpen ? <ChevronDown className="w-3 h-3" /> : <ChevronRight className="w-3 h-3" />
          ) : null}
        </span>
        {isOpen ? <FolderOpen className="w-3.5 h-3.5 text-blue-500/50" /> : <Folder className="w-3.5 h-3.5 text-zinc-600" />}
        <span className="truncate">{node.name || 'Root'}</span>
      </div>
      
      {isOpen && hasChildren && (
        <div className="animate-in fade-in slide-in-from-top-1 duration-200">
          {node.children.map((childPath: string) => (
            <TreeNode 
              key={childPath}
              node={folders[childPath]}
              folders={folders}
              selectedPath={selectedPath}
              onSelectPath={onSelectPath}
              depth={depth + 1}
            />
          ))}
        </div>
      )}
    </div>
  );
}
