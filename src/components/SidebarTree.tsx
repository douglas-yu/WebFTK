/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState } from 'react';
import { Folder, FolderOpen, ChevronRight, ChevronDown, HardDrive } from 'lucide-react';
import { FolderNode } from '../types';

interface SidebarTreeProps {
  folders: Record<string, FolderNode>;
  rootPaths: string[];
  selectedPath: string;
  onSelectPath: (path: string) => void;
}

export default function SidebarTree({ folders, rootPaths, selectedPath, onSelectPath }: SidebarTreeProps) {
  return (
    <div className="flex flex-col h-full bg-zinc-950 font-sans text-xs">
      <div className="p-3 border-b border-zinc-900 flex items-center gap-2 bg-zinc-900/20">
        <HardDrive className="w-4 h-4 text-zinc-500" />
        <span className="font-bold text-zinc-400 tracking-tighter uppercase">Evidence Tree</span>
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
            No evidence loaded
          </div>
        )}
      </div>
    </div>
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
