/**
 * @license
 * SPDX-License-Identifier: Apache-2.0
 */

import React, { useState, useEffect, useMemo } from 'react';

interface HexViewerProps {
  file: File | null;
}

export default function HexViewer({ file }: HexViewerProps) {
  const [data, setData] = useState<Uint8Array | null>(null);
  const [loading, setLoading] = useState(false);
  const [pageSize] = useState(1024); // Show 1kb at a time for performance
  const [offset, setOffset] = useState(0);

  useEffect(() => {
    if (!file) {
      setData(null);
      return;
    }

    const loadData = async () => {
      setLoading(true);
      try {
        const chunk = file.slice(offset, offset + pageSize);
        const buffer = await chunk.arrayBuffer();
        setData(new Uint8Array(buffer));
      } catch (err) {
        console.error('Failed to load hex data', err);
      } finally {
        setLoading(false);
      }
    };

    loadData();
  }, [file, offset, pageSize]);

  const rows = useMemo(() => {
    if (!data) return [];
    const result = [];
    for (let i = 0; i < data.length; i += 16) {
      result.push(data.slice(i, i + 16));
    }
    return result;
  }, [data]);

  if (!file) {
    return (
      <div className="flex flex-col items-center justify-center h-full text-zinc-500 font-mono text-sm border-2 border-dashed border-zinc-800 rounded-lg m-4">
        <p>No file selected for technical analysis</p>
      </div>
    );
  }

  return (
    <div className="flex flex-col h-full bg-zinc-950 font-mono text-xs overflow-hidden rounded-lg border border-zinc-800 shadow-2xl">
      <div className="p-2 border-b border-zinc-800 flex justify-between items-center bg-zinc-900/50">
        <span className="text-zinc-400 uppercase tracking-tighter text-[10px] font-bold">Hex Stream: {file.name}</span>
        <div className="flex gap-2">
          <button 
            onClick={() => setOffset(Math.max(0, offset - pageSize))}
            disabled={offset === 0}
            className="px-2 py-0.5 bg-zinc-800 hover:bg-zinc-700 disabled:opacity-30 rounded text-zinc-300"
          >
            PREV
          </button>
          <span className="text-zinc-500">Offset: {offset.toString(16).toUpperCase().padStart(8, '0')}</span>
          <button 
            onClick={() => setOffset(Math.min(file.size, offset + pageSize))}
            disabled={offset + pageSize >= file.size}
            className="px-2 py-0.5 bg-zinc-800 hover:bg-zinc-700 disabled:opacity-30 rounded text-zinc-300"
          >
            NEXT
          </button>
        </div>
      </div>
      
      <div className="flex-1 overflow-auto p-4 custom-scrollbar">
        {loading ? (
          <div className="flex items-center justify-center h-full animate-pulse text-zinc-600">
            Reading bitstream...
          </div>
        ) : (
          <table className="w-full border-collapse">
            <thead>
              <tr className="text-zinc-600 border-b border-zinc-900">
                <th className="text-left font-normal pb-2 w-24">OFFSET</th>
                <th className="text-left font-normal pb-2">00 01 02 03 04 05 06 07  08 09 0A 0B 0C 0D 0E 0F</th>
                <th className="text-left font-normal pb-2 w-32">ASCII</th>
              </tr>
            </thead>
            <tbody>
              {rows.map((row, rowIndex) => {
                const rowOffset = (offset + rowIndex * 16).toString(16).toUpperCase().padStart(8, '0');
                const hexValues = Array.from(row).map(b => b.toString(16).padStart(2, '0').toUpperCase());
                const asciiValues = Array.from(row).map(b => (b >= 32 && b <= 126 ? String.fromCharCode(b) : '.'));

                return (
                  <tr key={rowIndex} className="hover:bg-zinc-900 group">
                    <td className="text-zinc-500 group-hover:text-zinc-400 py-0.5">{rowOffset}</td>
                    <td className="text-zinc-300 py-0.5 font-medium">
                      {hexValues.slice(0, 8).join(' ')} &nbsp; {hexValues.slice(8).join(' ')}
                      {Array(16 - hexValues.length).fill('  ').map((_, i) => <span key={i}>   </span>)}
                    </td>
                    <td className="text-zinc-500 group-hover:text-zinc-400 py-0.5 border-l border-zinc-900 pl-4">
                      {asciiValues.join('')}
                    </td>
                  </tr>
                );
              })}
            </tbody>
          </table>
        )}
      </div>
      
      <div className="p-1 px-3 border-t border-zinc-800 bg-zinc-900/50 flex justify-between text-[10px] text-zinc-600">
        <span>Page Size: 1024 bytes</span>
        <span>File Pointer: {offset} / {file.size} bytes</span>
      </div>
    </div>
  );
}
