import {StrictMode} from 'react';
import {createRoot} from 'react-dom/client';
import { Buffer } from 'buffer';
import App from './App.tsx';
import './index.css';

// Polyfill Buffer and process for browser runtime
if (typeof window !== 'undefined') {
  (window as unknown as { Buffer: typeof Buffer; global: unknown; process: unknown }).Buffer = Buffer;
  (window as unknown as { Buffer: typeof Buffer; global: unknown; process: unknown }).global = window;
  (window as unknown as { Buffer: typeof Buffer; global: unknown; process: { env: Record<string, string> } }).process =
    (window as unknown as { process?: { env: Record<string, string> } }).process || { env: {} };
}

createRoot(document.getElementById('root')!).render(
  <StrictMode>
    <App />
  </StrictMode>,
);
