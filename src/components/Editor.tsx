import React, { useState, useEffect, useRef } from "react";
import { Keystroke, PasteEvent } from "../types";
import { cn } from "../lib/utils";

interface EditorProps {
  onSave: (content: string, keystrokes: Keystroke[], pastes: PasteEvent[]) => void;
  initialContent?: string;
  readOnly?: boolean;
}

export function Editor({ onSave, initialContent = "", readOnly = false }: EditorProps) {
  const [content, setContent] = useState(initialContent);
  const [keystrokes, setKeystrokes] = useState<Keystroke[]>([]);
  const [pastes, setPastes] = useState<PasteEvent[]>([]);
  const textareaRef = useRef<HTMLTextAreaElement>(null);

  const handleKeyDown = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (readOnly) return;
    const keystroke: Keystroke = {
      timestamp: Date.now(),
      key: e.key,
      type: "keydown",
    };
    setKeystrokes((prev) => [...prev, keystroke]);
  };

  const handleKeyUp = (e: React.KeyboardEvent<HTMLTextAreaElement>) => {
    if (readOnly) return;
    const keystroke: Keystroke = {
      timestamp: Date.now(),
      key: e.key,
      type: "keyup",
    };
    setKeystrokes((prev) => [...prev, keystroke]);
  };

  const handlePaste = (e: React.ClipboardEvent<HTMLTextAreaElement>) => {
    if (readOnly) return;
    const pastedText = e.clipboardData.getData("text");
    const pasteEvent: PasteEvent = {
      timestamp: Date.now(),
      contentLength: pastedText.length,
      content: pastedText,
    };
    setPastes((prev) => [...prev, pasteEvent]);
  };

  const handleChange = (e: React.ChangeEvent<HTMLTextAreaElement>) => {
    if (readOnly) return;
    setContent(e.target.value);
  };

  return (
    <div className="flex flex-col h-full bg-white rounded-lg shadow-sm border border-slate-200 overflow-hidden">
      <div className="flex items-center justify-between px-4 py-2 bg-slate-50 border-b border-slate-200">
        <div className="flex items-center gap-2">
          <div className={cn("w-2 h-2 rounded-full", readOnly ? "bg-slate-300" : "bg-green-500 animate-pulse")} />
          <span className="text-xs font-medium text-slate-500 uppercase tracking-wider">
            {readOnly ? "View Mode" : "Monitoring Active"}
          </span>
        </div>
        {!readOnly && (
          <button
            onClick={() => onSave(content, keystrokes, pastes)}
            className="px-3 py-1 text-xs font-semibold text-white bg-indigo-600 rounded hover:bg-indigo-700 transition-colors"
          >
            Save Session
          </button>
        )}
      </div>
      <textarea
        ref={textareaRef}
        value={content}
        onChange={handleChange}
        onKeyDown={handleKeyDown}
        onKeyUp={handleKeyUp}
        onPaste={handlePaste}
        readOnly={readOnly}
        placeholder="Start writing here..."
        className="flex-1 p-6 text-lg leading-relaxed text-slate-800 placeholder-slate-400 focus:outline-none resize-none font-serif"
      />
      <div className="px-4 py-2 bg-slate-50 border-t border-slate-200 flex justify-between text-[10px] text-slate-400 uppercase tracking-widest font-medium">
        <span>Words: {content.trim() ? content.trim().split(/\s+/).length : 0}</span>
        <span>Keystrokes: {keystrokes.length}</span>
        <span>Pastes: {pastes.length}</span>
      </div>
    </div>
  );
}
