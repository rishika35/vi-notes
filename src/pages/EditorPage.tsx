import React, { useState } from "react";
import { useNavigate } from "react-router-dom";
import { Editor } from "../components/Editor";
import { api } from "../lib/api";
import { Keystroke, PasteEvent, WritingSession } from "../types";
import { ArrowLeft, Save, Loader2, AlertCircle } from "lucide-react";

export function EditorPage() {
  const [title, setTitle] = useState("Untitled Session");
  const [isSaving, setIsSaving] = useState(false);
  const [error, setError] = useState<string | null>(null);
  const navigate = useNavigate();

  const handleSave = async (content: string, keystrokes: Keystroke[], pastes: PasteEvent[]) => {
    if (!content.trim()) {
      setError("Please write something before saving.");
      return;
    }

    setIsSaving(true);
    setError(null);

    try {
      // Calculate basic metrics
      const duration = keystrokes.length > 0 
        ? (keystrokes[keystrokes.length - 1].timestamp - keystrokes[0].timestamp) / 1000 
        : 0;
      const wordCount = content.trim().split(/\s+/).length;
      const wpm = duration > 0 ? Math.round((wordCount / duration) * 60) : 0;
      
      // Simple authenticity score logic: 
      // Higher score if fewer pastes and more keystrokes relative to content length
      const pastePenalty = pastes.reduce((acc, p) => acc + p.contentLength, 0);
      const contentLen = content.length || 1;
      const accuracy = Math.max(0, Math.min(100, ((contentLen - pastePenalty) / contentLen) * 100));

      const session: Partial<WritingSession> = {
        title,
        content,
        keystrokes,
        pastes,
        metrics: {
          wpm,
          accuracy,
          totalKeystrokes: keystrokes.length,
          totalPastes: pastes.length,
          duration,
        },
      };

      const savedSession = await api.sessions.save(session);
      navigate(`/sessions/${savedSession.id}`);
    } catch (err: any) {
      console.error("Save error:", err);
      setError(err.message || "Failed to save session. Please try again.");
      setIsSaving(false);
    }
  };

  return (
    <div className="flex flex-col h-[calc(100vh-12rem)] gap-6">
      <header className="flex items-center justify-between gap-4">
        <div className="flex items-center gap-4 flex-1">
          <button
            onClick={() => navigate("/dashboard")}
            className="p-2 text-slate-400 hover:text-slate-900 transition-colors"
          >
            <ArrowLeft className="w-5 h-5" />
          </button>
          <input
            type="text"
            value={title}
            onChange={(e) => setTitle(e.target.value)}
            className="text-2xl font-bold text-slate-900 bg-transparent border-none focus:outline-none focus:ring-0 p-0 w-full"
            placeholder="Session Title"
          />
        </div>
        {isSaving && (
          <div className="flex items-center gap-2 text-sm text-slate-500">
            <Loader2 className="w-4 h-4 animate-spin" />
            Saving...
          </div>
        )}
      </header>

      {error && (
        <div className="p-4 bg-red-50 border border-red-100 rounded-xl flex items-center gap-3 text-sm text-red-600">
          <AlertCircle className="w-4 h-4 shrink-0" />
          <span>{error}</span>
        </div>
      )}

      <div className="flex-1 min-h-0">
        <Editor onSave={handleSave} />
      </div>
    </div>
  );
}
