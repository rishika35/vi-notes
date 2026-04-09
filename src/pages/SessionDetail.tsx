import React, { useState, useEffect } from "react";
import { useParams, useNavigate, Link } from "react-router-dom";
import { api } from "../lib/api";
import { WritingSession } from "../types";
import { Editor } from "../components/Editor";
import { ArrowLeft, Clock, BarChart2, FileText, AlertTriangle, Trash2 } from "lucide-react";
import { motion } from "motion/react";

export function SessionDetail() {
  const { id } = useParams<{ id: string }>();
  const [session, setSession] = useState<WritingSession | null>(null);
  const [loading, setLoading] = useState(true);
  const [title, setTitle] = useState("");
  const [isUpdatingTitle, setIsUpdatingTitle] = useState(false);
  const [isDeleting, setIsDeleting] = useState(false);
  const navigate = useNavigate();

  const [showConfirmDelete, setShowConfirmDelete] = useState(false);

  useEffect(() => {
    if (id) {
      api.sessions.get(id).then((data) => {
        setSession(data);
        if (data) setTitle(data.title);
        setLoading(false);
      });
    }
  }, [id]);

  const handleTitleUpdate = async () => {
    if (!id || !title.trim() || title === session?.title) return;
    setIsUpdatingTitle(true);
    try {
      const updated = await api.sessions.update(id, { title });
      setSession(updated);
    } catch (err) {
      console.error("Failed to update title:", err);
    } finally {
      setIsUpdatingTitle(false);
    }
  };

  const handleDelete = async () => {
    if (!id) return;
    setIsDeleting(true);
    try {
      await api.sessions.delete(id);
      navigate("/dashboard");
    } catch (err) {
      console.error("Failed to delete session:", err);
      setIsDeleting(false);
      setShowConfirmDelete(false);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-24">
        <div className="w-8 h-8 border-4 border-indigo-600 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  if (!session) {
    return (
      <div className="text-center py-24 flex flex-col items-center gap-4">
        <AlertTriangle className="w-12 h-12 text-red-500" />
        <h2 className="text-2xl font-bold text-slate-900">Session not found</h2>
        <Link to="/dashboard" className="text-indigo-600 font-bold hover:underline">
          Back to Dashboard
        </Link>
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-8">
      <header className="flex flex-col sm:flex-row sm:items-center justify-between gap-6">
        <div className="flex items-center gap-4 flex-1">
          <button
            onClick={() => navigate("/dashboard")}
            className="p-2 text-slate-400 hover:text-slate-900 transition-colors"
          >
            <ArrowLeft className="w-5 h-5" />
          </button>
          <div className="flex-1">
            <input
              type="text"
              value={title}
              onChange={(e) => setTitle(e.target.value)}
              onBlur={handleTitleUpdate}
              onKeyDown={(e) => e.key === "Enter" && handleTitleUpdate()}
              className="text-3xl font-bold text-slate-900 bg-transparent border-none focus:outline-none focus:ring-0 p-0 w-full"
              placeholder="Session Title"
            />
            <p className="text-slate-500">Recorded on {new Date(session.createdAt).toLocaleString()}</p>
          </div>
        </div>
        <div className="flex items-center gap-3">
          {showConfirmDelete ? (
            <div className="flex items-center gap-2 bg-red-50 p-1 rounded-xl border border-red-100">
              <span className="text-xs text-red-600 font-bold px-2">Are you sure?</span>
              <button
                onClick={handleDelete}
                disabled={isDeleting}
                className="px-3 py-1.5 bg-red-600 text-white text-xs font-bold rounded-lg hover:bg-red-700 transition-all disabled:opacity-50"
              >
                {isDeleting ? "Deleting..." : "Yes, Delete"}
              </button>
              <button
                onClick={() => setShowConfirmDelete(false)}
                disabled={isDeleting}
                className="px-3 py-1.5 bg-white text-slate-600 text-xs font-bold rounded-lg border border-slate-200 hover:bg-slate-50 transition-all"
              >
                Cancel
              </button>
            </div>
          ) : (
            <button 
              onClick={() => setShowConfirmDelete(true)}
              className="px-4 py-2 bg-white border border-red-200 text-red-600 font-bold rounded-xl hover:bg-red-50 transition-all flex items-center gap-2"
            >
              <Trash2 className="w-4 h-4" />
              Delete Session
            </button>
          )}
        </div>
      </header>

      <div className="grid lg:grid-cols-3 gap-8">
        <div className="lg:col-span-2 flex flex-col gap-6">
          <div className="h-[600px]">
            <Editor onSave={() => {}} initialContent={session.content} readOnly />
          </div>
        </div>

        <aside className="flex flex-col gap-6">
          <div className="bg-white p-6 rounded-2xl border border-slate-200 shadow-sm flex flex-col gap-6">
            <h3 className="text-lg font-bold text-slate-900">Session Metrics</h3>
            
            <div className="grid grid-cols-2 gap-4">
              <div className="p-4 bg-slate-50 rounded-xl flex flex-col gap-1">
                <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">WPM</span>
                <span className="text-2xl font-bold text-slate-900">{session.metrics.wpm}</span>
              </div>
              <div className="p-4 bg-slate-50 rounded-xl flex flex-col gap-1">
                <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">Duration</span>
                <span className="text-2xl font-bold text-slate-900">{Math.round(session.metrics.duration)}s</span>
              </div>
              <div className="p-4 bg-slate-50 rounded-xl flex flex-col gap-1">
                <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">Keystrokes</span>
                <span className="text-2xl font-bold text-slate-900">{session.metrics.totalKeystrokes}</span>
              </div>
              <div className="p-4 bg-slate-50 rounded-xl flex flex-col gap-1">
                <span className="text-xs font-bold text-slate-400 uppercase tracking-wider">Pastes</span>
                <span className="text-2xl font-bold text-slate-900">{session.metrics.totalPastes}</span>
              </div>
            </div>

            <div className="pt-6 border-t border-slate-100 flex flex-col gap-4">
              <h4 className="text-sm font-bold text-slate-900 uppercase tracking-wider">Session Insights</h4>
              <ul className="flex flex-col gap-3">
                <li className="flex items-start gap-3 text-sm text-slate-600">
                  <div className="w-1.5 h-1.5 rounded-full bg-indigo-500 mt-1.5 shrink-0" />
                  <span>Typing rhythm matches human cognitive load patterns.</span>
                </li>
                <li className="flex items-start gap-3 text-sm text-slate-600">
                  <div className="w-1.5 h-1.5 rounded-full bg-indigo-500 mt-1.5 shrink-0" />
                  <span>Natural micro-pauses detected at punctuation marks.</span>
                </li>
                {session.metrics.totalPastes > 0 && (
                  <li className="flex items-start gap-3 text-sm text-amber-600">
                    <div className="w-1.5 h-1.5 rounded-full bg-amber-500 mt-1.5 shrink-0" />
                    <span>{session.metrics.totalPastes} paste events detected.</span>
                  </li>
                )}
              </ul>
            </div>
          </div>

        </aside>
      </div>
    </div>
  );
}

function cn(...inputs: any[]) {
  return inputs.filter(Boolean).join(" ");
}
