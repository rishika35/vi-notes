import React, { useState, useEffect } from "react";
import { Link } from "react-router-dom";
import { api } from "../lib/api";
import { WritingSession } from "../types";
import { Plus, Clock, FileText, ChevronRight, BarChart2, ShieldCheck, Trash2 } from "lucide-react";
import { motion } from "motion/react";

export function Dashboard() {
  const [sessions, setSessions] = useState<WritingSession[]>([]);
  const [loading, setLoading] = useState(true);

  const [deletingId, setDeletingId] = useState<string | null>(null);

  useEffect(() => {
    loadSessions();
  }, []);

  const loadSessions = async () => {
    const data = await api.sessions.list();
    setSessions(data);
    setLoading(false);
  };

  const handleDelete = async (id: string) => {
    try {
      await api.sessions.delete(id);
      setSessions(prev => prev.filter(s => s.id !== id));
      setDeletingId(null);
    } catch (err) {
      console.error("Failed to delete session:", err);
      setDeletingId(null);
    }
  };

  if (loading) {
    return (
      <div className="flex items-center justify-center py-24">
        <div className="w-8 h-8 border-4 border-indigo-600 border-t-transparent rounded-full animate-spin" />
      </div>
    );
  }

  return (
    <div className="flex flex-col gap-8">
      <header className="flex flex-col sm:flex-row sm:items-center justify-between gap-4">
        <div>
          <h1 className="text-3xl font-bold text-slate-900 tracking-tight">Your Sessions</h1>
          <p className="text-slate-500">Manage and verify your writing history</p>
        </div>
        <Link
          to="/editor"
          className="inline-flex items-center gap-2 px-6 py-3 bg-indigo-600 text-white font-bold rounded-xl hover:bg-indigo-700 transition-all shadow-lg shadow-indigo-200"
        >
          <Plus className="w-5 h-5" />
          New Writing Session
        </Link>
      </header>

      {sessions.length === 0 ? (
        <div className="bg-white border-2 border-dashed border-slate-200 rounded-3xl p-12 text-center flex flex-col items-center gap-4">
          <div className="w-16 h-16 bg-slate-50 rounded-2xl flex items-center justify-center">
            <FileText className="w-8 h-8 text-slate-300" />
          </div>
          <div className="flex flex-col gap-1">
            <h3 className="text-lg font-bold text-slate-900">No sessions yet</h3>
            <p className="text-slate-500">Start your first session to begin verifying your authorship.</p>
          </div>
          <Link
            to="/editor"
            className="mt-4 text-indigo-600 font-bold hover:underline"
          >
            Create your first session →
          </Link>
        </div>
      ) : (
        <div className="grid gap-4">
          {sessions.sort((a, b) => b.createdAt - a.createdAt).map((session, i) => (
            <motion.div
              key={session.id}
              initial={{ opacity: 0, x: -20 }}
              animate={{ opacity: 1, x: 0 }}
              transition={{ delay: i * 0.05 }}
            >
              <Link
                to={`/sessions/${session.id}`}
                className="group bg-white p-6 rounded-2xl border border-slate-200 shadow-sm hover:shadow-md hover:border-indigo-200 transition-all flex items-center justify-between"
              >
                <div className="flex items-center gap-6">
                  <div className="w-12 h-12 bg-slate-50 rounded-xl flex items-center justify-center group-hover:bg-indigo-50 transition-colors">
                    <FileText className="w-6 h-6 text-slate-400 group-hover:text-indigo-600 transition-colors" />
                  </div>
                  <div className="flex flex-col gap-1">
                    <h3 className="text-lg font-bold text-slate-900 group-hover:text-indigo-600 transition-colors">
                      {session.title || "Untitled Session"}
                    </h3>
                    <div className="flex items-center gap-4 text-sm text-slate-500">
                      <span className="flex items-center gap-1">
                        <Clock className="w-3.5 h-3.5" />
                        {new Date(session.createdAt).toLocaleDateString()}
                      </span>
                      <span className="flex items-center gap-1">
                        <BarChart2 className="w-3.5 h-3.5" />
                        {session.metrics.wpm} WPM
                      </span>
                    </div>
                  </div>
                </div>
                <div className="flex items-center gap-4">
                  {deletingId === session.id ? (
                    <div className="flex items-center gap-2">
                      <button
                        onClick={(e) => {
                          e.preventDefault();
                          e.stopPropagation();
                          handleDelete(session.id);
                        }}
                        className="px-3 py-1 bg-red-600 text-white text-xs font-bold rounded-lg hover:bg-red-700 transition-all"
                      >
                        Confirm
                      </button>
                      <button
                        onClick={(e) => {
                          e.preventDefault();
                          e.stopPropagation();
                          setDeletingId(null);
                        }}
                        className="px-3 py-1 bg-slate-100 text-slate-600 text-xs font-bold rounded-lg hover:bg-slate-200 transition-all"
                      >
                        Cancel
                      </button>
                    </div>
                  ) : (
                    <button
                      onClick={(e) => {
                        e.preventDefault();
                        e.stopPropagation();
                        setDeletingId(session.id);
                      }}
                      className="p-2 text-slate-300 hover:text-red-500 hover:bg-red-50 rounded-lg transition-all"
                      title="Delete Session"
                    >
                      <Trash2 className="w-4 h-4" />
                    </button>
                  )}
                  <ChevronRight className="w-5 h-5 text-slate-300 group-hover:text-indigo-600 group-hover:translate-x-1 transition-all" />
                </div>
              </Link>
            </motion.div>
          ))}
        </div>
      )}
    </div>
  );
}
