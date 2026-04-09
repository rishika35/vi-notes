import React from "react";
import { Link } from "react-router-dom";
import { ShieldCheck, Zap, PenTool, Database, BarChart3 } from "lucide-react";
import { motion } from "motion/react";

export function Home() {
  return (
    <div className="flex flex-col gap-24 py-12">
      <section className="text-center max-w-3xl mx-auto flex flex-col gap-8">
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5 }}
          className="inline-flex items-center gap-2 px-3 py-1 rounded-full bg-indigo-50 border border-indigo-100 text-indigo-600 text-xs font-bold uppercase tracking-wider"
        >
          <Zap className="w-3 h-3" />
          <span>The Future of Authorship Verification</span>
        </motion.div>
        <motion.h1
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.1 }}
          className="text-5xl md:text-7xl font-extrabold text-slate-900 tracking-tight leading-[1.1]"
        >
          Verify the <span className="text-indigo-600">Human</span> Behind the Words.
        </motion.h1>
        <motion.p
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.2 }}
          className="text-xl text-slate-500 leading-relaxed"
        >
          Vi-Notes ensures genuine human writing through real-time keyboard activity monitoring and statistical signature analysis.
        </motion.p>
        <motion.div
          initial={{ opacity: 0, y: 20 }}
          animate={{ opacity: 1, y: 0 }}
          transition={{ duration: 0.5, delay: 0.3 }}
          className="flex flex-col sm:flex-row items-center justify-center gap-4"
        >
          <Link
            to="/register"
            className="w-full sm:w-auto px-8 py-4 bg-indigo-600 text-white font-bold rounded-xl hover:bg-indigo-700 transition-all shadow-lg shadow-indigo-200 hover:scale-105"
          >
            Start Writing Now
          </Link>
          <Link
            to="/login"
            className="w-full sm:w-auto px-8 py-4 bg-white text-slate-900 font-bold rounded-xl hover:bg-slate-50 transition-all border border-slate-200"
          >
            Sign In
          </Link>
        </motion.div>
      </section>

      <section className="grid md:grid-cols-3 gap-8">
        {[
          {
            title: "Keyboard Monitoring",
            desc: "Captures typing speed, pause patterns, and composition rhythm to distinguish human thinking from AI generation.",
            icon: PenTool,
            color: "bg-blue-500",
          },
          {
            title: "Statistical Analysis",
            desc: "Examines linguistic patterns and stylistic consistency that AI-generated text often lacks.",
            icon: BarChart3,
            color: "bg-purple-500",
          },
          {
            title: "Secure Storage",
            desc: "Every session is cryptographically linked to your profile, providing a verifiable audit trail of your work.",
            icon: Database,
            color: "bg-indigo-500",
          },
        ].map((feature, i) => (
          <motion.div
            key={i}
            initial={{ opacity: 0, y: 20 }}
            whileInView={{ opacity: 1, y: 0 }}
            viewport={{ once: true }}
            transition={{ duration: 0.5, delay: i * 0.1 }}
            className="p-8 bg-white rounded-2xl border border-slate-200 shadow-sm hover:shadow-md transition-shadow"
          >
            <div className={cn("w-12 h-12 rounded-xl flex items-center justify-center mb-6", feature.color)}>
              <feature.icon className="w-6 h-6 text-white" />
            </div>
            <h3 className="text-xl font-bold text-slate-900 mb-3">{feature.title}</h3>
            <p className="text-slate-500 leading-relaxed">{feature.desc}</p>
          </motion.div>
        ))}
      </section>

      <section className="bg-slate-900 rounded-[2rem] p-12 md:p-24 text-center text-white flex flex-col items-center gap-8">
        <ShieldCheck className="w-16 h-16 text-indigo-400" />
        <h2 className="text-3xl md:text-5xl font-bold tracking-tight">Restoring Trust in Written Content</h2>
        <p className="text-slate-400 text-lg max-w-2xl">
          Whether you're an educator ensuring academic integrity or a professional writer proving your authorship, Vi-Notes provides the evidence you need.
        </p>
        <Link
          to="/register"
          className="px-8 py-4 bg-indigo-500 text-white font-bold rounded-xl hover:bg-indigo-400 transition-all"
        >
          Join Vi-Notes Today
        </Link>
      </section>
    </div>
  );
}

function cn(...inputs: any[]) {
  return inputs.filter(Boolean).join(" ");
}
