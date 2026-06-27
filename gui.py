#!/usr/bin/env python3
"""Tkinter GUI for the Security Audit Tool."""

from __future__ import annotations

import os
import json
import queue
import re
import subprocess
import sys
import threading
import time
import tkinter as tk
import webbrowser
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from tkinter import filedialog, messagebox, ttk

import audit_tool


ANSI_SEQUENCE_RE = re.compile(
    r"""
    \x1b
    (?:
        \[[0-?]*[ -/]*[@-~]
        |
        \][^\x07\x1b]*(?:\x07|\x1b\\)
        |
        [@-_]
    )
    """,
    re.VERBOSE,
)
INCOMPLETE_ANSI_RE = re.compile(
    r"(?:\x1b|\x1b\[[0-?]*[ -/]*|\x1b\][^\x07\x1b]*)$"
)


class TerminalOutputFilter:
    """Remove ANSI sequences safely even when a sequence spans read chunks."""

    def __init__(self):
        self.pending = ""

    def feed(self, text):
        data = self.pending + text
        self.pending = ""
        incomplete = INCOMPLETE_ANSI_RE.search(data)
        if incomplete:
            self.pending = incomplete.group(0)
            data = data[: incomplete.start()]
        return ANSI_SEQUENCE_RE.sub("", data).replace("\x00", "")

    def finish(self):
        self.pending = ""
        return ""


PROGRESS_PATTERNS = (
    re.compile(r"(?<![\d.])(\d{1,3}(?:\.\d+)?)\s*%"),
    re.compile(
        r"\b(?:scanning|progress|chunk|completed|tested|processed|target(?:s)?)"
        r"[^0-9\r\n]{0,30}(\d+)\s*/\s*(\d+)\b",
        re.I,
    ),
)


def progress_from_output(text):
    """Return the latest trustworthy 0-99 progress value found in output."""
    latest = None
    for match in PROGRESS_PATTERNS[0].finditer(text):
        latest = float(match.group(1))
    for match in PROGRESS_PATTERNS[1].finditer(text):
        completed, total = int(match.group(1)), int(match.group(2))
        if total > 0:
            latest = completed / total * 100
    if latest is None:
        return None
    return min(99, max(0, int(latest)))


class AuditToolGUI:
    def __init__(self, root):
        self.root = root
        self.root.title("Security Audit Tool")
        self.root.geometry("1180x760")
        self.root.minsize(900, 620)
        self.active_processes = set()
        self.events = queue.Queue()
        self.started = None
        self.pending = []
        self.rows = audit_tool.catalog()
        self.row_by_item = {}

        self.search_var = tk.StringVar()
        self.category_var = tk.StringVar(value="all")
        self.targets_var = tk.StringVar()
        self.options_var = tk.StringVar()
        self.workers_var = tk.StringVar(value="4")
        self.status_var = tk.StringVar(value=f"Ready — {len(self.rows)} scanners available")
        self.elapsed_var = tk.StringVar(value="Elapsed 00:00")
        self.progress_var = tk.StringVar(value="0%")
        self.batch_total = 0
        self.batch_completed = 0
        self.current_progress = 0
        self.cancelled = False

        self._build_style()
        self._build_layout()
        self._populate()
        self.root.after(100, self._drain_events)
        self.root.after(500, self._tick)
        self.root.protocol("WM_DELETE_WINDOW", self._on_close)

    def _build_style(self):
        style = ttk.Style(self.root)
        if "vista" in style.theme_names():
            style.theme_use("vista")
        style.configure("Title.TLabel", font=("Segoe UI", 19, "bold"))
        style.configure("Muted.TLabel", foreground="#586174")
        style.configure("Run.TButton", font=("Segoe UI", 10, "bold"))

    def _build_layout(self):
        outer = ttk.Frame(self.root, padding=16)
        outer.pack(fill="both", expand=True)

        header = ttk.Frame(outer)
        header.pack(fill="x")
        ttk.Label(header, text="Security Audit Tool", style="Title.TLabel").pack(side="left")
        ttk.Label(
            header,
            text="Conservative findings • live output • cancellable scans",
            style="Muted.TLabel",
        ).pack(side="left", padx=(16, 0), pady=(7, 0))

        filters = ttk.Frame(outer)
        filters.pack(fill="x", pady=(14, 8))
        ttk.Label(filters, text="Search").pack(side="left")
        search = ttk.Entry(filters, textvariable=self.search_var, width=34)
        search.pack(side="left", padx=(6, 16))
        search.bind("<KeyRelease>", lambda _event: self._populate())
        ttk.Label(filters, text="Category").pack(side="left")
        category = ttk.Combobox(
            filters,
            textvariable=self.category_var,
            values=["all"] + sorted({row["category"] for row in self.rows}),
            state="readonly",
            width=18,
        )
        category.pack(side="left", padx=(6, 0))
        category.bind("<<ComboboxSelected>>", lambda _event: self._populate())

        split = ttk.Panedwindow(outer, orient="vertical")
        split.pack(fill="both", expand=True)
        catalog_frame = ttk.Frame(split, padding=(0, 0, 0, 8))
        output_frame = ttk.Frame(split, padding=(0, 8, 0, 0))
        split.add(catalog_frame, weight=3)
        split.add(output_frame, weight=2)

        self.tree = ttk.Treeview(
            catalog_frame,
            columns=("category", "mode", "description"),
            show="tree headings",
            selectmode="extended",
        )
        self.tree.heading("#0", text="Scanner")
        self.tree.heading("category", text="Category")
        self.tree.heading("mode", text="Mode")
        self.tree.heading("description", text="Description")
        self.tree.column("#0", width=280, minwidth=180)
        self.tree.column("category", width=130, minwidth=100)
        self.tree.column("mode", width=85, minwidth=70, anchor="center")
        self.tree.column("description", width=550, minwidth=260)
        scroll = ttk.Scrollbar(catalog_frame, command=self.tree.yview)
        self.tree.configure(yscrollcommand=scroll.set)
        self.tree.pack(side="left", fill="both", expand=True)
        scroll.pack(side="right", fill="y")
        self.tree.bind("<<TreeviewSelect>>", self._selection_changed)

        inputs = ttk.LabelFrame(output_frame, text="Scan configuration", padding=10)
        inputs.pack(fill="x")
        ttk.Label(inputs, text="Target (IP, CIDR subnet, or IP list file)").grid(
            row=0, column=0, sticky="w"
        )
        ttk.Entry(inputs, textvariable=self.targets_var).grid(
            row=0, column=1, sticky="ew", padx=8
        )
        ttk.Button(inputs, text="Target file…", command=self._choose_target_file).grid(
            row=0, column=2
        )
        ttk.Label(inputs, text="Options").grid(row=1, column=0, sticky="w", pady=(8, 0))
        options_frame = ttk.Frame(inputs)
        options_frame.grid(row=1, column=1, sticky="ew", padx=8, pady=(8, 0))
        ttk.Entry(options_frame, textvariable=self.options_var).pack(side="left", fill="x", expand=True)
        ttk.Label(options_frame, text="  Workers").pack(side="left")
        ttk.Entry(options_frame, textvariable=self.workers_var, width=5).pack(side="left", padx=(6, 0))
        
        ttk.Label(
            inputs,
            text="Example: --timeout 30 --no-color",
            style="Muted.TLabel",
        ).grid(row=1, column=2, sticky="w", pady=(8, 0))
        inputs.columnconfigure(1, weight=1)

        actions = ttk.Frame(output_frame)
        actions.pack(fill="x", pady=8)
        self.run_button = ttk.Button(
            actions, text="Run selected", style="Run.TButton", command=self._start
        )
        self.run_button.pack(side="left")
        self.run_all_button = ttk.Button(
            actions,
            text="Run all scanners",
            style="Run.TButton",
            command=self._start_all,
        )
        self.run_all_button.pack(side="left", padx=(8, 0))
        self.cancel_button = ttk.Button(
            actions, text="Cancel", command=self._cancel, state="disabled"
        )
        self.cancel_button.pack(side="left", padx=8)
        ttk.Button(actions, text="Clear output", command=self._clear_output).pack(side="left")
        ttk.Button(actions, text="Open reports", command=self._open_reports).pack(
            side="left", padx=8
        )
        ttk.Label(actions, textvariable=self.elapsed_var).pack(side="right")

        progress_row = ttk.Frame(output_frame)
        progress_row.pack(fill="x")
        self.progress = ttk.Progressbar(progress_row, mode="determinate", maximum=100)
        self.progress.pack(side="left", fill="x", expand=True)
        ttk.Label(progress_row, textvariable=self.progress_var, width=5).pack(
            side="left", padx=(8, 0)
        )
        ttk.Label(output_frame, textvariable=self.status_var).pack(fill="x", pady=(5, 4))

        console_frame = ttk.Frame(output_frame)
        console_frame.pack(fill="both", expand=True)
        self.console = tk.Text(
            console_frame,
            wrap="word",
            height=11,
            font=("Consolas", 9),
            background="#10151d",
            foreground="#dbe5f3",
            insertbackground="white",
        )
        console_scroll = ttk.Scrollbar(console_frame, command=self.console.yview)
        self.console.configure(yscrollcommand=console_scroll.set)
        self.console.pack(side="left", fill="both", expand=True)
        console_scroll.pack(side="right", fill="y")

    def _populate(self):
        selected_ids = {
            self.row_by_item[item]["id"]
            for item in self.tree.selection()
            if item in self.row_by_item
        }
        self.tree.delete(*self.tree.get_children())
        self.row_by_item.clear()
        query = self.search_var.get().strip().lower()
        category = self.category_var.get()
        for row in self.rows:
            haystack = " ".join(
                (row["id"], row["file"], row["category"], row["description"])
            ).lower()
            if query and query not in haystack:
                continue
            if category != "all" and row["category"] != category:
                continue
            item = self.tree.insert(
                "",
                "end",
                text=row["id"],
                values=(row["category"], row["verification"], row["description"]),
            )
            self.row_by_item[item] = row
            if row["id"] in selected_ids:
                self.tree.selection_add(item)

    def _selection_changed(self, _event=None):
        count = len(self.tree.selection())
        if not self.active_processes:
            self.status_var.set(
                f"{count} scanner{'s' if count != 1 else ''} selected"
                if count
                else f"Ready — {len(self.rows)} scanners available"
            )

    def _choose_target_file(self):
        path = filedialog.askopenfilename(title="Choose target list")
        if path:
            self.targets_var.set(f'-f "{path}"')

    def _start(self):
        selections = list(self.tree.selection())
        if not selections:
            messagebox.showwarning("No scanner selected", "Select at least one scanner.")
            return
        self._start_rows([self.row_by_item[item] for item in selections])

    def _start_all(self):
        batch_rows = [
            row for row in self.rows if row["file"] not in audit_tool.BATCH_EXCLUDED
        ]
        skipped = len(self.rows) - len(batch_rows)
        message = f"Run all {len(batch_rows)} scanners against the configured target?"
        if skipped:
            message += (
                f"\n\n{skipped} batch-incompatible scanner(s) will be skipped "
                "(for example DNS AXFR, which requires --domain)."
            )
        message += "\n\nScanners will run in parallel up to the configured worker limit."
        if not messagebox.askyesno("Run all scanners", message):
            return
        self._start_rows(batch_rows)

    def _start_rows(self, rows):
        if not self.targets_var.get().strip():
            messagebox.showwarning("No targets", "Enter an authorized target or target file.")
            return
        try:
            target_arguments = audit_tool.validate_target_arguments(
                audit_tool.parse_scanner_args(self.targets_var.get().strip())
            )
            option_arguments = audit_tool.parse_scanner_args(
                self.options_var.get().strip()
            )
            if option_arguments and not option_arguments[0].startswith("-"):
                raise ValueError("Scanner options must begin with an option flag.")
            if any(flag in option_arguments for flag in audit_tool.FILE_FLAGS):
                raise ValueError("Choose the IP list file in the Targets field.")
            self.common_arguments = target_arguments + option_arguments
            
            workers_str = self.workers_var.get().strip()
            self.max_workers = int(workers_str) if workers_str.isdigit() else 4
            self.max_workers = min(max(1, self.max_workers), 64)
        except ValueError as exc:
            messagebox.showerror("Invalid scan input", str(exc))
            return
        
        self.pending = rows
        self.batch_total = len(self.pending)
        self.batch_completed = 0
        self.current_progress = 0
        self.cancelled = False
        self._set_progress(0)
        self.run_button.configure(state="disabled")
        self.run_all_button.configure(state="disabled")
        self.cancel_button.configure(state="normal")
        self.started = time.monotonic()
        
        # Start initial batch of workers
        for _ in range(min(self.max_workers, self.batch_total)):
            self._run_next()

    def _run_next(self):
        if not self.pending:
            if not self.active_processes and (
                self.cancelled or self.batch_completed >= self.batch_total
            ):
                self._finish_batch()
            return
            
        row = self.pending.pop(0)
        scanner = audit_tool.resolve_scanner(row["id"])
        stamp = time.strftime("%Y%m%d-%H%M%S")
        output_dir = audit_tool.REPORTS / f"{row['id']}-{stamp}"
        output_dir.mkdir(parents=True, exist_ok=True)
        command = [
            sys.executable,
            str(scanner),
            *audit_tool.filter_scanner_args(scanner, self.common_arguments),
        ]
        environment = os.environ.copy()
        environment["PYTHONUNBUFFERED"] = "1"
        
        self._append(f"\n[QUEUE] Starting {row['id']}...\n")
        self.status_var.set(f"Running batch — {len(self.active_processes) + 1} active, {len(self.pending)} queued")
        
        threading.Thread(
            target=self._execute,
            args=(command, output_dir, environment, row),
            daemon=True,
        ).start()

    def _execute(self, command, output_dir, environment, row):
        output_filter = TerminalOutputFilter()
        process = None
        try:
            process = subprocess.Popen(
                command,
                cwd=output_dir,
                env=environment,
                stdout=subprocess.PIPE,
                stderr=subprocess.STDOUT,
                bufsize=0,
            )
            self.active_processes.add(process)
            
            self.events.put(("output", f"\n{'=' * 60}\n{row['id']} START\n{'=' * 60}\n"))
            
            while True:
                chunk = process.stdout.read(256)
                if chunk:
                    clean = output_filter.feed(chunk.decode("utf-8", errors="replace"))
                    if clean:
                        self.events.put(("output", clean))
                elif process.poll() is not None:
                    break
            output_filter.finish()
            returncode = process.wait()
            process.stdout.close()
            if process in self.active_processes:
                self.active_processes.remove(process)
            self.events.put(("done", row, returncode))
        except Exception as exc:
            if process is not None and process in self.active_processes:
                self.active_processes.remove(process)
            self.events.put(("error", row, str(exc)))

    def _drain_events(self):
        try:
            while True:
                event = self.events.get_nowait()
                if event[0] == "output":
                    text = event[1].replace("\r", "\n")
                    self._append(text)
                    parsed = progress_from_output(text)
                    if parsed is not None:
                        # For parallel, individual scanner progress is less useful for global bar
                        # but we still track it for the last one
                        self.current_progress = parsed
                        self._update_batch_progress()
                elif event[0] == "done":
                    _kind, row, returncode = event
                    self._append(f"\n[DONE] {row['id']}: {audit_tool.outcome_label(returncode)}\n")
                    self.batch_completed += 1
                    self._update_batch_progress()
                    self._run_next()
                elif event[0] == "error":
                    _kind, row, detail = event
                    self._append(f"\n[ERROR] {row['id']}: {detail}\n")
                    self.batch_completed += 1 # Count errors as completion
                    self._run_next()
        except queue.Empty:
            pass
        self.root.after(100, self._drain_events)

    def _finish_batch(self):
        self.started = None
        self._set_progress(100)
        self.run_button.configure(state="normal")
        self.run_all_button.configure(state="normal")
        self.cancel_button.configure(state="disabled")
        self.elapsed_var.set("Elapsed 00:00")
        self.status_var.set(
            "Scan batch cancelled" if self.cancelled else "Scan batch complete"
        )
        self.cancelled = False

    def _update_batch_progress(self):
        if not self.batch_total:
            self._set_progress(0)
            return
        # Simple completion-based progress for parallel runs
        overall = (self.batch_completed * 100) / self.batch_total
        self._set_progress(int(overall))

    def _cancel(self):
        self.cancelled = True
        self.pending.clear()
        for process in list(self.active_processes):
            if process.poll() is None:
                process.terminate()
        self.status_var.set("Cancelling active scanners…")
        if not self.active_processes:
            self._finish_batch()

    def _tick(self):
        if self.started is not None:
            self.elapsed_var.set(
                f"Elapsed {audit_tool.format_elapsed(time.monotonic() - self.started)}"
            )
        self.root.after(500, self._tick)

    def _append(self, text):
        self.console.insert("end", text)
        self.console.see("end")

    def _clear_output(self):
        self.console.delete("1.0", "end")

    def _open_reports(self):
        audit_tool.REPORTS.mkdir(parents=True, exist_ok=True)
        try:
            if sys.platform == "win32":
                os.startfile(audit_tool.REPORTS)
            elif sys.platform == "darwin":
                subprocess.Popen(["open", str(audit_tool.REPORTS)])
            else:
                subprocess.Popen(["xdg-open", str(audit_tool.REPORTS)])
        except OSError as exc:
            messagebox.showerror("Cannot open reports", str(exc))

    def _on_close(self):
        if self.active_processes:
            if not messagebox.askyesno(
                "Scan running", "Cancel all active scans and close the application?"
            ):
                return
            self.pending.clear()
            for p in list(self.active_processes):
                try:
                    p.terminate()
                except Exception:
                    pass
        self.root.destroy()


def launch_gui():
    try:
        root = tk.Tk()
    except tk.TclError as exc:
        print(f"Tk GUI unavailable ({exc}). Starting browser GUI instead.", file=sys.stderr)
        return launch_web_gui()
    AuditToolGUI(root)
    root.mainloop()
    return 0


WEB_HTML = r"""<!doctype html>
<html lang="en">
<head>
<meta charset="utf-8"><meta name="viewport" content="width=device-width,initial-scale=1">
<title>Security Audit Tool</title>
<style>
:root{color-scheme:dark;--bg:#0b1020;--panel:#121a2b;--line:#28344b;--text:#e8eef8;--muted:#91a0b8;--blue:#4da3ff;--green:#45d483;--yellow:#f1c75b}
*{box-sizing:border-box}body{margin:0;background:linear-gradient(135deg,#09101e,#111a2d);color:var(--text);font:14px system-ui,Segoe UI,sans-serif}
main{max-width:1400px;margin:auto;padding:24px}.title{display:flex;align-items:baseline;gap:16px}h1{margin:0;font-size:28px}.muted{color:var(--muted)}
.panel{background:rgba(18,26,43,.96);border:1px solid var(--line);border-radius:12px;padding:14px;margin-top:14px;box-shadow:0 12px 40px #0005}
.toolbar,.actions{display:flex;gap:10px;align-items:center;flex-wrap:wrap}input,select,button{background:#0d1526;color:var(--text);border:1px solid #34425c;border-radius:7px;padding:9px 11px}
input{min-width:260px;flex:1}button{cursor:pointer}button.primary{background:#1677d8;border-color:#4da3ff;font-weight:700}button.danger{background:#6e2630}button:disabled{opacity:.45;cursor:not-allowed}
.table-wrap{max-height:360px;overflow:auto;border:1px solid var(--line);border-radius:8px;margin-top:12px}table{width:100%;border-collapse:collapse}th,td{padding:9px;border-bottom:1px solid #202b40;text-align:left}th{position:sticky;top:0;background:#172238;z-index:1}.mode{font-weight:700}.VERIFY{color:var(--green)}.ASSESS{color:var(--yellow)}.DISCOVER{color:#65b7ff}
.progress{height:8px;background:#0a1020;border-radius:8px;overflow:hidden;margin:12px 0}.bar{height:100%;width:0;background:linear-gradient(90deg,#2387e8,#62d2ff);transition:width .25s}.running .bar{width:35%;animation:slide 1.3s infinite ease-in-out}@keyframes slide{from{transform:translateX(-120%)}to{transform:translateX(330%)}}
pre{height:270px;overflow:auto;white-space:pre-wrap;background:#070b13;border:1px solid #243047;border-radius:8px;padding:12px;color:#d9e5f5;font:13px Consolas,monospace}
#status{font-weight:650}.grid{display:grid;grid-template-columns:1fr 1fr;gap:10px}@media(max-width:800px){.grid{grid-template-columns:1fr}}
</style></head>
<body><main>
<div class="title"><h1>Security Audit Tool</h1><span class="muted">Conservative findings · live progress · cancellable scans</span></div>
<section class="panel">
 <div class="toolbar"><input id="search" placeholder="Search scanners"><select id="category"><option value="">All categories</option></select><span id="count" class="muted"></span></div>
 <div class="table-wrap"><table><thead><tr><th></th><th>Scanner</th><th>Category</th><th>Mode</th><th>Description</th></tr></thead><tbody id="rows"></tbody></table></div>
</section>
<section class="panel">
 <div class="grid"><input id="targets" placeholder="IP, CIDR subnet, or -f IP-list.txt"><input id="options" placeholder="Options, e.g. --workers 10 --timeout 5"></div>
<div class="actions" style="margin-top:10px"><button id="run" class="primary">Run selected</button><button id="runAll" class="primary">Run all scanners</button><button id="cancel" class="danger" disabled>Cancel</button><button id="clear">Clear output</button><span id="status">Ready</span><span id="percent">0%</span><span id="elapsed" class="muted"></span></div>
 <div id="progress" class="progress"><div id="bar" class="bar"></div></div><pre id="output"></pre>
</section>
</main><script>
let catalog=[],batchCatalog=[],started=0,lastOutput="";
const $=id=>document.getElementById(id);
async function load(){catalog=await (await fetch('/api/catalog')).json();batchCatalog=catalog.filter(x=>x.batch_compatible!==false);for(const c of [...new Set(catalog.map(x=>x.category))].sort())$('category').insertAdjacentHTML('beforeend',`<option>${c}</option>`);render();poll()}
function esc(s){return String(s).replace(/[&<>"]/g,c=>({'&':'&amp;','<':'&lt;','>':'&gt;','"':'&quot;'}[c]))}
function render(){const q=$('search').value.toLowerCase(),cat=$('category').value;const rows=catalog.filter(r=>(!cat||r.category===cat)&&JSON.stringify(r).toLowerCase().includes(q));$('rows').innerHTML=rows.map(r=>`<tr><td><input type="checkbox" data-id="${esc(r.id)}"></td><td>${esc(r.id)}</td><td>${esc(r.category)}</td><td class="mode ${r.verification}">${r.verification}</td><td>${esc(r.description)}</td></tr>`).join('');$('count').textContent=`${rows.length} shown / ${catalog.length}`}
$('search').oninput=render;$('category').onchange=render;
async function runBatch(scanners){if(!scanners.length)return alert('Select at least one scanner.');if(!$('targets').value.trim())return alert('Enter an authorized target.');const arguments=[$('targets').value,$('options').value].filter(Boolean).join(' ');const r=await fetch('/api/run',{method:'POST',headers:{'Content-Type':'application/json'},body:JSON.stringify({scanners,arguments})});const d=await r.json();if(!r.ok)alert(d.error||'Could not start scan');else started=Date.now()}
$('run').onclick=()=>runBatch([...document.querySelectorAll('input[data-id]:checked')].map(x=>x.dataset.id));
$('runAll').onclick=()=>{if(confirm(`Run all ${batchCatalog.length} batch-compatible scanners?`))runBatch(batchCatalog.map(x=>x.id))};
$('cancel').onclick=()=>fetch('/api/cancel',{method:'POST'});$('clear').onclick=()=>{lastOutput="";$('output').textContent=""};
async function poll(){try{const s=await (await fetch('/api/status')).json();$('status').textContent=s.status;$('run').disabled=s.running;$('runAll').disabled=s.running;$('cancel').disabled=!s.running;$('bar').style.width=`${s.progress}%`;$('percent').textContent=`${s.progress}%`;if(s.output!==lastOutput){lastOutput=s.output;$('output').textContent=s.output;$('output').scrollTop=$('output').scrollHeight}if(s.running&&started)$('elapsed').textContent=`Elapsed ${Math.floor((Date.now()-started)/1000)}s`;else $('elapsed').textContent=""}catch(e){}setTimeout(poll,500)}load();
</script></body></html>"""


class WebScanState:
    def __init__(self):
        self.lock = threading.Lock()
        self.process = None
        self.running = False
        self.cancelled = False
        self.status = "Ready"
        self.output = ""
        self.progress = 0

    def snapshot(self):
        with self.lock:
            return {
                "running": self.running,
                "status": self.status,
                "output": self.output[-1_000_000:],
                "progress": self.progress,
            }

    def append(self, text):
        with self.lock:
            self.output = (self.output + text)[-1_000_000:]

    def start(self, scanners, arguments):
        scanner_args = audit_tool.validate_target_arguments(
            audit_tool.parse_scanner_args(arguments)
        )
        with self.lock:
            if self.running:
                raise RuntimeError("A scan batch is already running.")
            self.running = True
            self.cancelled = False
            self.status = "Starting scan batch…"
            self.output = ""
            self.progress = 0
        threading.Thread(
            target=self._run_batch,
            args=(scanners, scanner_args),
            daemon=True,
        ).start()

    def _run_batch(self, scanners, scanner_args):
        try:
            runnable = []
            for scanner_id in scanners:
                path = audit_tool.resolve_scanner(scanner_id)
                if path.name in audit_tool.BATCH_EXCLUDED:
                    self.append(
                        f"\n[SKIP] {scanner_id}: not compatible with shared batch "
                        "arguments (run it individually with required options).\n"
                    )
                    continue
                runnable.append(scanner_id)
            scanners = runnable
            total = len(scanners)
            if not total:
                with self.lock:
                    self.status = "No batch-compatible scanners selected"
                return
            for index, scanner_id in enumerate(scanners, 1):
                with self.lock:
                    if self.cancelled:
                        break
                    self.status = f"Running {scanner_id} ({index}/{len(scanners)})"
                path = audit_tool.resolve_scanner(scanner_id)
                stamp = time.strftime("%Y%m%d-%H%M%S")
                output_dir = audit_tool.REPORTS / f"{scanner_id}-{stamp}-{index}"
                output_dir.mkdir(parents=True, exist_ok=True)
                command = [
                    sys.executable,
                    str(path),
                    *audit_tool.filter_scanner_args(path, scanner_args),
                ]
                self.append(
                    f"\n{'=' * 88}\n{scanner_id}\nReports: {output_dir}\n"
                    f"Command: {subprocess.list2cmdline(command)}\n{'-' * 88}\n"
                )
                environment = os.environ.copy()
                environment["PYTHONUNBUFFERED"] = "1"
                process = subprocess.Popen(
                    command,
                    cwd=output_dir,
                    env=environment,
                    stdout=subprocess.PIPE,
                    stderr=subprocess.STDOUT,
                    bufsize=0,
                )
                with self.lock:
                    self.process = process
                output_filter = TerminalOutputFilter()
                current_progress = 0
                while True:
                    chunk = process.stdout.read(256)
                    if chunk:
                        clean = output_filter.feed(
                            chunk.decode("utf-8", errors="replace")
                        )
                        if clean:
                            self.append(clean.replace("\r", "\n"))
                            parsed = progress_from_output(clean)
                            if parsed is not None:
                                current_progress = max(current_progress, parsed)
                                with self.lock:
                                    self.progress = min(
                                        99,
                                        int(
                                            (
                                                (index - 1) * 100
                                                + current_progress
                                            )
                                            / total
                                        ),
                                    )
                    elif process.poll() is not None:
                        break
                output_filter.finish()
                returncode = process.wait()
                process.stdout.close()
                self.append(f"\n[{scanner_id}] {audit_tool.outcome_label(returncode)}\n")
                with self.lock:
                    self.progress = min(99, int(index * 100 / total))
            with self.lock:
                self.status = "Cancelled" if self.cancelled else "Scan batch complete"
                if not self.cancelled:
                    self.progress = 100
        except Exception as exc:
            self.append(f"\nERROR: {exc}\n")
            with self.lock:
                self.status = f"Error: {exc}"
        finally:
            with self.lock:
                self.process = None
                self.running = False

    def cancel(self):
        with self.lock:
            self.cancelled = True
            process = self.process
            self.status = "Cancelling…"
        if process is not None and process.poll() is None:
            process.terminate()


def create_web_server(host="127.0.0.1", port=0):
    state = WebScanState()

    class Handler(BaseHTTPRequestHandler):
        def log_message(self, _format, *_args):
            return

        def send_bytes(self, data, content_type="application/json", status=200):
            self.send_response(status)
            self.send_header("Content-Type", content_type)
            self.send_header("Content-Length", str(len(data)))
            self.send_header("Cache-Control", "no-store")
            self.end_headers()
            self.wfile.write(data)

        def send_json(self, value, status=200):
            self.send_bytes(
                json.dumps(value).encode("utf-8"),
                "application/json; charset=utf-8",
                status,
            )

        def do_GET(self):
            if self.path == "/":
                self.send_bytes(WEB_HTML.encode("utf-8"), "text/html; charset=utf-8")
            elif self.path == "/api/catalog":
                self.send_json(audit_tool.catalog())
            elif self.path == "/api/status":
                self.send_json(state.snapshot())
            else:
                self.send_json({"error": "Not found"}, 404)

        def do_POST(self):
            length = int(self.headers.get("Content-Length", "0"))
            try:
                payload = json.loads(self.rfile.read(length) or b"{}")
                if self.path == "/api/run":
                    scanners = payload.get("scanners") or []
                    if not isinstance(scanners, list) or not scanners:
                        raise ValueError("Select at least one scanner.")
                    for scanner_id in scanners:
                        audit_tool.resolve_scanner(str(scanner_id))
                    state.start(scanners, str(payload.get("arguments", "")))
                    self.send_json({"ok": True})
                elif self.path == "/api/cancel":
                    state.cancel()
                    self.send_json({"ok": True})
                else:
                    self.send_json({"error": "Not found"}, 404)
            except (ValueError, RuntimeError, json.JSONDecodeError) as exc:
                self.send_json({"error": str(exc)}, 400)

    server = ThreadingHTTPServer((host, port), Handler)
    server.scan_state = state
    return server


def launch_web_gui():
    server = create_web_server()
    host, port = server.server_address
    url = f"http://{host}:{port}/"
    print(f"Browser GUI: {url}")
    if not os.environ.get("AUDIT_TOOL_NO_BROWSER"):
        webbrowser.open(url)
    try:
        server.serve_forever()
    except KeyboardInterrupt:
        print("\nGUI stopped.")
    finally:
        server.server_close()
    return 0


if __name__ == "__main__":
    raise SystemExit(launch_gui())
