"""
p2_gui.py — Graphical front-end for the Siemens P2 Protocol Scanner.

A tkinter/ttk desktop app that wraps the p2_scanner library:

  * Loads / edits / saves site.json
  * Shows a Network → Nodes → Devices tree
  * Enumerates FLN devices, verifies online/offline
  * Reads all points on a device, quick-scan subset, or single point by
    name or slot, with full Desigo-style slot/label rendering
  * Exports results to CSV/JSON
  * Port-scans a range to find new PXCs
  * Queries PXC firmware

Run from the same directory as p2_scanner.py:

    python p2_gui.py                # loads site.json if present
    python p2_gui.py --config mysite.json

Read-only, same as the CLI scanner. No writes, ever.
"""

from __future__ import annotations

import argparse
import csv as _csv
import json
import os
import queue
import sys
import tkinter as tk
from tkinter import filedialog, messagebox, simpledialog, ttk
from typing import Any, Dict, List, Optional, Tuple

# p2_scanner is located at runtime, not import time. The GUI zip and the
# scanner zip usually get extracted to different folders; we'd rather hunt
# for it (and prompt the user if needed) than fail on a rigid assumption.
_HERE = os.path.dirname(os.path.abspath(__file__))
if _HERE not in sys.path:
    sys.path.insert(0, _HERE)

# Placeholder — populated by _locate_and_import_p2_scanner() in main().
# All references to `p2.something` throughout this module resolve at call
# time, so the module-global rebind works fine.
p2 = None  # type: ignore

_SCANNER_PATH_CACHE = os.path.join(_HERE, ".p2_gui_scanner_path")


def _enable_high_dpi() -> None:
    """Tell Windows we'll handle our own DPI scaling so it stops bitmap-
    scaling us into a blurry mess on high-DPI displays. No-op elsewhere.

    Called before tk.Tk() — the Tk root reads DPI at construction time."""
    if sys.platform != "win32":
        return
    try:
        import ctypes
        # Try per-monitor-aware (Windows 8.1+) first; fall back to system DPI
        # aware; fall back to the old SetProcessDPIAware API.
        try:
            ctypes.windll.shcore.SetProcessDpiAwareness(2)
        except (AttributeError, OSError):
            try:
                ctypes.windll.shcore.SetProcessDpiAwareness(1)
            except (AttributeError, OSError):
                try:
                    ctypes.windll.user32.SetProcessDPIAware()
                except Exception:
                    pass
    except Exception:
        pass  # Not fatal — worst case the window is just fuzzy

from p2_gui_widgets import (  # noqa: E402
    CompareWindow,
    ConfigDialog,
    HelpWindow,
    HistoryWindow,
    LogPane,
    NodeTree,
    PointTable,
    ProgramsWindow,
    ScanHistory,
    SinglePointDialog,
    SweepDialog,
    SweepResultsWindow,
    WalkPointsWindow,
)
from p2_gui_workers import TaskRunner  # noqa: E402


DEFAULT_CONFIG_PATH = os.path.join(_HERE, "site.json")
POLL_INTERVAL_MS = 80


# ═══════════════════════════════════════════════════════════════════════════
# MAIN WINDOW
# ═══════════════════════════════════════════════════════════════════════════

class MainWindow:
    def __init__(self, root: tk.Tk, config_path: str) -> None:
        self.root = root
        self.config_path = config_path

        self.log_queue: "queue.Queue[Tuple[str, str]]" = queue.Queue()
        self.result_queue: "queue.Queue[tuple]" = queue.Queue()
        # Used for mid-task progress updates (e.g. live-verify per-device
        # status flips) separate from final results. Workers push tuples
        # here; the UI thread drains them in _poll().
        self.progress_queue: "queue.Queue[tuple]" = queue.Queue()
        self.runner = TaskRunner(self.log_queue, self.result_queue)

        # (node_name, device_name) -> list of result dicts (latest scan only)
        # Used for the detail-panel "restore when I click back" behavior.
        # Full scan history with timestamps lives separately in scan_history.
        self._device_cache: Dict[Tuple[str, str], List[Dict]] = {}
        # Session-wide scan history: every scan and sweep done since launch,
        # with timestamps so the user can go back and compare.
        self.scan_history = ScanHistory()
        # node_name -> firmware info dict
        self._firmware_cache: Dict[str, Dict] = {}
        # node_name -> list of device dicts from enumerate
        self._node_devices: Dict[str, List[Dict]] = {}

        self._current_device: Optional[Dict] = None
        self._current_node: Optional[Dict] = None

        self._build_ui()
        self._refresh_identity_labels()
        self._rebuild_tree_from_config()

        self._load_config_if_present()
        self._start_polling()

        # Note on first-connect latency for users new to this build. The
        # scanner auto-detects legacy vs modern PXC wire dialect; modern
        # panels add ~2s to the very first connect while it probes. After
        # that it's cached for the session. Keeping this concise — a
        # 3-line info blurb, not a wall.
        self.log.log(
            "Scanner supports both legacy (PME1252) and modern "
            "(PME1300) PXC firmware.",
            level="info",
        )
        self.log.log(
            "First connect to a modern panel may take ~2s extra while "
            "the dialect is probed; subsequent connects are fast.",
            level="info",
        )

        root.protocol("WM_DELETE_WINDOW", self._on_close)

    # ------------------------------------------------------------------
    # UI construction
    # ------------------------------------------------------------------

    def _build_ui(self) -> None:
        self.root.title("P2 Scanner — GUI")
        # Size + center on screen (nothing worse than an app opening
        # scrunched in the top-left corner on a multi-monitor setup).
        w, h = 1240, 820
        self.root.update_idletasks()
        sw = self.root.winfo_screenwidth()
        sh = self.root.winfo_screenheight()
        x = max(0, (sw - w) // 2)
        y = max(0, (sh - h) // 2)
        self.root.geometry(f"{w}x{h}+{x}+{y}")
        self.root.minsize(960, 600)

        try:
            style = ttk.Style()
            # 'clam' is the most consistent cross-platform ttk theme
            if "clam" in style.theme_names():
                style.theme_use("clam")
            style.configure("Treeview", rowheight=22)
        except tk.TclError:
            pass

        # ── Menu ─────────────────────────────────────────────────────
        menubar = tk.Menu(self.root)

        filemenu = tk.Menu(menubar, tearoff=0)
        filemenu.add_command(label="Load Config…", command=self._menu_load)
        filemenu.add_command(label="Save Config", command=self._menu_save)
        filemenu.add_command(label="Save Config As…", command=self._menu_save_as)
        filemenu.add_separator()
        filemenu.add_command(label="Edit Site Config…", command=self._menu_edit_config)
        filemenu.add_separator()
        filemenu.add_command(label="Exit", command=self._on_close)
        menubar.add_cascade(label="File", menu=filemenu)

        discmenu = tk.Menu(menubar, tearoff=0)
        discmenu.add_command(
            label="Port Scan Range…", command=self._menu_port_scan
        )
        discmenu.add_command(
            label="Add Node Manually…", command=self._menu_add_node
        )
        discmenu.add_separator()
        discmenu.add_command(
            label="Sweep Points Across Devices…", command=self._menu_sweep
        )
        menubar.add_cascade(label="Discovery", menu=discmenu)

        viewmenu = tk.Menu(menubar, tearoff=0)
        viewmenu.add_command(
            label="Scan History…", command=self._menu_scan_history
        )
        menubar.add_cascade(label="View", menu=viewmenu)

        helpmenu = tk.Menu(menubar, tearoff=0)
        helpmenu.add_command(label="User Guide", command=self._menu_user_guide)
        helpmenu.add_separator()
        helpmenu.add_command(label="About", command=self._menu_about)
        menubar.add_cascade(label="Help", menu=helpmenu)

        self.root.config(menu=menubar)

        # ── Toolbar ──────────────────────────────────────────────────
        toolbar = ttk.Frame(self.root, padding=(10, 6))
        toolbar.pack(side="top", fill="x")

        self.net_label = ttk.Label(
            toolbar, text="Network: —", font=("", 10, "bold")
        )
        self.net_label.pack(side="left", padx=(0, 14))
        self.site_label = ttk.Label(toolbar, text="Site: —", foreground="#666")
        self.site_label.pack(side="left", padx=(0, 14))
        self.scanner_label = ttk.Label(
            toolbar, text="Scanner: —", foreground="#666"
        )
        self.scanner_label.pack(side="left", padx=(0, 14))

        ttk.Button(
            toolbar, text="Edit Config…", command=self._menu_edit_config
        ).pack(side="right", padx=2)

        self.debug_var = tk.BooleanVar()
        ttk.Checkbutton(
            toolbar,
            text="Debug reads",
            variable=self.debug_var,
            command=self._toggle_debug,
        ).pack(side="right", padx=12)

        # ── Main body (vertical paned: work area | log) ──────────────
        vpane = ttk.PanedWindow(self.root, orient="vertical")
        vpane.pack(fill="both", expand=True, padx=10, pady=(0, 4))

        hpane = ttk.PanedWindow(vpane, orient="horizontal")
        vpane.add(hpane, weight=3)

        # Left: tree + node-level buttons
        left = ttk.Frame(hpane)
        hpane.add(left, weight=1)

        self.tree = NodeTree(
            left,
            on_select_node=self._on_select_node,
            on_select_device=self._on_select_device,
        )
        self.tree.pack(side="top", fill="both", expand=True)

        tree_btns = ttk.Frame(left)
        tree_btns.pack(side="top", fill="x", pady=(6, 0))
        self._enum_btn = ttk.Button(
            tree_btns, text="Enumerate FLN", command=self._enumerate_node
        )
        self._enum_btn.pack(side="left", padx=2, fill="x", expand=True)
        self._verify_btn = ttk.Button(
            tree_btns, text="Verify Online", command=self._verify_node
        )
        self._verify_btn.pack(side="left", padx=2, fill="x", expand=True)
        self._firmware_btn = ttk.Button(
            tree_btns, text="Firmware", command=self._query_firmware
        )
        self._firmware_btn.pack(side="left", padx=2, fill="x", expand=True)

        # Secondary node operations: panel-wide walks that are potentially
        # slow (10-30s on a busy panel), so given their own row so they're
        # distinct from the snappy primary ops.
        tree_btns2 = ttk.Frame(left)
        tree_btns2.pack(side="top", fill="x", pady=(3, 0))
        self._walk_btn = ttk.Button(
            tree_btns2, text="Walk All Points", command=self._walk_all_points
        )
        self._walk_btn.pack(side="left", padx=2, fill="x", expand=True)
        self._programs_btn = ttk.Button(
            tree_btns2, text="PPCL Programs", command=self._dump_programs
        )
        self._programs_btn.pack(side="left", padx=2, fill="x", expand=True)

        # Right: device detail
        right = ttk.Frame(hpane, padding=(8, 0, 0, 0))
        hpane.add(right, weight=3)

        self.detail_header = ttk.Label(
            right, text="Select a node or device", font=("", 12, "bold")
        )
        self.detail_header.pack(anchor="w")
        self.detail_subhead = ttk.Label(
            right, text="", foreground="#555"
        )
        self.detail_subhead.pack(anchor="w", pady=(0, 8))

        detail_btns = ttk.Frame(right)
        detail_btns.pack(fill="x", pady=(0, 8))
        self._scan_all_btn = ttk.Button(
            detail_btns,
            text="Scan All Points",
            command=self._scan_all,
            state="disabled",
        )
        self._scan_all_btn.pack(side="left", padx=2)
        self._quick_btn = ttk.Button(
            detail_btns,
            text="Quick Scan",
            command=self._scan_quick,
            state="disabled",
        )
        self._quick_btn.pack(side="left", padx=2)
        self._single_btn = ttk.Button(
            detail_btns,
            text="Read Point…",
            command=self._read_single,
            state="disabled",
        )
        self._single_btn.pack(side="left", padx=2)

        ttk.Separator(detail_btns, orient="vertical").pack(
            side="left", fill="y", padx=10
        )
        self._csv_btn = ttk.Button(
            detail_btns,
            text="Export CSV…",
            command=self._export_csv,
            state="disabled",
        )
        self._csv_btn.pack(side="left", padx=2)
        self._json_btn = ttk.Button(
            detail_btns,
            text="Export JSON…",
            command=self._export_json,
            state="disabled",
        )
        self._json_btn.pack(side="left", padx=2)

        self.point_table = PointTable(right)
        self.point_table.pack(fill="both", expand=True)

        # ── Log pane ────────────────────────────────────────────────
        logframe = ttk.LabelFrame(vpane, text=" Log ", padding=4)
        vpane.add(logframe, weight=1)
        self.log = LogPane(logframe, self.log_queue)
        self.log.pack(fill="both", expand=True)

        # ── Status bar ──────────────────────────────────────────────
        status = ttk.Frame(self.root, padding=(10, 3))
        status.pack(side="bottom", fill="x")
        self.status_label = ttk.Label(status, text="Ready", foreground="#555")
        self.status_label.pack(side="left")
        self.busy_label = ttk.Label(status, text="", foreground="#c48a00")
        self.busy_label.pack(side="right")

    # ------------------------------------------------------------------
    # Config handling
    # ------------------------------------------------------------------

    def _load_config_if_present(self) -> None:
        if not os.path.exists(self.config_path):
            self.log.log(
                f"No config at {self.config_path} — use File → Edit Site Config to get started.",
                level="warn",
            )
            return
        try:
            # Use the scanner's own loader so globals are set correctly
            ok = p2.load_config(self.config_path)
            if ok:
                self.log.log(
                    f"Loaded config: network={p2.P2_NETWORK or '—'}, "
                    f"site={p2.P2_SITE or '—'}, "
                    f"{len(p2.KNOWN_NODES)} nodes",
                    level="ok",
                )
                self._refresh_identity_labels()
                self._rebuild_tree_from_config()
                # Warn on obvious placeholder values
                if p2.P2_NETWORK == "MYBLN" or p2.P2_SITE == "SITE":
                    self.log.log(
                        "Config still has placeholder values (MYBLN / SITE). "
                        "Edit via File → Edit Site Config before running scans.",
                        level="warn",
                    )
        except Exception as e:
            self.log.log(f"Config load failed: {e}", level="error")

    def _current_config_dict(self) -> Dict:
        """Snapshot the scanner's current globals into a config dict."""
        return {
            "p2_network": p2.P2_NETWORK,
            "p2_site": p2.P2_SITE,
            "scanner_name": p2.SCANNER_NAME,
            "known_nodes": dict(p2.KNOWN_NODES),
        }

    def _apply_config_dict(self, cfg: Dict) -> None:
        """Apply config dict into scanner globals."""
        p2._set_network(cfg.get("p2_network", ""))
        p2._set_scanner_name(cfg.get("scanner_name", "P2SCAN|5034"))
        # P2_SITE doesn't have a setter — write to the module directly
        p2.P2_SITE = cfg.get("p2_site", "")
        # KNOWN_NODES is a dict the scanner mutates; replace contents
        p2.KNOWN_NODES.clear()
        p2.KNOWN_NODES.update(cfg.get("known_nodes", {}))

    def _save_config_to(self, path: str) -> bool:
        try:
            # save_config reads from module globals; write it ourselves so
            # we can preserve arbitrary extra keys too (e.g. _comment)
            existing: Dict = {}
            if os.path.exists(path):
                try:
                    with open(path) as f:
                        existing = json.load(f)
                except Exception:
                    existing = {}
            existing["p2_network"] = p2.P2_NETWORK
            existing["p2_site"] = p2.P2_SITE
            existing["scanner_name"] = p2.SCANNER_NAME
            existing["known_nodes"] = dict(p2.KNOWN_NODES)
            with open(path, "w") as f:
                json.dump(existing, f, indent=2)
            return True
        except OSError as e:
            messagebox.showerror("Save failed", str(e), parent=self.root)
            return False

    def _refresh_identity_labels(self) -> None:
        net = p2.P2_NETWORK if p2 else ""
        site = p2.P2_SITE if p2 else ""
        scanner = p2.SCANNER_NAME if p2 else ""
        self.net_label.configure(text=f"Network: {net or '—'}")
        self.site_label.configure(text=f"Site: {site or '—'}")
        self.scanner_label.configure(text=f"Scanner: {scanner or '—'}")

    def _rebuild_tree_from_config(self) -> None:
        """Rebuild the tree to reflect current p2.KNOWN_NODES."""
        self.tree.set_network(p2.P2_NETWORK)
        for name, ip in sorted(p2.KNOWN_NODES.items()):
            self.tree.add_node(name, ip)

    # ------------------------------------------------------------------
    # Menu handlers
    # ------------------------------------------------------------------

    def _menu_load(self) -> None:
        path = filedialog.askopenfilename(
            parent=self.root,
            title="Load site config",
            filetypes=[("JSON", "*.json"), ("All files", "*.*")],
            initialdir=_HERE,
        )
        if not path:
            return
        self.config_path = path
        self._load_config_if_present()

    def _menu_save(self) -> None:
        if self._save_config_to(self.config_path):
            self.log.log(f"Saved config to {self.config_path}", level="ok")

    def _menu_save_as(self) -> None:
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title="Save site config",
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
            initialdir=_HERE,
        )
        if not path:
            return
        if self._save_config_to(path):
            self.config_path = path
            self.log.log(f"Saved config to {path}", level="ok")

    def _menu_edit_config(self) -> None:
        new_cfg = ConfigDialog.ask(self.root, self._current_config_dict())
        if new_cfg is None:
            return
        self._apply_config_dict(new_cfg)
        self._refresh_identity_labels()
        self._rebuild_tree_from_config()
        # Clear caches — they were keyed on the previous identity
        self._device_cache.clear()
        self._firmware_cache.clear()
        self._node_devices.clear()
        self._clear_detail_panel()
        self.log.log("Config updated (not yet saved to disk).", level="info")

    def _menu_add_node(self) -> None:
        # Import the small name+IP dialog directly from widgets; avoids
        # reopening the full ConfigDialog (which Edit Config already does).
        from p2_gui_widgets import _NodeEditDialog  # local import to keep public API clean

        r = _NodeEditDialog.ask(self.root, "Add Node")
        if not r:
            return
        name, ip = r
        if name in p2.KNOWN_NODES and not messagebox.askyesno(
            "Replace existing?",
            f"Node '{name}' already maps to {p2.KNOWN_NODES[name]}.\n"
            f"Replace with {ip}?",
            parent=self.root,
        ):
            return
        p2.KNOWN_NODES[name] = ip
        self._rebuild_tree_from_config()
        self.log.log(f"Added node {name} → {ip}", level="ok")

    def _menu_port_scan(self) -> None:
        if self.runner.busy:
            messagebox.showinfo(
                "Busy", "Finish the current operation first.", parent=self.root
            )
            return
        range_str = simpledialog.askstring(
            "Port Scan",
            "IP range to scan for PXC (TCP/5033):\n\n"
            "Formats:  192.0.2.50  |  192.0.2.80-200  |  192.0.2.0/24  |  192.0.2",
            parent=self.root,
        )
        if not range_str:
            return
        range_str = range_str.strip()
        self.log.log(f"Port-scanning {range_str} for PXC on TCP/5033…")
        self._set_busy(f"Port scanning {range_str}…")
        self.runner.submit(
            ("port_scan", range_str),
            self._do_port_scan,
            range_str,
        )

    # ------------------------------------------------------------------
    # Sweep — read specified points across many devices at once
    # ------------------------------------------------------------------

    def _menu_sweep(self) -> None:
        if not self._check_busy():
            return
        if not p2.P2_NETWORK:
            messagebox.showwarning(
                "No network name",
                "Set the BLN network name first (File → Edit Site Config).",
                parent=self.root,
            )
            return

        # Build the "available nodes" list from config, plus per-node device
        # counts (total / online) from whatever we've already enumerated.
        available_nodes = [
            {"name": name, "ip": ip}
            for name, ip in sorted(p2.KNOWN_NODES.items())
        ]
        device_counts: Dict[str, Tuple[int, int]] = {}
        for name, ip in p2.KNOWN_NODES.items():
            devs = self._node_devices.get(name, [])
            total = len(devs)
            online = sum(1 for d in devs if d.get("status") == "online")
            device_counts[name] = (total, online)

        if not any(tot for tot, _ in device_counts.values()):
            if not messagebox.askyesno(
                "No enumerated devices",
                "No devices have been enumerated yet. A sweep with nothing "
                "to read will produce nothing.\n\n"
                "Enumerate FLN on at least one node first, or open the "
                "dialog anyway to review options?",
                parent=self.root,
            ):
                return

        spec = SweepDialog.ask(self.root, available_nodes, device_counts)
        if not spec:
            return

        targets = self._build_sweep_targets(spec)
        if not targets:
            messagebox.showinfo(
                "Nothing to sweep",
                "No devices matched the selected scope. Try enumerating "
                "more nodes or loosening the scope (e.g. 'All enumerated' "
                "instead of 'Only online').",
                parent=self.root,
            )
            return

        self._last_sweep_spec = spec  # for re-sweep
        self.log.log(
            f"Sweeping {len(spec['points'])} point(s) "
            f"across {len(targets)} device(s)…"
        )
        self._set_busy(f"Sweeping {len(targets)} devices…")
        self.runner.submit(
            ("sweep", tuple(spec["points"])),
            self._do_sweep_points,
            targets,
            list(spec["points"]),
        )

    def _build_sweep_targets(self, spec: Dict) -> List[Dict]:
        """Turn a SweepDialog spec into a concrete list of target dicts.

        Each target: {'node', 'host', 'device', 'description', 'application'}
        """
        selected_nodes = spec["nodes"]
        scope = spec["scope"]  # 'all' | 'online'

        targets: List[Dict] = []
        for node_name in sorted(selected_nodes):
            host = p2.KNOWN_NODES.get(node_name)
            if not host:
                continue
            devs = self._node_devices.get(node_name, [])
            for d in devs:
                if scope == "online" and d.get("status") != "online":
                    continue
                targets.append(
                    {
                        "node": node_name,
                        "host": host,
                        "device": d["device"],
                        "description": d.get("description", ""),
                        "application": d.get("application", 0) or 0,
                    }
                )
        return targets

    @staticmethod
    def _do_sweep_points(
        targets: List[Dict], points: List[str]
    ) -> List[Dict]:
        """Worker: iterate devices, read `points` on each, collect results.

        Runs in the background worker thread. Prints progress via the
        redirected stdout so the UI log shows live status.
        """
        sweep_results: List[Dict] = []
        total = len(targets)

        for i, t in enumerate(targets, start=1):
            node = t["node"]
            host = t["host"]
            dev = t["device"]
            desc = t["description"]
            app = t["application"]

            # Per-device optimization: if we know the app, filter out points
            # that aren't defined in its point table. Saves timeouts for
            # points like "HEAT.COOL" when sweeping across a mixed-app
            # building where not every app has that point. Numeric slot
            # references are kept regardless since they resolve per-app.
            scan_points: List[str] = []
            skipped: List[str] = []
            if app:
                try:
                    table = p2.get_point_table(app)
                except Exception:
                    table = None
                if table:
                    defined = {entry[0] for entry in table.values()}
                    for pt in points:
                        if str(pt).strip().isdigit() or pt in defined:
                            scan_points.append(pt)
                        else:
                            skipped.append(pt)
                else:
                    scan_points = list(points)
            else:
                scan_points = list(points)

            print(f"  Sweep {i}/{total} — {node}/{dev}", flush=True)

            if not scan_points:
                # All requested points are undefined for this app; log and
                # record a synthetic miss so the user sees why.
                sweep_results.append(
                    {
                        "_node": node,
                        "_device": dev,
                        "_description": desc,
                        "error": "no requested points defined in app "
                        f"{app}",
                    }
                )
                continue

            try:
                dev_results = p2.scan_device(
                    host,
                    dev,
                    scan_points,
                    False,  # quick
                    "none",  # suppress per-device banners; use our log
                    False,  # force_slot
                )
            except p2.ScannerInputError:
                # Bad input (invalid slot etc.) — propagate so the UI can
                # show a friendly error and stop the whole sweep.
                raise
            except Exception as e:
                sweep_results.append(
                    {
                        "_node": node,
                        "_device": dev,
                        "_description": desc,
                        "error": str(e),
                    }
                )
                continue

            if dev_results:
                for r in dev_results:
                    # Skip the APPLICATION read that scan_device always does —
                    # the user didn't ask for it in a sweep context.
                    if r.get("point_name") == "APPLICATION" and "APPLICATION" not in points:
                        continue
                    r["_node"] = node
                    r["_device"] = dev
                    r["_description"] = desc
                    sweep_results.append(r)
            else:
                sweep_results.append(
                    {
                        "_node": node,
                        "_device": dev,
                        "_description": desc,
                        "error": "no data",
                    }
                )

        print(f"  Sweep complete: {total} device(s) visited, "
              f"{len(sweep_results)} result row(s)", flush=True)
        return sweep_results

    def _on_sweep_done(self, task_id: tuple, results: List[Dict]) -> None:
        if not results:
            self.log.log("Sweep returned no rows.", level="warn")
            return

        points = list(task_id[1])

        # Archive the sweep first. Figure out how many distinct devices
        # were touched by counting (node, device) pairs in the results.
        unique_devices = {
            (r.get("_node") or r.get("node"), r.get("_device") or r.get("device"))
            for r in results
        }
        self.scan_history.add_sweep(
            points=points,
            target_count=len(unique_devices),
            results=results,
        )

        SweepResultsWindow(
            self.root,
            points=points,
            results=results,
            on_jump_to_device=self._jump_to_device,
            on_resweep=self._menu_sweep,
            on_export_csv=self._export_sweep_csv,
            on_export_json=self._export_sweep_json,
        )

    def _jump_to_device(self, node_name: str, device_name: str) -> None:
        """Select a device in the main NodeTree (called when user double-
        clicks a sweep result row)."""
        # Bring main window to front
        self.root.lift()
        self.root.focus_force()

        # Use the tree's internal lookup — walk children of the node iid
        node_iid = self.tree._node_iid_by_name.get(node_name)  # noqa: SLF001
        if not node_iid:
            self.log.log(f"Node {node_name} not in tree", level="warn")
            return
        for child in self.tree._tree.get_children(node_iid):  # noqa: SLF001
            entry = self.tree._data.get(child)  # noqa: SLF001
            if entry and entry[0] == "device" and entry[1]["device"] == device_name:
                self.tree._tree.selection_set(child)  # noqa: SLF001
                self.tree._tree.focus(child)  # noqa: SLF001
                self.tree._tree.see(child)  # noqa: SLF001
                return
        self.log.log(
            f"Device {device_name} not in tree under {node_name}",
            level="warn",
        )

    def _export_sweep_csv(
        self, results: List[Dict], points: List[str]
    ) -> None:
        from tkinter import filedialog  # local to keep toolbar callbacks light
        import csv as _csv_mod
        default = f"sweep_{'_'.join(p.replace(' ', '') for p in points)[:40]}.csv"
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title="Export sweep results (CSV)",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")],
            initialfile=default,
        )
        if not path:
            return
        cols = [
            "node", "device", "description", "point_slot", "point_name",
            "value", "value_text", "units", "point_type", "comm_status",
            "error",
        ]
        try:
            with open(path, "w", newline="") as f:
                w = _csv_mod.writer(f)
                w.writerow(cols)
                for r in results:
                    w.writerow(
                        [
                            r.get("_node", r.get("node", "")),
                            r.get("_device", r.get("device", "")),
                            r.get("_description", r.get("description", "")),
                            r.get("point_slot", "") if r.get("point_slot") is not None else "",
                            r.get("point_name", ""),
                            r.get("value", "") if r.get("value") is not None else "",
                            r.get("value_text", "") or "",
                            r.get("units", "") or "",
                            r.get("point_type", "") or "",
                            r.get("comm_status", "") or "",
                            r.get("error", "") or "",
                        ]
                    )
            self.log.log(f"Exported {len(results)} sweep rows → {path}", level="ok")
        except OSError as e:
            messagebox.showerror("Export failed", str(e), parent=self.root)

    def _export_sweep_json(
        self, results: List[Dict], points: List[str]
    ) -> None:
        from tkinter import filedialog
        default = f"sweep_{'_'.join(p.replace(' ', '') for p in points)[:40]}.json"
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title="Export sweep results (JSON)",
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
            initialfile=default,
        )
        if not path:
            return
        try:
            with open(path, "w") as f:
                json.dump(
                    {"points": points, "results": results},
                    f,
                    indent=2,
                    default=str,
                )
            self.log.log(f"Exported {len(results)} sweep rows → {path}", level="ok")
        except OSError as e:
            messagebox.showerror("Export failed", str(e), parent=self.root)

    def _menu_user_guide(self) -> None:
        # Track an instance so repeated clicks raise the existing window
        # instead of stacking duplicates.
        existing = getattr(self, "_help_window", None)
        if existing is not None:
            try:
                if existing.winfo_exists():
                    existing.lift()
                    existing.focus_set()
                    return
            except tk.TclError:
                pass
        self._help_window = HelpWindow(self.root)

    # ------------------------------------------------------------------
    # Scan history
    # ------------------------------------------------------------------

    def _menu_scan_history(self) -> None:
        """Open (or raise) the session scan-history browser."""
        existing = getattr(self, "_history_window", None)
        if existing is not None:
            try:
                if existing.winfo_exists():
                    existing.refresh()
                    existing.lift()
                    existing.focus_set()
                    return
            except tk.TclError:
                pass
        self._history_window = HistoryWindow(
            self.root,
            history=self.scan_history,
            on_open_entry=self._open_history_entry,
            on_compare_entries=self._compare_history_entries,
        )

    def _open_history_entry(self, entry: Dict) -> None:
        """User double-clicked or hit Open on a history entry."""
        if entry["kind"] == "device":
            # Restore into the detail panel: find the device in the tree,
            # select it, and inject the historical results into the table.
            self._jump_to_device(entry["node"], entry["device"])
            # _jump_to_device sets _current_device via the selection event;
            # once that's done, load the historical results instead of the
            # latest cached. We schedule via after(0) so selection events
            # fire first.
            def restore() -> None:
                self.point_table.load(entry["results"])
                self._csv_btn.configure(state="normal")
                self._json_btn.configure(state="normal")
                self.log.log(
                    f"Loaded historical {entry.get('scan_type', 'scan')} "
                    f"of {entry['device']} from "
                    f"{self._format_ts(entry['timestamp'])}",
                    level="info",
                )
            self.root.after(50, restore)
        elif entry["kind"] == "sweep":
            # Reopen the sweep results window with the historical results
            SweepResultsWindow(
                self.root,
                points=list(entry["points"]),
                results=list(entry["results"]),
                on_jump_to_device=self._jump_to_device,
                on_resweep=self._menu_sweep,
                on_export_csv=self._export_sweep_csv,
                on_export_json=self._export_sweep_json,
            )
            self.log.log(
                f"Reopened sweep from {self._format_ts(entry['timestamp'])}: "
                f"{', '.join(entry['points'])}",
                level="info",
            )
        elif entry["kind"] == "walk":
            # Reopen a historical walk in a fresh WalkPointsWindow
            WalkPointsWindow(
                self.root,
                node_name=entry["node"],
                entries=list(entry["entries"]),
                on_export_csv=self._export_walk_csv,
                on_export_json=self._export_walk_json,
            )
            self.log.log(
                f"Reopened walk of {entry['node']} from "
                f"{self._format_ts(entry['timestamp'])}",
                level="info",
            )

    def _compare_history_entries(
        self, before: Dict, after: Dict
    ) -> None:
        """User selected two entries and clicked Compare."""
        CompareWindow(self.root, before, after)
        self.log.log(
            f"Comparing {self._format_ts(before['timestamp'])} → "
            f"{self._format_ts(after['timestamp'])}",
            level="info",
        )

    @staticmethod
    def _format_ts(ts: float) -> str:
        import datetime
        return datetime.datetime.fromtimestamp(ts).strftime("%H:%M:%S")

    def _menu_about(self) -> None:
        messagebox.showinfo(
            "About",
            "P2 Scanner GUI\n\n"
            "Desktop front-end for the Siemens P2 protocol scanner.\n"
            "Wraps the p2_scanner library for interactive use against\n"
            "Siemens PXC controllers.\n\n"
            "Read-only — never writes to controllers.",
            parent=self.root,
        )

    def _toggle_debug(self) -> None:
        p2.DEBUG_READS = bool(self.debug_var.get())
        self.log.log(
            f"Debug reads {'ON' if p2.DEBUG_READS else 'OFF'}",
            level="info",
        )

    # ------------------------------------------------------------------
    # Tree selection callbacks
    # ------------------------------------------------------------------

    def _on_select_node(self, payload: Dict) -> None:
        self._current_node = payload
        self._current_device = None
        # Surface the panel's reachability state in the header. payload
        # may not include status if the node was just added — default
        # to unknown/gray. The status flips to online/offline whenever a
        # node-level operation completes (or fails), via
        # NodeTree.set_node_status, but the payload dict the tree
        # selection callback hands us reflects whatever was there at
        # selection time. Pull the latest from the tree directly.
        latest = self.tree.node_payload(payload["name"]) or payload
        node_status = latest.get("status", "unknown")
        status_color = {
            "online": "#0a7a0a",
            "offline": "#a82020",
        }.get(node_status, "")
        if node_status == "online":
            header = f"Node: {payload['name']}   (online)"
        elif node_status == "offline":
            header = f"Node: {payload['name']}   (offline)"
        else:
            header = f"Node: {payload['name']}"
        self.detail_header.configure(text=header, foreground=status_color)
        self.detail_subhead.configure(text=f"{payload['ip']}   ·   TCP/5033")

        fw = self._firmware_cache.get(payload["name"])
        if fw:
            sub = (
                f"{payload['ip']}   ·   "
                f"model={fw.get('model', '?')}   "
                f"firmware={fw.get('firmware', '?')}"
            )
            if fw.get("extra"):
                sub += f"   ·   {fw['extra']}"
            self.detail_subhead.configure(text=sub)

        self._scan_all_btn.configure(state="disabled")
        self._quick_btn.configure(state="disabled")
        self._single_btn.configure(state="disabled")
        self._csv_btn.configure(state="disabled")
        self._json_btn.configure(state="disabled")
        self.point_table.clear()

    def _on_select_device(self, payload: Dict) -> None:
        self._current_device = payload
        self._current_node = None

        app_str = f"app {payload.get('application')}" if payload.get("application") else "app unknown"
        if payload.get("application_cached"):
            # APPLICATION came from the panel cache for a comm-faulted
            # device — flag it so the user knows it's not live.
            app_str += " (cached)"
        status = payload.get("status", "unknown")
        comm = payload.get("comm_status")
        extras = []
        if payload.get("room_temp") is not None:
            extras.append(
                f"ROOM TEMP {payload['room_temp']:.1f}{payload.get('units', '') or ''}"
            )
        elif comm == "comm_fault" and payload.get("stale_temp") is not None:
            # FLN-faulted: surface the cached value the panel is still
            # serving, but mark it as stale so it isn't mistaken for live.
            extras.append(
                f"ROOM TEMP {payload['stale_temp']:.1f}"
                f"{payload.get('units', '') or ''} (cached, #COM)"
            )
        if payload.get("description"):
            extras.append(payload["description"])
        extra_str = "   ·   ".join(extras)
        # Color: green for online, red for offline. For online-but-#COM
        # (which shouldn't happen with the corrected scanner, but might
        # arise from race conditions), fall back to amber.
        if status == "online":
            status_color = "#a06010" if comm == "comm_fault" else "#0a7a0a"
        elif status == "offline":
            status_color = "#a82020"
        else:
            status_color = "#666666"
        # Header label: append #COM tag for comm-faulted devices
        if comm == "comm_fault":
            header_label = f"Device: {payload['device']}   ({status} · #COM)"
        else:
            header_label = f"Device: {payload['device']}   ({status})"
        self.detail_header.configure(
            text=header_label,
            foreground=status_color,
        )
        self.detail_subhead.configure(
            text=(
                f"node={payload['node']}   ·   {payload['host']}   ·   "
                f"{app_str}" + (f"   ·   {extra_str}" if extra_str else "")
            )
        )

        self._scan_all_btn.configure(state="normal")
        self._quick_btn.configure(state="normal")
        self._single_btn.configure(state="normal")

        # Show cached results if any
        cache_key = (payload["node"], payload["device"])
        cached = self._device_cache.get(cache_key)
        if cached:
            self.point_table.load(cached)
            self._csv_btn.configure(state="normal")
            self._json_btn.configure(state="normal")
        else:
            self.point_table.clear()
            self._csv_btn.configure(state="disabled")
            self._json_btn.configure(state="disabled")

    def _clear_detail_panel(self) -> None:
        self._current_device = None
        self._current_node = None
        self.detail_header.configure(text="Select a node or device", foreground="")
        self.detail_subhead.configure(text="")
        self.point_table.clear()
        for btn in (
            self._scan_all_btn,
            self._quick_btn,
            self._single_btn,
            self._csv_btn,
            self._json_btn,
        ):
            btn.configure(state="disabled")

    # ------------------------------------------------------------------
    # Node-level operations
    # ------------------------------------------------------------------

    def _require_node(self) -> Optional[Dict]:
        node = self.tree.selected_node_payload()
        if not node:
            messagebox.showinfo(
                "No node selected", "Select a node first.", parent=self.root
            )
            return None
        if not p2.P2_NETWORK:
            messagebox.showwarning(
                "No network name",
                "Set the BLN network name first (File → Edit Site Config).",
                parent=self.root,
            )
            return None
        return node

    def _enumerate_node(self) -> None:
        node = self._require_node()
        if not node or not self._check_busy():
            return
        self.log.log(f"Enumerating FLN devices on {node['name']} ({node['ip']})…")
        self._set_busy(f"Enumerating {node['name']}…")
        self.runner.submit(
            ("enumerate", node["name"]),
            p2.enumerate_fln_devices,
            node["ip"],
            node["name"],
        )

    def _verify_node(self) -> None:
        node = self._require_node()
        if not node or not self._check_busy():
            return
        devices = self._node_devices.get(node["name"])
        if not devices:
            # No FLN devices to verify — but the user still wants to
            # know whether the PXC itself is reachable. Run a firmware
            # query as the lightest available "is this panel up?" probe;
            # the result handler flips the node row to online or
            # offline. This is especially useful for nodes that only
            # host PPCL programs / global points and never had devices,
            # where the device-level Verify would simply do nothing.
            self.log.log(
                f"No enumerated devices for {node['name']} — "
                f"probing PXC reachability instead…"
            )
            self._set_busy(f"Probing {node['name']}…")
            self.runner.submit(
                ("firmware", node["name"]),
                self._do_firmware_query,
                node["ip"],
                node["name"],
            )
            return
        self.log.log(
            f"Verifying {len(devices)} devices on {node['name']}…"
        )
        self._set_busy(f"Verifying {node['name']}…")
        # Live verify: our own worker opens one PXC connection and pushes a
        # progress update to progress_queue after each device so the tree
        # can flip green/red in real time. Without this the user stares at
        # a frozen UI for multiple minutes on sites with offline devices.
        self.runner.submit(
            ("verify", node["name"]),
            self._do_verify_live,
            node["ip"],
            node["name"],
            devices,
            self.progress_queue,
        )

    @staticmethod
    def _do_verify_live(
        host: str,
        node_name: str,
        devices: List[Dict],
        progress_queue: "queue.Queue[tuple]",
    ) -> List[Dict]:
        """Worker: verify online/offline status device-by-device, pushing a
        per-device progress update to progress_queue as we go.

        Mirrors the logic of p2.verify_devices but with live progress.
        Mutates `devices` in place and also returns it."""
        net = p2.P2_NETWORK if p2.P2_NETWORK else "P2NET"
        conn = p2.P2Connection(host, network=net, scanner_name=p2.SCANNER_NAME)
        node_lower = node_name.lower()

        if not conn.connect(node_lower):
            print(f"  [ERROR] Could not connect to {host} as {node_name}")
            return devices

        total = len(devices)
        online = 0
        offline = 0

        try:
            for i, dev in enumerate(devices, start=1):
                dev_name = dev["device"]
                # Read ROOM TEMP first. The comm_status flag on the
                # response is the authoritative live/dead signal — it
                # matches Desigo's own #COM indicator on the same point.
                #   comm_status=='online'     → live FLN read → ONLINE
                #   comm_status=='comm_fault' → PXC returned stale cache
                #                               because the device is
                #                               FLN-faulted → OFFLINE
                #   None (no ROOM TEMP point) → fall through to APPLICATION
                #                               as a last-resort probe
                #
                # NOTE: an earlier version of this loop fell back to
                # APPLICATION whenever ROOM TEMP came back stale.
                # APPLICATION is panel-cached metadata (configured app
                # number), not live FLN data — it returns successfully
                # even for #COM-faulted devices, so falling back to it
                # converts true offlines into false onlines. The scanner
                # was fixed; this mirror has been brought into line.
                result = conn.read_point(dev_name, "ROOM TEMP", node_lower)

                # Default: offline until proven otherwise
                dev["status"] = "offline"
                room_temp_comm = result.get("comm_status") if result else None
                if room_temp_comm:
                    dev["comm_status"] = room_temp_comm

                if result and result.get("comm_status") == "online":
                    # Live ROOM TEMP read.
                    dev["status"] = "online"
                    dev["room_temp"] = result.get("value")
                    dev["units"] = result.get("units", "")
                    if dev.get("application", 0) == 0:
                        app_result = conn.read_point(
                            dev_name, "APPLICATION", node_lower
                        )
                        if app_result and app_result.get("value") is not None:
                            dev["application"] = int(app_result["value"])
                    online += 1
                elif result and result.get("comm_status") == "comm_fault":
                    # PXC explicitly reports the device as FLN-faulted.
                    # Record the stale value (useful for diagnostics) but
                    # do NOT mark online. APPLICATION would lie here.
                    dev["stale_temp"] = result.get("value")
                    if "units" not in dev:
                        dev["units"] = result.get("units", "")
                    # Best-effort: still surface APPLICATION from the
                    # panel cache so the GUI can show "app 2090" beside
                    # the offline indicator (matching what Desigo does).
                    if dev.get("application", 0) == 0:
                        app_result = conn.read_point(
                            dev_name, "APPLICATION", node_lower
                        )
                        if app_result and app_result.get("value") is not None:
                            dev["application"] = int(app_result["value"])
                            dev["application_cached"] = True
                    offline += 1
                else:
                    # No ROOM TEMP response at all (point doesn't exist on
                    # this device, parse failed, or panel returned an
                    # error). Fall back to APPLICATION — for devices
                    # without a ROOM TEMP point this is the only way to
                    # confirm they exist. Trust comm_status here too:
                    # if APPLICATION itself comes back stale, the device
                    # is offline.
                    app_result = conn.read_point(
                        dev_name, "APPLICATION", node_lower
                    )
                    if app_result and app_result.get("value") is not None:
                        if app_result.get("comm_status") == "comm_fault":
                            dev["comm_status"] = "comm_fault"
                            if dev.get("application", 0) == 0:
                                dev["application"] = int(app_result["value"])
                                dev["application_cached"] = True
                            offline += 1
                        else:
                            dev["status"] = "online"
                            if dev.get("application", 0) == 0:
                                dev["application"] = int(app_result["value"])
                            online += 1
                    else:
                        offline += 1

                # Push progress so the UI thread can update the tree row.
                # We copy the dev dict so subsequent in-place changes by this
                # loop can't race the UI's reading of the update.
                try:
                    progress_queue.put_nowait(
                        ("verify_progress", node_name, i, total, dict(dev))
                    )
                except Exception:
                    pass  # best-effort; a full queue shouldn't kill the verify

                # Also log progress to stdout (captured in the log pane)
                print(
                    f"  Verify {i}/{total} — {dev_name:<18s} → "
                    f"{dev['status']}",
                    flush=True,
                )
        finally:
            conn.close()

        print(
            f"  Verify complete: {online} online, {offline} offline, {total} total"
        )
        return devices

    def _query_firmware(self) -> None:
        node = self._require_node()
        if not node or not self._check_busy():
            return
        self.log.log(f"Querying firmware on {node['name']}…")
        self._set_busy(f"Firmware query: {node['name']}…")
        # Try the newer 0x010C compact sysinfo first — returns more fields
        # on PME1300-era firmware — and silently fall back to legacy 0x0100
        # on older panels.
        self.runner.submit(
            ("firmware", node["name"]),
            self._do_firmware_query,
            node["ip"],
            node["name"],
        )

    @staticmethod
    def _do_firmware_query(host: str, node_name: str) -> Optional[Dict]:
        """Worker: try 0x010C first, fall back to 0x0100. Returns a dict
        shaped for _on_firmware_done regardless of which opcode worked."""
        net = p2.P2_NETWORK if p2.P2_NETWORK else "P2NET"
        conn = p2.P2Connection(host, network=net, scanner_name=p2.SCANNER_NAME)
        try:
            if not conn.connect(node_name.lower()):
                print(f"  Could not connect to {host} as {node_name}")
                return None

            # Newer panels: compact (0x010C) — returns model + firmware
            # string + build_date + raw_strings list. More informative on
            # PME1300-era firmware than legacy 0x0100.
            compact = conn.read_system_info_compact(node_name.lower())
            if compact:
                result = {
                    "model": compact.get("model", ""),
                    "firmware": compact.get("firmware", ""),
                    "build": compact.get("build_date", ""),
                    "extra": "",
                    "_source": "compact (0x010C)",
                }
                # Stick the full raw string list into 'extra' so the user
                # sees everything the panel sent back, formatted compactly
                rs = compact.get("raw_strings") or []
                if rs and len(rs) > 3:
                    result["extra"] = " | ".join(rs[3:7])[:80]
                print(
                    f"  Compact sysinfo: model={result['model']}  "
                    f"firmware={result['firmware']}  "
                    f"build={result['build']}"
                )
                return result
            # Older panels: legacy sysinfo (0x0100)
            print("  Compact sysinfo not supported; falling back to legacy 0x0100…")
        finally:
            conn.close()

        # Legacy path: use the existing helper (opens its own connection)
        legacy = p2.get_node_info(host, node_name)
        if legacy:
            legacy = dict(legacy)  # defensive copy
            legacy["_source"] = "legacy (0x0100)"
        return legacy

    def _walk_all_points(self) -> None:
        """Walk every point on the panel via 0x0981 cursor pagination.
        Can take 10-30 seconds on a busy panel."""
        node = self._require_node()
        if not node or not self._check_busy():
            return
        if not messagebox.askyesno(
            "Walk all points?",
            f"This enumerates every point on {node['name']} — including "
            "PPCL variables, schedule points, and global analogs.\n\n"
            "It can take 10–30 seconds on a busy panel. Continue?",
            parent=self.root,
        ):
            return
        self.log.log(f"Walking all points on {node['name']}…")
        self._set_busy(f"Walk points: {node['name']}…")
        self.runner.submit(
            ("walk_points", node["name"]),
            self._do_walk_points,
            node["ip"],
            node["name"],
        )

    @staticmethod
    def _do_walk_points(host: str, node_name: str) -> List[Dict]:
        net = p2.P2_NETWORK if p2.P2_NETWORK else "P2NET"
        conn = p2.P2Connection(host, network=net, scanner_name=p2.SCANNER_NAME)
        try:
            if not conn.connect(node_name.lower()):
                print(f"  Could not connect to {host} as {node_name}")
                return []
            print(f"  Enumerating all points on {node_name}…")
            entries = conn.enumerate_all_points(node_name.lower())
            print(f"  Walk complete: {len(entries)} entr{'ies' if len(entries) != 1 else 'y'} found")
            return entries
        finally:
            conn.close()

    def _dump_programs(self) -> None:
        """Dump PPCL source code for every program on the panel."""
        node = self._require_node()
        if not node or not self._check_busy():
            return
        if not messagebox.askyesno(
            "Dump PPCL programs?",
            f"This reads every PPCL program's source from {node['name']}.\n\n"
            "It can take 10–30 seconds on a busy panel. Continue?",
            parent=self.root,
        ):
            return
        self.log.log(f"Dumping PPCL programs on {node['name']}…")
        self._set_busy(f"Dump programs: {node['name']}…")
        self.runner.submit(
            ("dump_programs", node["name"]),
            self._do_dump_programs,
            node["ip"],
            node["name"],
        )

    @staticmethod
    def _do_dump_programs(host: str, node_name: str) -> List[Dict]:
        net = p2.P2_NETWORK if p2.P2_NETWORK else "P2NET"
        conn = p2.P2Connection(host, network=net, scanner_name=p2.SCANNER_NAME)
        try:
            if not conn.connect(node_name.lower()):
                print(f"  Could not connect to {host} as {node_name}")
                return []
            print(f"  Reading PPCL programs on {node_name}…")
            programs = conn.read_programs(node_name.lower())
            total_lines = sum(p.get("code", "").count("\n") for p in programs)
            print(
                f"  Dump complete: {len(programs)} program{'s' if len(programs) != 1 else ''}, "
                f"{total_lines} total lines"
            )
            return programs
        finally:
            conn.close()

    # ------------------------------------------------------------------
    # Device-level operations
    # ------------------------------------------------------------------

    def _require_device(self) -> Optional[Dict]:
        if not self._current_device:
            messagebox.showinfo(
                "No device selected",
                "Select a device in the tree first.",
                parent=self.root,
            )
            return None
        if not p2.P2_NETWORK:
            messagebox.showwarning(
                "No network name",
                "Set the BLN network name first (File → Edit Site Config).",
                parent=self.root,
            )
            return None
        return self._current_device

    def _scan_all(self) -> None:
        dev = self._require_device()
        if not dev or not self._check_busy():
            return
        self.log.log(
            f"Scanning all points on {dev['device']} via {dev['node']} "
            f"({dev['host']})…"
        )
        self._set_busy(f"Scanning {dev['device']}…")
        self.runner.submit(
            ("scan_all", dev["node"], dev["device"]),
            p2.scan_device,
            dev["host"],
            dev["device"],
            None,  # points
            False,  # quick
            "none",  # suppress scan_device's own table/json/csv print
            False,  # force_slot
        )

    def _scan_quick(self) -> None:
        dev = self._require_device()
        if not dev or not self._check_busy():
            return

        # Filter QUICK_SCAN_POINTS down to just what's actually defined in
        # this device's application. The scanner's built-in quick=True mode
        # tries all 18 names blindly — any that don't exist in the app time
        # out on the wire, so on a small app the "quick" scan ends up slower
        # than a full scan. Filtering makes it actually quick.
        app = dev.get("application") or 0
        quick_points = list(getattr(p2, "QUICK_SCAN_POINTS", []))
        if app and quick_points:
            try:
                table = p2.get_point_table(app)
                if table:
                    defined = {entry[0] for entry in table.values()}
                    filtered = [p for p in quick_points if p in defined]
                    if filtered:
                        quick_points = filtered
            except Exception:
                pass  # non-fatal — fall through with the unfiltered list

        self.log.log(
            f"Quick scan on {dev['device']} ({len(quick_points)} points)…"
        )
        self._set_busy(f"Quick-scanning {dev['device']}…")
        self.runner.submit(
            ("scan_quick", dev["node"], dev["device"]),
            p2.scan_device,
            dev["host"],
            dev["device"],
            quick_points,  # explicit list — bypass quick=True
            False,         # quick
            "none",
            False,
        )

    def _read_single(self) -> None:
        dev = self._require_device()
        if not dev or not self._check_busy():
            return
        r = SinglePointDialog.ask(
            self.root,
            device_name=dev["device"],
            application=dev.get("application") or None,
        )
        if not r:
            return
        point, force_slot = r
        self.log.log(
            f"Reading {point!r} on {dev['device']} "
            f"(force_slot={force_slot})…"
        )
        self._set_busy(f"Reading {point}…")
        self.runner.submit(
            ("scan_single", dev["node"], dev["device"]),
            p2.scan_device,
            dev["host"],
            dev["device"],
            [point],
            False,
            "none",
            force_slot,
        )

    # ------------------------------------------------------------------
    # Exports
    # ------------------------------------------------------------------

    def _export_csv(self) -> None:
        results = self.point_table.results()
        if not results:
            return
        dev = self._current_device or {}
        default_name = f"{dev.get('node', 'node')}_{dev.get('device', 'device')}.csv"
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title="Export CSV",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")],
            initialfile=default_name,
        )
        if not path:
            return
        try:
            with open(path, "w", newline="") as f:
                cols = [
                    "point_slot",
                    "point_name",
                    "value",
                    "value_text",
                    "units",
                    "point_type",
                    "data_type",
                    "comm_status",
                ]
                w = _csv.writer(f)
                w.writerow(cols)
                for r in results:
                    w.writerow([r.get(c, "") if r.get(c) is not None else "" for c in cols])
            self.log.log(f"Exported {len(results)} points → {path}", level="ok")
        except OSError as e:
            messagebox.showerror("Export failed", str(e), parent=self.root)

    def _export_json(self) -> None:
        results = self.point_table.results()
        if not results:
            return
        dev = self._current_device or {}
        default_name = f"{dev.get('node', 'node')}_{dev.get('device', 'device')}.json"
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title="Export JSON",
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
            initialfile=default_name,
        )
        if not path:
            return
        try:
            with open(path, "w") as f:
                json.dump(results, f, indent=2, default=str)
            self.log.log(f"Exported {len(results)} points → {path}", level="ok")
        except OSError as e:
            messagebox.showerror("Export failed", str(e), parent=self.root)

    # ------------------------------------------------------------------
    # Async task plumbing
    # ------------------------------------------------------------------

    def _check_busy(self) -> bool:
        if self.runner.busy:
            messagebox.showinfo(
                "Busy",
                "Another operation is in progress. Wait for it to finish.",
                parent=self.root,
            )
            return False
        return True

    def _set_busy(self, message: str) -> None:
        self.busy_label.configure(text=f"⏳ {message}")
        for btn in (
            self._scan_all_btn,
            self._quick_btn,
            self._single_btn,
            self._enum_btn,
            self._verify_btn,
            self._firmware_btn,
            self._walk_btn,
            self._programs_btn,
        ):
            btn.configure(state="disabled")

    def _clear_busy(self) -> None:
        self.busy_label.configure(text="")
        # Re-enable per current selection
        if self._current_device:
            self._scan_all_btn.configure(state="normal")
            self._quick_btn.configure(state="normal")
            self._single_btn.configure(state="normal")
            results = self.point_table.results()
            self._csv_btn.configure(state="normal" if results else "disabled")
            self._json_btn.configure(state="normal" if results else "disabled")
        for btn in (
            self._enum_btn, self._verify_btn, self._firmware_btn,
            self._walk_btn, self._programs_btn,
        ):
            btn.configure(state="normal")

    def _start_polling(self) -> None:
        self._poll()

    def _poll(self) -> None:
        """Tk event-loop tick. Drain log + progress + result queues."""
        self.log.poll()
        # Drain progress updates first — they're frequent and cheap, and
        # doing them before final results means a final "verify complete"
        # arrives after all its per-device updates have been rendered.
        while True:
            try:
                upd = self.progress_queue.get_nowait()
            except queue.Empty:
                break
            try:
                self._handle_progress(upd)
            except Exception as e:  # noqa: BLE001
                self.log.log(f"Progress handler error: {e}", level="error")
        while True:
            try:
                item = self.result_queue.get_nowait()
            except queue.Empty:
                break
            try:
                self._handle_result(item)
            except Exception as e:  # noqa: BLE001
                self.log.log(f"Result handler error: {e}", level="error")
        self.root.after(POLL_INTERVAL_MS, self._poll)

    def _handle_progress(self, upd: tuple) -> None:
        """Handle a mid-task progress update from a worker.

        Current update kinds:
            ('verify_progress', node_name, i, total, updated_device_dict)
        """
        if not upd:
            return
        kind = upd[0]
        if kind == "verify_progress":
            _, node_name, i, total, dev = upd
            # Update the tree row in place so the user sees the color flip
            self.tree.update_device_status(node_name, dev["device"], dev)
            # Also keep the busy label informative
            status_tag = dev.get("status") or "…"
            self.busy_label.configure(
                text=f"⏳ Verifying {node_name}: {i}/{total} "
                f"({dev['device']} → {status_tag})"
            )

    def _handle_result(self, item: tuple) -> None:
        task_id, status, payload, elapsed = item

        if status == "error":
            exc, tb = payload
            # If a node-level operation failed (firmware, enumerate,
            # walk, programs, verify), the panel itself is likely not
            # reachable. Flip the node row to offline so the user can
            # see at a glance which PXC is dead. We restrict this to
            # node-scoped task kinds — a per-device scan failure
            # shouldn't repaint the whole node.
            if (
                isinstance(task_id, tuple)
                and len(task_id) >= 2
                and task_id[0] in (
                    "firmware",
                    "enumerate",
                    "verify",
                    "walk_points",
                    "dump_programs",
                )
            ):
                self.tree.set_node_status(task_id[1], "offline")
            # Surface ScannerInputError as a friendly message instead of a stack trace
            if p2 is not None and isinstance(exc, getattr(p2, "ScannerInputError", ())):
                messagebox.showwarning(
                    "Invalid input", str(exc), parent=self.root
                )
                self.log.log(f"Input rejected: {exc}", level="warn")
            else:
                self.log.log(
                    f"Task {task_id!r} failed after {elapsed:.1f}s: {exc}",
                    level="error",
                )
                # Dump traceback lines at 'error' level; keep them indented
                for line in tb.rstrip().splitlines()[-6:]:
                    self.log.log("    " + line, level="error")
            self._clear_busy()
            return

        # status == 'ok'
        kind = task_id[0] if isinstance(task_id, tuple) else task_id
        self.log.log(f"Completed in {elapsed:.1f}s", level="ok")

        try:
            if kind == "enumerate":
                self._on_enumerate_done(task_id, payload)
            elif kind == "verify":
                self._on_verify_done(task_id, payload)
            elif kind == "firmware":
                self._on_firmware_done(task_id, payload)
            elif kind in ("scan_all", "scan_quick", "scan_single"):
                self._on_scan_done(task_id, payload)
            elif kind == "port_scan":
                self._on_port_scan_done(task_id, payload)
            elif kind == "sweep":
                self._on_sweep_done(task_id, payload)
            elif kind == "walk_points":
                self._on_walk_points_done(task_id, payload)
            elif kind == "dump_programs":
                self._on_dump_programs_done(task_id, payload)
        finally:
            self._clear_busy()

    # ------------------------------------------------------------------
    # Result handlers
    # ------------------------------------------------------------------

    def _on_enumerate_done(self, task_id: tuple, devices: List[Dict]) -> None:
        node_name = task_id[1]
        self._node_devices[node_name] = devices
        self.tree.set_node_devices(node_name, devices)
        # An enumerate that returns successfully means the panel
        # accepted our handshake and answered the 0x0986 request — the
        # node is reachable. An empty list (0 devices) is still a
        # success, just means the panel hosts no FLN devices.
        self.tree.set_node_status(node_name, "online")
        self.log.log(
            f"Found {len(devices)} device(s) on {node_name}", level="ok"
        )

    def _on_verify_done(self, task_id: tuple, devices: List[Dict]) -> None:
        node_name = task_id[1]
        self._node_devices[node_name] = devices
        self.tree.set_node_devices(node_name, devices)
        # Verify reached the panel — it's online regardless of how its
        # downstream FLN devices look.
        self.tree.set_node_status(node_name, "online")
        online = sum(1 for d in devices if d.get("status") == "online")
        offline = sum(1 for d in devices if d.get("status") == "offline")
        # #COM-faulted devices are a subset of offline. Surface the count
        # separately because it's the most common reason a row turns red:
        # the device is wired up and the panel still has cached data, but
        # FLN comms with the controller are currently broken.
        comm_fault = sum(
            1 for d in devices if d.get("comm_status") == "comm_fault"
        )
        if comm_fault:
            self.log.log(
                f"Verify done: {online} online, {offline} offline "
                f"({comm_fault} #COM), {len(devices)} total",
                level="ok",
            )
        else:
            self.log.log(
                f"Verify done: {online} online, {offline} offline, "
                f"{len(devices)} total",
                level="ok",
            )

    def _on_firmware_done(self, task_id: tuple, info: Optional[Dict]) -> None:
        node_name = task_id[1]
        if not info:
            # Firmware query is the lightest probe we have — if it
            # failed, the panel isn't reachable. Mark offline.
            self.tree.set_node_status(node_name, "offline")
            self.log.log(
                f"No firmware info returned for {node_name} "
                "(connect failed or handshake rejected — node likely offline)",
                level="warn",
            )
            return
        self._firmware_cache[node_name] = info
        # Successful firmware read → panel is up.
        self.tree.set_node_status(node_name, "online")
        # Build a clean summary line. Compact sysinfo gives us a build date;
        # legacy doesn't.
        parts = [f"model={info.get('model', '?')}"]
        if info.get("firmware"):
            parts.append(f"firmware={info['firmware']}")
        if info.get("build"):
            parts.append(f"build={info['build']}")
        if info.get("extra"):
            parts.append(f"extra={info['extra']}")
        source = info.get("_source", "")
        suffix = f"   [{source}]" if source else ""
        self.log.log(
            f"{node_name}: " + "   ".join(parts) + suffix,
            level="ok",
        )
        # If this is the currently selected node, update the subheader
        if self._current_node and self._current_node["name"] == node_name:
            self._on_select_node(self._current_node)

    def _on_walk_points_done(
        self, task_id: tuple, entries: List[Dict]
    ) -> None:
        node_name = task_id[1]
        if not entries:
            self.log.log(
                f"Walk points on {node_name} returned no entries "
                "— check handshake and PXC access",
                level="warn",
            )
            return
        # Reaching this point means the panel responded to 0x0981 and
        # streamed at least one entry — definitively online.
        self.tree.set_node_status(node_name, "online")
        self.log.log(
            f"{node_name}: {len(entries)} entr{'ies' if len(entries) != 1 else 'y'} walked",
            level="ok",
        )
        # Archive so the user can diff walks across time (useful for
        # tracking panel changes: "what came and went between yesterday
        # and today"). Symmetric with how regular scans are archived.
        self.scan_history.add_walk(node=node_name, entries=entries)
        WalkPointsWindow(
            self.root,
            node_name=node_name,
            entries=entries,
            on_export_csv=self._export_walk_csv,
            on_export_json=self._export_walk_json,
        )

    def _on_dump_programs_done(
        self, task_id: tuple, programs: List[Dict]
    ) -> None:
        node_name = task_id[1]
        if not programs:
            self.log.log(
                f"No PPCL programs returned for {node_name} "
                "(panel may not have any, or firmware doesn't support 0x0985)",
                level="warn",
            )
            return
        # Successful PPCL dump → panel responded to opcode 0x0985.
        self.tree.set_node_status(node_name, "online")
        total_lines = sum(p.get("code", "").count("\n") for p in programs)
        self.log.log(
            f"{node_name}: {len(programs)} program(s), {total_lines} lines",
            level="ok",
        )
        ProgramsWindow(
            self.root,
            node_name=node_name,
            programs=programs,
            on_export=self._export_programs,
        )

    # ------------------------------------------------------------------
    # Walk / programs exports
    # ------------------------------------------------------------------

    def _export_walk_csv(
        self, entries: List[Dict], node_name: str
    ) -> None:
        import csv as _csv_mod
        from tkinter import filedialog
        default = f"walk_{node_name}.csv"
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title="Export walk results (CSV)",
            defaultextension=".csv",
            filetypes=[("CSV", "*.csv")],
            initialfile=default,
        )
        if not path:
            return
        try:
            with open(path, "w", newline="") as f:
                w = _csv_mod.writer(f)
                w.writerow(["device", "subkey", "point", "value", "units", "description"])
                for e in entries:
                    w.writerow([
                        e.get("device", ""),
                        e.get("subkey", "") or "",
                        e.get("point", ""),
                        "" if e.get("value") is None else e.get("value"),
                        e.get("units", "") or "",
                        e.get("description", "") or "",
                    ])
            self.log.log(f"Exported {len(entries)} entries → {path}", level="ok")
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc), parent=self.root)

    def _export_walk_json(
        self, entries: List[Dict], node_name: str
    ) -> None:
        from tkinter import filedialog
        default = f"walk_{node_name}.json"
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title="Export walk results (JSON)",
            defaultextension=".json",
            filetypes=[("JSON", "*.json")],
            initialfile=default,
        )
        if not path:
            return
        try:
            with open(path, "w") as f:
                json.dump(
                    {"node": node_name, "entries": entries},
                    f, indent=2, default=str,
                )
            self.log.log(f"Exported {len(entries)} entries → {path}", level="ok")
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc), parent=self.root)

    def _export_programs(
        self, programs: List[Dict], node_name: str
    ) -> None:
        """Writes either a single .json archive or a folder of .ppcl files,
        depending on what the user picks."""
        from tkinter import filedialog
        default = f"ppcl_{node_name}.json"
        path = filedialog.asksaveasfilename(
            parent=self.root,
            title="Export PPCL programs (JSON)",
            defaultextension=".json",
            filetypes=[("JSON archive", "*.json"), ("All files", "*.*")],
            initialfile=default,
        )
        if not path:
            return
        try:
            with open(path, "w") as f:
                json.dump(
                    {"node": node_name, "programs": programs},
                    f, indent=2, default=str,
                )
            self.log.log(
                f"Exported {len(programs)} program(s) → {path}", level="ok"
            )
        except OSError as exc:
            messagebox.showerror("Export failed", str(exc), parent=self.root)

    def _on_scan_done(self, task_id: tuple, results: List[Dict]) -> None:
        _, node_name, device_name = task_id
        if not results:
            self.log.log(
                f"No points returned for {device_name} — "
                "check handshake, network name, or comm status",
                level="warn",
            )
            # Keep an empty result set in the table for clarity
            self.point_table.clear()
            self._device_cache.pop((node_name, device_name), None)
            self._csv_btn.configure(state="disabled")
            self._json_btn.configure(state="disabled")
            return

        kind = task_id[0]
        if kind == "scan_single":
            # Merge into any existing cached results so single-point reads
            # refresh a row in the table instead of blowing it away.
            existing = self._device_cache.get((node_name, device_name), [])
            by_name = {r.get("point_name"): r for r in existing}
            for r in results:
                by_name[r.get("point_name")] = r
            merged = list(by_name.values())
            self._device_cache[(node_name, device_name)] = merged
            self.point_table.load(merged)
        else:
            self._device_cache[(node_name, device_name)] = results
            self.point_table.load(results)

        self._csv_btn.configure(state="normal")
        self._json_btn.configure(state="normal")
        self.log.log(
            f"{device_name}: {len(results)} point(s) read", level="ok"
        )

        # Archive this scan in session history. For single-point reads we
        # record just the new results (not the merged cache) so the diff in
        # a later compare is meaningful. Application comes from the first
        # result that carries point_info (scan_device attaches app context
        # to every result via get_point_info under the hood).
        scan_type = {
            "scan_all": "full",
            "scan_quick": "quick",
            "scan_single": "single",
        }.get(kind, "full")
        # Pull application from device tree if we know it
        dev_payload = None
        for _, payload in self.tree._data.values():  # noqa: SLF001
            if isinstance(payload, dict) and payload.get("device") == device_name \
                    and payload.get("node") == node_name:
                dev_payload = payload
                break
        application = (dev_payload or {}).get("application", 0) if dev_payload else 0
        self.scan_history.add_device_scan(
            node=node_name,
            device=device_name,
            application=application,
            results=results,
            scan_type=scan_type,
        )

    def _on_port_scan_done(
        self, task_id: tuple, hosts: List[str]
    ) -> None:
        if not hosts:
            self.log.log("Port scan: no PXCs found.", level="warn")
            return
        self.log.log(f"Port scan: {len(hosts)} PXC(s) found.", level="ok")
        # Let user add discovered IPs to known_nodes
        self._offer_to_add_hosts(hosts)

    def _offer_to_add_hosts(self, hosts: List[str]) -> None:
        # Suggest sequential node names starting after the highest existing
        existing_ips = set(p2.KNOWN_NODES.values())
        new_hosts = [h for h in hosts if h not in existing_ips]
        if not new_hosts:
            messagebox.showinfo(
                "Port Scan",
                f"All {len(hosts)} discovered IPs are already in known_nodes.",
                parent=self.root,
            )
            return
        if not messagebox.askyesno(
            "Port Scan",
            f"Found {len(new_hosts)} new PXC IP(s):\n  "
            + "\n  ".join(new_hosts)
            + "\n\nAdd them to known_nodes? You'll be prompted for a name for each.",
            parent=self.root,
        ):
            return
        next_n = 1
        while any(f"NODE{next_n}" == k for k in p2.KNOWN_NODES):
            next_n += 1
        for ip in new_hosts:
            default = f"NODE{next_n}"
            name = simpledialog.askstring(
                "Add Node",
                f"Name for PXC at {ip}:",
                initialvalue=default,
                parent=self.root,
            )
            if not name:
                continue
            name = name.strip()
            p2.KNOWN_NODES[name] = ip
            self.log.log(f"Added node {name} → {ip}", level="ok")
            next_n += 1
        self._rebuild_tree_from_config()

    # ------------------------------------------------------------------
    # Port-scan helper (runs in worker thread)
    # ------------------------------------------------------------------

    @staticmethod
    def _do_port_scan(range_str: str) -> List[str]:
        ip_list = p2.parse_ip_range(range_str)
        print(f"  Port scanning {len(ip_list)} IP(s) on TCP/{p2.P2_PORT}…")
        hosts = p2.port_scan_p2(ip_list)
        print(f"  Result: {len(hosts)} PXC(s) responding.")
        for h in hosts:
            print(f"    {h}")
        return hosts

    # ------------------------------------------------------------------
    # Shutdown
    # ------------------------------------------------------------------

    def _on_close(self) -> None:
        try:
            self.runner.shutdown(wait=False)
        finally:
            self.root.destroy()


def _import_from(dirpath: str):
    """Try to import p2_scanner from `dirpath`. Returns the module on success,
    None on failure. Adds (and on failure removes) the dir from sys.path."""
    scanner_file = os.path.join(dirpath, "p2_scanner.py")
    if not os.path.isfile(scanner_file):
        return None
    # Clean any stale entry so we really import from the target dir
    sys.modules.pop("p2_scanner", None)
    if dirpath in sys.path:
        sys.path.remove(dirpath)
    sys.path.insert(0, dirpath)
    try:
        import p2_scanner as _p2  # type: ignore
        return _p2
    except Exception:
        try:
            sys.path.remove(dirpath)
        except ValueError:
            pass
        return None


def _candidate_scanner_dirs() -> List[str]:
    """Directories to auto-probe for p2_scanner.py, most likely first."""
    candidates: List[str] = []

    # 1. Same directory as p2_gui.py
    candidates.append(_HERE)

    # 2. Persisted location from previous run
    try:
        if os.path.isfile(_SCANNER_PATH_CACHE):
            with open(_SCANNER_PATH_CACHE) as f:
                remembered = f.read().strip()
            if remembered:
                candidates.append(remembered)
    except OSError:
        pass

    # 3. Common sibling folder names (scanner zips tend to unpack into these)
    parent = os.path.dirname(_HERE)
    for name in (
        "p2_scanner_cli_latest_version",
        "p2_scanner_cli",
        "p2_scanner",
        "scanner",
    ):
        candidates.append(os.path.join(parent, name))

    # 4. One-level-deep children of the GUI folder (in case the zip was
    #    extracted as a subfolder inside the GUI folder)
    try:
        for entry in os.listdir(_HERE):
            full = os.path.join(_HERE, entry)
            if os.path.isdir(full):
                candidates.append(full)
    except OSError:
        pass

    # Dedupe while preserving order
    seen = set()
    unique = []
    for c in candidates:
        norm = os.path.normcase(os.path.abspath(c))
        if norm not in seen:
            seen.add(norm)
            unique.append(c)
    return unique


def _save_scanner_path(dirpath: str) -> None:
    try:
        with open(_SCANNER_PATH_CACHE, "w") as f:
            f.write(dirpath)
    except OSError:
        pass  # cache is best-effort; not a fatal problem


def _locate_and_import_p2_scanner(root: tk.Tk) -> Optional[Any]:
    """Find p2_scanner.py, import it, return the module.

    Tries automatic candidates first, then falls back to a file picker.
    Returns None if the user cancels.
    """
    first_error: Optional[str] = None

    # Automatic probe
    for d in _candidate_scanner_dirs():
        mod = _import_from(d)
        if mod is not None:
            _save_scanner_path(d)
            return mod

    # If p2_scanner.py existed in _HERE but failed to import, try to capture
    # the error for the dialog (most likely a stdlib issue, not missing file)
    scanner_here = os.path.join(_HERE, "p2_scanner.py")
    if os.path.isfile(scanner_here):
        try:
            # Fresh import attempt to get the real exception
            sys.modules.pop("p2_scanner", None)
            import p2_scanner  # noqa: F401 - just for the exception
        except Exception as e:
            first_error = f"{type(e).__name__}: {e}"

    # Interactive fallback
    while True:
        msg = (
            "Could not locate p2_scanner.py automatically."
            if first_error is None
            else (
                "p2_scanner.py was found but failed to import:\n"
                f"  {first_error}\n\n"
                "If that looks like a code error, fix it and retry. "
                "Otherwise, browse to a different copy."
            )
        )
        msg += (
            "\n\nBrowse to the folder containing p2_scanner.py?\n\n"
            "Yes = pick the folder\n"
            "No  = pick the p2_scanner.py file itself\n"
            "Cancel = quit"
        )
        choice = messagebox.askyesnocancel("Locate p2_scanner.py", msg, parent=root)
        if choice is None:
            return None

        if choice:
            picked = filedialog.askdirectory(
                title="Folder containing p2_scanner.py",
                parent=root,
                mustexist=True,
            )
            if not picked:
                continue
            scan_dir = picked
        else:
            picked = filedialog.askopenfilename(
                title="Locate p2_scanner.py",
                parent=root,
                filetypes=[("p2_scanner.py", "p2_scanner.py"), ("Python files", "*.py")],
            )
            if not picked:
                continue
            scan_dir = os.path.dirname(os.path.abspath(picked))

        mod = _import_from(scan_dir)
        if mod is not None:
            _save_scanner_path(scan_dir)
            return mod

        # Import failed. Give a useful message.
        scanner_there = os.path.join(scan_dir, "p2_scanner.py")
        if not os.path.isfile(scanner_there):
            messagebox.showerror(
                "Not found",
                f"p2_scanner.py was not found in:\n{scan_dir}",
                parent=root,
            )
        else:
            try:
                sys.modules.pop("p2_scanner", None)
                sys.path.insert(0, scan_dir)
                import p2_scanner  # noqa: F401
            except Exception as e:
                messagebox.showerror(
                    "Import failed",
                    f"Found p2_scanner.py in:\n  {scan_dir}\n\n"
                    f"but import raised:\n  {type(e).__name__}: {e}\n\n"
                    "Make sure tecpoints.json is in that folder too.",
                    parent=root,
                )
                try:
                    sys.path.remove(scan_dir)
                except ValueError:
                    pass


# ═══════════════════════════════════════════════════════════════════════════
# ENTRY POINT
# ═══════════════════════════════════════════════════════════════════════════

def main() -> int:
    parser = argparse.ArgumentParser(
        description="Graphical front-end for the P2 Scanner"
    )
    parser.add_argument(
        "--config",
        default=DEFAULT_CONFIG_PATH,
        help=f"Path to site config JSON (default: {DEFAULT_CONFIG_PATH})",
    )
    parser.add_argument(
        "--scanner-dir",
        default=None,
        help="Explicit path to the directory containing p2_scanner.py "
        "(overrides auto-detection)",
    )
    args = parser.parse_args()

    _enable_high_dpi()

    root = tk.Tk()
    # Hide the empty root while we locate the scanner / show any dialogs.
    # Without this an empty "tk" window briefly appears next to the picker.
    root.withdraw()

    # If the user gave --scanner-dir, try it first
    if args.scanner_dir:
        mod = _import_from(args.scanner_dir)
        if mod is None:
            messagebox.showerror(
                "Cannot start",
                f"--scanner-dir pointed to:\n  {args.scanner_dir}\n\n"
                "but p2_scanner.py could not be imported from there.",
                parent=root,
            )
            root.destroy()
            return 2
        _save_scanner_path(args.scanner_dir)
    else:
        mod = _locate_and_import_p2_scanner(root)
        if mod is None:
            root.destroy()
            return 2

    # Publish the located module at module-global scope so the rest of
    # p2_gui (MainWindow and helpers) can reach it through `p2.*`.
    global p2
    p2 = mod

    root.deiconify()
    MainWindow(root, args.config)
    root.mainloop()
    return 0


if __name__ == "__main__":
    sys.exit(main())
