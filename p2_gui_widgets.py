"""
p2_gui_widgets.py — Custom tkinter/ttk widgets for the P2 Scanner GUI.

Widgets:
  LogPane      — scrolling Text pane that drains a log queue and honors \\r
                 progress-line overwrites (like a terminal does).
  PointTable   — Treeview displaying point-read results with slot/units/
                 rendered value columns, comm-fault row highlighting.
  NodeTree     — hierarchical Treeview: Network → Nodes → Devices, with
                 online/offline indicators per device.
  ConfigDialog — modal editor for site.json fields + known_nodes grid.
  SinglePointDialog — small modal for "Read Point…" free-text entry.
"""

from __future__ import annotations

import datetime
import queue
import tkinter as tk
from tkinter import ttk
from typing import Callable, Dict, Iterable, List, Optional, Tuple


# ═══════════════════════════════════════════════════════════════════════════
# WINDOW PLACEMENT HELPER
# ═══════════════════════════════════════════════════════════════════════════

def _center_on_parent(
    win: tk.Toplevel,
    parent: tk.Misc,
    width: Optional[int] = None,
    height: Optional[int] = None,
) -> None:
    """Center `win` over its parent's top-level window, clamped to the
    visible screen. Call after the window's widgets are laid out (we do
    an update_idletasks internally) so natural sizes are reliable.

    width/height are optional; if omitted the window's current/requested
    size is used. Pass them when you've set an explicit geometry string
    (e.g. "880x480") so the size survives the subsequent geometry() call
    that sets the +x+y position.
    """
    win.update_idletasks()

    if width is None:
        w = win.winfo_width()
        if w <= 1:
            w = win.winfo_reqwidth()
        width = w
    if height is None:
        h = win.winfo_height()
        if h <= 1:
            h = win.winfo_reqheight()
        height = h

    try:
        top = parent.winfo_toplevel()
        px = top.winfo_rootx()
        py = top.winfo_rooty()
        pw = top.winfo_width()
        ph = top.winfo_height()
    except tk.TclError:
        # Parent gone / not yet mapped — fall back to screen-center
        px, py = 0, 0
        pw, ph = win.winfo_screenwidth(), win.winfo_screenheight()

    # If the parent isn't mapped yet (width 1, height 1), center on screen
    if pw <= 1 or ph <= 1:
        pw, ph = win.winfo_screenwidth(), win.winfo_screenheight()
        px, py = 0, 0

    x = px + (pw - width) // 2
    y = py + (ph - height) // 2

    # Clamp so the window is fully on-screen. Accept a small top margin
    # for the window chrome.
    sw = win.winfo_screenwidth()
    sh = win.winfo_screenheight()
    x = max(0, min(x, sw - width))
    y = max(0, min(y, sh - height))

    win.geometry(f"{width}x{height}+{x}+{y}")


# ═══════════════════════════════════════════════════════════════════════════
# LOG PANE
# ═══════════════════════════════════════════════════════════════════════════

class LogPane(ttk.Frame):
    """Scrolling log. Drains a queue of (term, line) tuples from the
    worker thread via a polled method called from the Tk event loop.

    A mark is kept at the start of the 'current' line so \\r progress
    updates can overwrite it without leaving trails in the buffer.
    """

    def __init__(self, parent: tk.Misc, log_queue: "queue.Queue[Tuple[str, str]]") -> None:
        super().__init__(parent)
        self._q = log_queue

        self._text = tk.Text(
            self,
            wrap="none",
            bg="#1b1b1b",
            fg="#d4d4d4",
            insertbackground="#d4d4d4",
            font=("Consolas", 9) if self._has_consolas() else ("Courier", 9),
            height=10,
            borderwidth=0,
        )
        sby = ttk.Scrollbar(self, orient="vertical", command=self._text.yview)
        sbx = ttk.Scrollbar(self, orient="horizontal", command=self._text.xview)
        self._text.configure(yscrollcommand=sby.set, xscrollcommand=sbx.set)

        clear_btn = ttk.Button(self, text="Clear", command=self.clear, width=8)

        self._text.grid(row=0, column=0, sticky="nsew")
        sby.grid(row=0, column=1, sticky="ns")
        sbx.grid(row=1, column=0, sticky="ew")
        clear_btn.grid(row=1, column=1, sticky="ew")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Tags for line-level coloring
        self._text.tag_configure("ts", foreground="#888")
        self._text.tag_configure("info", foreground="#d4d4d4")
        self._text.tag_configure("warn", foreground="#d1a33a")
        self._text.tag_configure("error", foreground="#e06c75")
        self._text.tag_configure("ok", foreground="#8fc974")

        self._text.mark_set("lineanchor", "1.0")
        self._text.mark_gravity("lineanchor", "left")
        self._last_was_cr = False
        self._text.configure(state="disabled")

    def _has_consolas(self) -> bool:
        try:
            import tkinter.font as tkfont
            return "Consolas" in tkfont.families()
        except Exception:
            return False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def poll(self) -> None:
        """Drain the queue into the widget. Call periodically from the UI loop."""
        appended = False
        drained = 0
        # Cap work per poll so a flood of output doesn't freeze the UI
        while drained < 500:
            try:
                term, line = self._q.get_nowait()
            except queue.Empty:
                break
            self._append_raw(term, line)
            appended = True
            drained += 1
        if appended:
            self._text.see("end")

    def log(self, message: str, level: str = "info") -> None:
        """Write a UI-originated message to the log with timestamp + tag."""
        ts = datetime.datetime.now().strftime("%H:%M:%S")
        self._text.configure(state="normal")
        try:
            # If we were mid-progress-line, finish it
            if self._last_was_cr:
                self._text.insert("end-1c", "\n")
                self._last_was_cr = False
            self._text.insert("end-1c", f"[{ts}] ", ("ts",))
            self._text.insert("end-1c", message + "\n", (level,))
            self._text.mark_set("lineanchor", "end-1c")
        finally:
            self._text.configure(state="disabled")
        self._text.see("end")

    def clear(self) -> None:
        self._text.configure(state="normal")
        self._text.delete("1.0", "end")
        self._text.mark_set("lineanchor", "1.0")
        self._text.configure(state="disabled")
        self._last_was_cr = False

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _append_raw(self, term: str, line: str) -> None:
        self._text.configure(state="normal")
        try:
            if self._last_was_cr:
                # Overwrite from the anchor forward
                self._text.delete("lineanchor", "end-1c")
            if line:
                self._text.insert("end-1c", line)
            if term == "\n":
                self._text.insert("end-1c", "\n")
                self._text.mark_set("lineanchor", "end-1c")
                self._last_was_cr = False
            elif term == "\r":
                self._last_was_cr = True
            else:
                # Empty terminator = buffer flush at end of run
                self._text.mark_set("lineanchor", "end-1c")
                self._last_was_cr = False
        finally:
            self._text.configure(state="disabled")


# ═══════════════════════════════════════════════════════════════════════════
# POINT RESULT TABLE
# ═══════════════════════════════════════════════════════════════════════════

PTYPE_LABEL = {
    "analog_ro": "AI",
    "analog_rw": "AO",
    "digital_ro": "BI",
    "digital_rw": "BO",
}


def _format_value_cell(result: Dict) -> str:
    """Render the Value column: digital gets 'LABEL (raw)', analog gets a float."""
    val_text = result.get("value_text") or ""
    raw = result.get("value")

    if val_text:
        # Digital: "NIGHT (1)" style
        if raw is not None:
            try:
                return f"{val_text} ({int(raw)})"
            except (TypeError, ValueError):
                return val_text
        return val_text

    if raw is None:
        return "—"
    try:
        f = float(raw)
    except (TypeError, ValueError):
        return str(raw)
    if abs(f - round(f)) < 0.01:
        return f"{f:.0f}"
    return f"{f:.2f}"


class PointTable(ttk.Frame):
    """Treeview of point results. Call load(results) to replace contents."""

    COLUMNS = (
        # (key, label, width, anchor)
        ("slot", "Slot", 55, "center"),
        ("name", "Point Name", 210, "w"),
        ("value", "Value", 140, "e"),
        ("units", "Units", 70, "center"),
        ("type", "Type", 55, "center"),
        ("status", "Status", 70, "center"),
    )

    def __init__(self, parent: tk.Misc) -> None:
        super().__init__(parent)
        keys = [c[0] for c in self.COLUMNS]
        self._tree = ttk.Treeview(self, columns=keys, show="headings")
        for key, label, width, anchor in self.COLUMNS:
            self._tree.heading(
                key, text=label, command=lambda k=key: self._sort_by(k)
            )
            self._tree.column(key, width=width, anchor=anchor, stretch=(key == "name"))

        sby = ttk.Scrollbar(self, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=sby.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        sby.grid(row=0, column=1, sticky="ns")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        self._tree.tag_configure(
            "comm_fault", background="#ffeee5", foreground="#8a2a00"
        )
        self._tree.tag_configure(
            "unknown", background="#f5f5f5", foreground="#888"
        )

        self._results: List[Dict] = []
        self._sort_key = "slot"
        self._sort_reverse = False

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def clear(self) -> None:
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        self._results = []

    def load(self, results: Iterable[Dict]) -> None:
        self._results = list(results)
        self._render()

    def results(self) -> List[Dict]:
        return list(self._results)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _sort_by(self, key: str) -> None:
        if key == self._sort_key:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_key = key
            self._sort_reverse = False
        self._render()

    def _render(self) -> None:
        for iid in self._tree.get_children():
            self._tree.delete(iid)

        def sort_tuple(r: Dict):
            k = self._sort_key
            if k == "slot":
                s = r.get("point_slot")
                return (s if s is not None else 10_000, r.get("point_name", ""))
            if k == "name":
                return (r.get("point_name", "").lower(),)
            if k == "value":
                v = r.get("value")
                return (float("inf") if v is None else v,)
            if k == "units":
                return (r.get("units") or "",)
            if k == "type":
                return (((r.get("point_info") or {}).get("type")) or "",)
            if k == "status":
                return (r.get("comm_status") or "~",)
            return (r.get("point_name", ""),)

        rows = sorted(self._results, key=sort_tuple, reverse=self._sort_reverse)

        for r in rows:
            slot = r.get("point_slot")
            slot_str = f"({slot})" if slot is not None else ""
            name = r.get("point_name", "?")
            value_str = _format_value_cell(r)
            units = r.get("units") or ""
            info = r.get("point_info") or {}
            type_str = PTYPE_LABEL.get(info.get("type", ""), info.get("type") or "?")

            comm = r.get("comm_status") or ""
            if comm == "online":
                status, tag = "✓ OK", ""
            elif comm == "comm_fault":
                status, tag = "✗ #COM", "comm_fault"
            else:
                status, tag = "—", "unknown"

            self._tree.insert(
                "",
                "end",
                values=(slot_str, name, value_str, units, type_str, status),
                tags=(tag,) if tag else (),
            )


# ═══════════════════════════════════════════════════════════════════════════
# NODE / DEVICE TREE
# ═══════════════════════════════════════════════════════════════════════════

class NodeTree(ttk.Frame):
    """Hierarchical tree: Network → Nodes → Devices.

    Selection callbacks receive the node or device payload dict.
    """

    def __init__(
        self,
        parent: tk.Misc,
        on_select_node: Optional[Callable[[Dict], None]] = None,
        on_select_device: Optional[Callable[[Dict], None]] = None,
    ) -> None:
        super().__init__(parent)
        self._tree = ttk.Treeview(self, show="tree", selectmode="browse")
        sby = ttk.Scrollbar(self, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=sby.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        sby.grid(row=0, column=1, sticky="ns")
        self.grid_rowconfigure(0, weight=1)
        self.grid_columnconfigure(0, weight=1)

        # Foreground color tags give the tree its online/offline legibility.
        # Kept muted enough not to overwhelm when there are 60+ rows visible.
        self._tree.tag_configure("status_online", foreground="#0a7a0a")
        self._tree.tag_configure("status_offline", foreground="#a82020")
        self._tree.tag_configure("status_unknown", foreground="#666666")
        # Amber for FLN comm-fault — distinct from a totally unreachable
        # device because the panel still has cached data and APPLICATION
        # is readable. Matches Desigo's #COM convention.
        self._tree.tag_configure("status_comm_fault", foreground="#a06010")
        # Node-level status tags. Same color palette as devices but
        # rendered in bold so the panel's own state stands out from the
        # devices hanging off it. A node can be online (PXC responding to
        # P2 handshakes) or offline (TCP refused / handshake failed) —
        # this lets the user spot a dead PXC even when it has zero FLN
        # devices, which the device-level Verify can't show.
        try:
            import tkinter.font as _tkfont
            _default = _tkfont.nametofont("TkDefaultFont")
            _bold = (_default.cget("family"), _default.cget("size"), "bold")
            self._tree.tag_configure(
                "node_online", foreground="#0a7a0a", font=_bold
            )
            self._tree.tag_configure(
                "node_offline", foreground="#a82020", font=_bold
            )
            self._tree.tag_configure(
                "node_unknown", foreground="#666666", font=_bold
            )
        except Exception:
            self._tree.tag_configure("node_online", foreground="#0a7a0a")
            self._tree.tag_configure("node_offline", foreground="#a82020")
            self._tree.tag_configure("node_unknown", foreground="#666666")
        try:
            import tkinter.font as tkfont
            default = tkfont.nametofont("TkDefaultFont")
            bold = (default.cget("family"), default.cget("size"), "bold")
            self._tree.tag_configure("network_root", font=bold)
        except Exception:
            pass

        self._on_select_node = on_select_node
        self._on_select_device = on_select_device
        self._tree.bind("<<TreeviewSelect>>", self._handle_select)

        # iid -> (kind, payload)
        self._data: Dict[str, Tuple[str, Dict]] = {}
        self._network_iid: Optional[str] = None
        self._node_iid_by_name: Dict[str, str] = {}

    # ------------------------------------------------------------------
    # Public API
    # ------------------------------------------------------------------

    def set_network(self, network_name: str) -> None:
        """Reset the tree and set (or refresh) the network root label."""
        self._tree.delete(*self._tree.get_children())
        self._data.clear()
        self._node_iid_by_name.clear()
        label = f"⌬  {network_name}" if network_name else "⌬  (no network configured)"
        self._network_iid = self._tree.insert(
            "", "end", text=label, open=True, tags=("network_root",)
        )

    def add_node(self, name: str, ip: str) -> str:
        if self._network_iid is None:
            self.set_network("")
        assert self._network_iid is not None
        # Initial status is "unknown" (gray ▸) — flips to online/offline
        # once any operation against the panel succeeds or fails. The
        # arrow marker `▸` is kept as the closed-folder hint; we prepend
        # a status dot when status becomes known.
        iid = self._tree.insert(
            self._network_iid,
            "end",
            text=f"▸  {name}   {ip}",
            open=False,
            tags=("node_unknown",),
        )
        self._data[iid] = (
            "node",
            {"name": name, "ip": ip, "status": "unknown"},
        )
        self._node_iid_by_name[name] = iid
        return iid

    def set_node_status(self, name: str, status: str) -> bool:
        """Update a node row's status indicator.

        status: 'online', 'offline', or 'unknown'.

        Online means the PXC accepted a TCP connection and completed a
        P2 handshake; offline means it refused, timed out, or rejected
        the handshake. This is independent of whether the node has any
        FLN devices — exactly the signal the device-level Verify can't
        provide for nodes that only host PPCL programs / global points.
        """
        iid = self._node_iid_by_name.get(name)
        if iid is None:
            return False
        entry = self._data.get(iid)
        if not (entry and entry[0] == "node"):
            return False
        ip = entry[1].get("ip", "")
        marker = {"online": "●", "offline": "○"}.get(status, "▸")
        tag = {
            "online": "node_online",
            "offline": "node_offline",
        }.get(status, "node_unknown")
        # Preserve the open/closed state — set_node_status can fire
        # mid-session and shouldn't snap a folder shut.
        was_open = bool(self._tree.item(iid, "open"))
        self._tree.item(
            iid,
            text=f"{marker}  {name}   {ip}",
            tags=(tag,),
            open=was_open,
        )
        entry[1]["status"] = status
        return True

    def clear_nodes(self) -> None:
        """Remove all nodes (and their devices), keep the network root."""
        if self._network_iid is None:
            return
        for child in list(self._tree.get_children(self._network_iid)):
            self._remove_subtree(child)

    def set_node_devices(self, node_name: str, devices: List[Dict]) -> None:
        node_iid = self._node_iid_by_name.get(node_name)
        if node_iid is None:
            return
        # Remove existing device children
        for child in list(self._tree.get_children(node_iid)):
            self._remove_subtree(child)

        payload_node = self._data[node_iid][1]

        for dev in devices:
            status = dev.get("status") or "unknown"
            comm = dev.get("comm_status")
            # Distinguish "FLN-faulted but APPLICATION-cached" (amber #COM)
            # from "totally unreachable" (red ○) and "live" (green ●).
            # Devices with comm_status='comm_fault' are always classified
            # offline by the scanner now, but we render them with the
            # amber tag and a #COM marker so the user can tell at a
            # glance which are wired-but-failing vs. genuinely missing.
            if comm == "comm_fault":
                marker = "◐"
                tag = "status_comm_fault"
            else:
                marker = {"online": "●", "offline": "○"}.get(status, "◌")
                tag = {
                    "online": "status_online",
                    "offline": "status_offline",
                }.get(status, "status_unknown")
            app = dev.get("application", 0) or 0
            app_cached = dev.get("application_cached", False)
            if app and app_cached:
                app_str = f"app {app} (cached)"
            elif app:
                app_str = f"app {app}"
            elif comm == "comm_fault":
                app_str = "#COM"
            else:
                app_str = ""
            dev_name = dev["device"]
            label = f"  {marker}  {dev_name:<18s} {app_str}"
            iid = self._tree.insert(node_iid, "end", text=label, tags=(tag,))
            self._data[iid] = (
                "device",
                {
                    "node": payload_node["name"],
                    "host": payload_node["ip"],
                    "device": dev_name,
                    "application": app,
                    "application_cached": app_cached,
                    "status": status,
                    "comm_status": comm,
                    "description": dev.get("description", ""),
                    "room_temp": dev.get("room_temp"),
                    "stale_temp": dev.get("stale_temp"),
                    "units": dev.get("units", ""),
                },
            )
        self._tree.item(node_iid, open=True)

    def update_device_status(
        self, node_name: str, device_name: str, updated: Dict
    ) -> bool:
        """Update a single device row in place — for live-verify progress
        where we want the row to flip color as each device is checked
        instead of waiting for the whole batch. Returns True if the row
        was found and updated, False otherwise."""
        node_iid = self._node_iid_by_name.get(node_name)
        if node_iid is None:
            return False
        for child in self._tree.get_children(node_iid):
            entry = self._data.get(child)
            if not (entry and entry[0] == "device"):
                continue
            if entry[1].get("device") != device_name:
                continue

            status = updated.get("status") or entry[1].get("status", "unknown")
            comm = updated.get("comm_status", entry[1].get("comm_status"))
            app = updated.get("application", entry[1].get("application", 0)) or 0
            app_cached = updated.get(
                "application_cached", entry[1].get("application_cached", False)
            )
            if comm == "comm_fault":
                marker = "◐"
                tag = "status_comm_fault"
            else:
                marker = {"online": "●", "offline": "○"}.get(status, "◌")
                tag = {
                    "online": "status_online",
                    "offline": "status_offline",
                }.get(status, "status_unknown")
            if app and app_cached:
                app_str = f"app {app} (cached)"
            elif app:
                app_str = f"app {app}"
            elif comm == "comm_fault":
                app_str = "#COM"
            else:
                app_str = ""
            label = f"  {marker}  {device_name:<18s} {app_str}"
            self._tree.item(child, text=label, tags=(tag,))

            # Merge the update into our stored payload so the detail panel
            # picks up fresh data on next selection.
            entry[1]["status"] = status
            entry[1]["application"] = app
            if comm is not None:
                entry[1]["comm_status"] = comm
            if app_cached:
                entry[1]["application_cached"] = app_cached
            if "room_temp" in updated:
                entry[1]["room_temp"] = updated["room_temp"]
            if "stale_temp" in updated:
                entry[1]["stale_temp"] = updated["stale_temp"]
            if "units" in updated:
                entry[1]["units"] = updated["units"]
            return True
        return False

    def selected(self) -> Optional[Tuple[str, Dict]]:
        sel = self._tree.selection()
        if not sel:
            return None
        return self._data.get(sel[0])

    def selected_node_payload(self) -> Optional[Dict]:
        """Return the node dict, whether a node OR one of its devices is selected."""
        sel = self._tree.selection()
        if not sel:
            return None
        iid = sel[0]
        entry = self._data.get(iid)
        if entry and entry[0] == "node":
            return entry[1]
        if entry and entry[0] == "device":
            parent = self._tree.parent(iid)
            parent_entry = self._data.get(parent)
            if parent_entry and parent_entry[0] == "node":
                return parent_entry[1]
        return None

    def node_payload(self, name: str) -> Optional[Dict]:
        """Return the stored payload for a node by name.

        Useful when the caller has a node name and wants the latest
        copy of its payload — including any status updates pushed via
        set_node_status — without going through the selection machinery.
        """
        iid = self._node_iid_by_name.get(name)
        if iid is None:
            return None
        entry = self._data.get(iid)
        if not (entry and entry[0] == "node"):
            return None
        return entry[1]

    def select_node(self, name: str) -> None:
        iid = self._node_iid_by_name.get(name)
        if iid:
            self._tree.selection_set(iid)
            self._tree.focus(iid)
            self._tree.see(iid)

    # ------------------------------------------------------------------
    # Internal
    # ------------------------------------------------------------------

    def _remove_subtree(self, iid: str) -> None:
        for child in list(self._tree.get_children(iid)):
            self._remove_subtree(child)
        self._data.pop(iid, None)
        # Also drop from node name index if this was a node
        for nm, niid in list(self._node_iid_by_name.items()):
            if niid == iid:
                del self._node_iid_by_name[nm]
                break
        self._tree.delete(iid)

    def _handle_select(self, _event=None) -> None:
        s = self.selected()
        if not s:
            return
        kind, payload = s
        if kind == "node" and self._on_select_node:
            self._on_select_node(payload)
        elif kind == "device" and self._on_select_device:
            self._on_select_device(payload)


# ═══════════════════════════════════════════════════════════════════════════
# CONFIG / SINGLE-POINT DIALOGS
# ═══════════════════════════════════════════════════════════════════════════

class _NodeEditDialog(tk.Toplevel):
    """Small name+IP dialog used by ConfigDialog."""

    def __init__(self, parent: tk.Misc, title: str, name: str, ip: str) -> None:
        super().__init__(parent)
        self.title(title)
        self.transient(parent)
        self.resizable(False, False)

        body = ttk.Frame(self, padding=12)
        body.pack()

        ttk.Label(body, text="Node Name:").grid(row=0, column=0, sticky="w", pady=2)
        self._name_var = tk.StringVar(value=name)
        e1 = ttk.Entry(body, textvariable=self._name_var, width=22)
        e1.grid(row=0, column=1, sticky="ew", pady=2)

        ttk.Label(body, text="IP Address:").grid(row=1, column=0, sticky="w", pady=2)
        self._ip_var = tk.StringVar(value=ip)
        ttk.Entry(body, textvariable=self._ip_var, width=22).grid(
            row=1, column=1, sticky="ew", pady=2
        )

        self.result: Optional[Tuple[str, str]] = None

        btns = ttk.Frame(body)
        btns.grid(row=2, column=0, columnspan=2, pady=(10, 0), sticky="e")
        ttk.Button(btns, text="Cancel", command=self._cancel).pack(
            side="right", padx=2
        )
        ttk.Button(btns, text="OK", command=self._ok).pack(side="right", padx=2)

        self.bind("<Return>", lambda _e: self._ok())
        self.bind("<Escape>", lambda _e: self._cancel())

        e1.focus_set()
        _center_on_parent(self, parent)
        self.grab_set()

    def _ok(self) -> None:
        n = self._name_var.get().strip()
        i = self._ip_var.get().strip()
        if not n or not i:
            return
        self.result = (n, i)
        self.destroy()

    def _cancel(self) -> None:
        self.result = None
        self.destroy()

    @classmethod
    def ask(
        cls, parent: tk.Misc, title: str, name: str = "", ip: str = ""
    ) -> Optional[Tuple[str, str]]:
        dlg = cls(parent, title, name, ip)
        dlg.wait_window()
        return dlg.result


class ConfigDialog(tk.Toplevel):
    """Modal editor for site.json content."""

    def __init__(self, parent: tk.Misc, config: Dict) -> None:
        super().__init__(parent)
        self.title("Site Configuration")
        self.transient(parent)
        self.resizable(False, True)

        self._cfg: Dict = {
            "p2_network": config.get("p2_network", ""),
            "p2_site": config.get("p2_site", ""),
            "scanner_name": config.get("scanner_name", "P2SCAN|5034"),
            "known_nodes": dict(config.get("known_nodes", {})),
        }
        # Preserve any unknown keys so save-round-trip doesn't drop them
        self._extras: Dict = {
            k: v
            for k, v in config.items()
            if k not in ("p2_network", "p2_site", "scanner_name", "known_nodes")
        }
        self.result: Optional[Dict] = None

        body = ttk.Frame(self, padding=12)
        body.pack(fill="both", expand=True)

        # --- P2 identity fields ---
        ttk.Label(body, text="BLN Network Name:").grid(row=0, column=0, sticky="w", pady=2)
        self._net_var = tk.StringVar(value=self._cfg["p2_network"])
        ttk.Entry(body, textvariable=self._net_var, width=34).grid(
            row=0, column=1, sticky="ew", pady=2
        )

        ttk.Label(body, text="Site Name:").grid(row=1, column=0, sticky="w", pady=2)
        self._site_var = tk.StringVar(value=self._cfg["p2_site"])
        ttk.Entry(body, textvariable=self._site_var, width=34).grid(
            row=1, column=1, sticky="ew", pady=2
        )

        ttk.Label(body, text="Scanner Name:").grid(row=2, column=0, sticky="w", pady=2)
        self._scanner_var = tk.StringVar(value=self._cfg["scanner_name"])
        ttk.Entry(body, textvariable=self._scanner_var, width=34).grid(
            row=2, column=1, sticky="ew", pady=2
        )

        hint = ttk.Label(
            body,
            text=(
                "Scanner format tip: sites sometimes require <SITE>DCC-SVR|5034 "
                "(the Desigo CC server identity) instead of the generic default."
            ),
            foreground="#777",
            wraplength=460,
            justify="left",
        )
        hint.grid(row=3, column=0, columnspan=2, sticky="w", pady=(2, 8))

        # --- Known nodes ---
        ttk.Label(body, text="Known Nodes:", font=("", 10, "bold")).grid(
            row=4, column=0, columnspan=2, sticky="w", pady=(4, 4)
        )

        nodes_frame = ttk.Frame(body)
        nodes_frame.grid(row=5, column=0, columnspan=2, sticky="nsew")
        body.rowconfigure(5, weight=1)
        body.columnconfigure(1, weight=1)

        self._nodes_tree = ttk.Treeview(
            nodes_frame,
            columns=("name", "ip"),
            show="headings",
            height=9,
            selectmode="browse",
        )
        self._nodes_tree.heading("name", text="Node Name")
        self._nodes_tree.heading("ip", text="IP Address")
        self._nodes_tree.column("name", width=160)
        self._nodes_tree.column("ip", width=160)
        self._nodes_tree.grid(row=0, column=0, sticky="nsew")
        nsb = ttk.Scrollbar(nodes_frame, orient="vertical", command=self._nodes_tree.yview)
        self._nodes_tree.configure(yscrollcommand=nsb.set)
        nsb.grid(row=0, column=1, sticky="ns")
        nodes_frame.rowconfigure(0, weight=1)
        nodes_frame.columnconfigure(0, weight=1)
        self._nodes_tree.bind("<Double-1>", lambda _e: self._edit_node())

        self._refresh_nodes()

        node_btns = ttk.Frame(body)
        node_btns.grid(row=6, column=0, columnspan=2, sticky="ew", pady=(4, 0))
        ttk.Button(node_btns, text="Add…", command=self._add_node).pack(side="left", padx=2)
        ttk.Button(node_btns, text="Edit…", command=self._edit_node).pack(side="left", padx=2)
        ttk.Button(node_btns, text="Remove", command=self._remove_node).pack(
            side="left", padx=2
        )

        # --- OK / Cancel ---
        btns = ttk.Frame(body)
        btns.grid(row=7, column=0, columnspan=2, sticky="e", pady=(14, 0))
        ttk.Button(btns, text="Cancel", command=self._cancel).pack(side="right", padx=4)
        ttk.Button(btns, text="OK", command=self._ok).pack(side="right", padx=4)

        self.bind("<Escape>", lambda _e: self._cancel())
        _center_on_parent(self, parent)
        self.grab_set()

    # ------------------------------------------------------------------

    def _refresh_nodes(self) -> None:
        for iid in self._nodes_tree.get_children():
            self._nodes_tree.delete(iid)
        for name, ip in sorted(self._cfg["known_nodes"].items()):
            self._nodes_tree.insert("", "end", iid=name, values=(name, ip))

    def _add_node(self) -> None:
        r = _NodeEditDialog.ask(self, "Add Node")
        if r:
            name, ip = r
            self._cfg["known_nodes"][name] = ip
            self._refresh_nodes()

    def _edit_node(self) -> None:
        sel = self._nodes_tree.selection()
        if not sel:
            return
        old_name = sel[0]
        old_ip = self._cfg["known_nodes"].get(old_name, "")
        r = _NodeEditDialog.ask(self, "Edit Node", old_name, old_ip)
        if r:
            name, ip = r
            if name != old_name:
                self._cfg["known_nodes"].pop(old_name, None)
            self._cfg["known_nodes"][name] = ip
            self._refresh_nodes()

    def _remove_node(self) -> None:
        sel = self._nodes_tree.selection()
        if not sel:
            return
        self._cfg["known_nodes"].pop(sel[0], None)
        self._refresh_nodes()

    def _ok(self) -> None:
        self._cfg["p2_network"] = self._net_var.get().strip()
        self._cfg["p2_site"] = self._site_var.get().strip()
        self._cfg["scanner_name"] = (
            self._scanner_var.get().strip() or "P2SCAN|5034"
        )
        merged = dict(self._extras)
        merged.update(self._cfg)
        self.result = merged
        self.destroy()

    def _cancel(self) -> None:
        self.result = None
        self.destroy()

    @classmethod
    def ask(cls, parent: tk.Misc, config: Dict) -> Optional[Dict]:
        dlg = cls(parent, config)
        dlg.wait_window()
        return dlg.result


class SinglePointDialog(tk.Toplevel):
    """Prompt for a point name OR slot number, plus the force-slot option."""

    def __init__(
        self,
        parent: tk.Misc,
        device_name: str,
        application: Optional[int] = None,
    ) -> None:
        super().__init__(parent)
        self.title(f"Read Point — {device_name}")
        self.transient(parent)
        self.resizable(False, False)

        body = ttk.Frame(self, padding=12)
        body.pack()

        ttk.Label(
            body, text="Point name or slot number:", font=("", 10)
        ).grid(row=0, column=0, sticky="w")
        self._entry = ttk.Entry(body, width=30)
        self._entry.grid(row=1, column=0, sticky="ew", pady=(2, 4))

        hint_text = 'Examples:  "ROOM TEMP"  ·  "HEAT.COOL"  ·  29'
        if application:
            hint_text = f"App {application}   |   " + hint_text
        ttk.Label(body, text=hint_text, foreground="#777").grid(
            row=2, column=0, sticky="w"
        )

        self._force_var = tk.BooleanVar()
        ttk.Checkbutton(
            body,
            text="Force read of undefined slot (troubleshooting)",
            variable=self._force_var,
        ).grid(row=3, column=0, sticky="w", pady=(8, 0))

        self.result: Optional[Tuple[str, bool]] = None

        btns = ttk.Frame(body)
        btns.grid(row=4, column=0, pady=(12, 0), sticky="e")
        ttk.Button(btns, text="Cancel", command=self._cancel).pack(
            side="right", padx=2
        )
        ttk.Button(btns, text="Read", command=self._ok).pack(side="right", padx=2)

        self.bind("<Return>", lambda _e: self._ok())
        self.bind("<Escape>", lambda _e: self._cancel())

        self._entry.focus_set()
        _center_on_parent(self, parent)
        self.grab_set()

    def _ok(self) -> None:
        val = self._entry.get().strip()
        if not val:
            return
        self.result = (val, self._force_var.get())
        self.destroy()

    def _cancel(self) -> None:
        self.result = None
        self.destroy()

    @classmethod
    def ask(
        cls,
        parent: tk.Misc,
        device_name: str,
        application: Optional[int] = None,
    ) -> Optional[Tuple[str, bool]]:
        dlg = cls(parent, device_name, application)
        dlg.wait_window()
        return dlg.result


# ═══════════════════════════════════════════════════════════════════════════
# SWEEP DIALOG + RESULTS WINDOW
# ═══════════════════════════════════════════════════════════════════════════

# Common points catalog for the Sweep dialog's "Add common point" menu.
# Slots shown are the STANDARD VAV (2020-2027) slot assignments. For other
# application families (fume hoods, unit ventilators, etc.) the same point
# names may live at different slot numbers, which is why the dialog inserts
# names rather than slot numbers — names are universal, slots are not.
#
# Each entry: (category, slot, name, description)
# Category order is preserved as the menu group order.
COMMON_POINTS_CATALOG: List[Tuple[str, int, str, str]] = [
    # Temperature & sensors
    ("Temperature",  3,  "CTL TEMP",      "Control temperature"),
    ("Temperature",  4,  "ROOM TEMP",     "Room temperature sensor reading"),
    ("Temperature",  15, "AUX TEMP",      "Auxiliary temperature sensor (reheat apps)"),
    ("Temperature",  15, "SUPPLY TEMP",   "Supply air temperature (app 2021)"),
    # Setpoints — day/night, heating/cooling
    ("Setpoints",    6,  "DAY CLG STPT",  "Day cooling setpoint"),
    ("Setpoints",    7,  "DAY HTG STPT",  "Day heating setpoint"),
    ("Setpoints",    8,  "NGT CLG STPT",  "Night cooling setpoint"),
    ("Setpoints",    9,  "NGT HTG STPT",  "Night heating setpoint"),
    ("Setpoints",    11, "RM STPT MIN",   "Room setpoint dial minimum"),
    ("Setpoints",    12, "RM STPT MAX",   "Room setpoint dial maximum"),
    ("Setpoints",    13, "RM STPT DIAL",  "Room setpoint dial reading"),
    ("Setpoints",    35, "CTL STPT",      "Active control setpoint"),
    # Mode / occupancy
    ("Mode",         5,  "HEAT.COOL",     "Heating or cooling mode"),
    ("Mode",         29, "DAY.NGT",       "Day or night occupancy"),
    ("Mode",         21, "NGT OVRD",      "Night override active"),
    ("Mode",         20, "OVRD TIME",     "Override duration (hours)"),
    # Airflow & damper
    ("Airflow",      39, "FLOW",          "Actual airflow percentage"),
    ("Airflow",      40, "AIR VOLUME",    "Air volume (CFM)"),
    ("Airflow",      41, "DMPR POS",      "Damper position"),
    ("Airflow",      42, "DMPR COMD",     "Damper command"),
    ("Airflow",      38, "FLOW STPT",     "Flow setpoint"),
    # Hot water valves (reheat)
    ("Valves",       64, "VLV1 POS",      "Valve 1 position"),
    ("Valves",       65, "VLV1 COMD",     "Valve 1 command"),
    ("Valves",       66, "VLV2 POS",      "Valve 2 position"),
    ("Valves",       67, "VLV2 COMD",     "Valve 2 command"),
    # Controller outputs
    ("Outputs",      47, "CLG LOOPOUT",   "Cooling loop output"),
    ("Outputs",      56, "HTG LOOPOUT",   "Heating loop output"),
    # Status / inputs
    ("Status",       18, "WALL SWITCH",   "Wall switch monitoring enabled"),
    ("Status",       19, "DI OVRD SW",    "Override switch status"),
    ("Status",       91, "ERROR STATUS",  "Error status bitmap"),
    # Meta
    ("Meta",         2,  "APPLICATION",   "Application number"),
]


class SweepDialog(tk.Toplevel):
    """Configure a building-wide point sweep:

      * which points to read (names and/or slot numbers, one per line)
      * which scope of devices to include (all enumerated, or online only)
      * which nodes to include (checkbox list)

    On OK, `self.result` is a dict:
        {
            'points':  [str, ...],       # point names / numeric strings
            'scope':   'all' | 'online',
            'nodes':   {node_name, ...}, # set of included node names
        }
    or None if cancelled.
    """

    def __init__(
        self,
        parent: tk.Misc,
        available_nodes: List[Dict],
        device_counts: Dict[str, Tuple[int, int]],
    ) -> None:
        """
        available_nodes : [{'name': str, 'ip': str}, ...]
        device_counts   : node_name -> (total_devices, online_devices)
                          Used to show "NODE1 (12 devices, 10 online)" labels.
        """
        super().__init__(parent)
        self.title("Sweep Points Across Devices")
        self.transient(parent)
        self.resizable(False, True)

        self.result: Optional[Dict] = None

        body = ttk.Frame(self, padding=12)
        body.pack(fill="both", expand=True)

        # --- Points entry ---
        ttk.Label(body, text="Points to read:", font=("", 10, "bold")).grid(
            row=0, column=0, columnspan=2, sticky="w"
        )
        ttk.Label(
            body,
            text="One per line — point name or slot number. Examples: "
            "ROOM TEMP, CTL STPT, HEAT.COOL, 4",
            foreground="#777",
            wraplength=500,
            justify="left",
        ).grid(row=1, column=0, columnspan=2, sticky="w", pady=(0, 2))

        # Menubutton + Clear, above the text area
        ctrl_row = ttk.Frame(body)
        ctrl_row.grid(row=2, column=0, columnspan=2, sticky="ew", pady=(0, 2))
        self._common_btn = ttk.Menubutton(
            ctrl_row, text="Add common point ▾", direction="below"
        )
        self._common_btn.pack(side="left")
        self._build_common_points_menu(self._common_btn)
        ttk.Button(
            ctrl_row, text="Clear",
            command=lambda: self._points_text.delete("1.0", "end"),
        ).pack(side="left", padx=(6, 0))
        ttk.Label(
            ctrl_row,
            text="  (slot numbers shown are standard-VAV defaults; names work across all apps)",
            foreground="#999",
        ).pack(side="left")

        text_frame = ttk.Frame(body)
        text_frame.grid(row=3, column=0, columnspan=2, sticky="ew", pady=(0, 8))
        self._points_text = tk.Text(
            text_frame, height=5, width=52, wrap="none", undo=True
        )
        self._points_text.insert("1.0", "ROOM TEMP")
        self._points_text.grid(row=0, column=0, sticky="nsew")
        sb = ttk.Scrollbar(text_frame, orient="vertical", command=self._points_text.yview)
        self._points_text.configure(yscrollcommand=sb.set)
        sb.grid(row=0, column=1, sticky="ns")
        text_frame.columnconfigure(0, weight=1)

        # --- Scope radio ---
        ttk.Label(body, text="Devices to include:", font=("", 10, "bold")).grid(
            row=4, column=0, columnspan=2, sticky="w", pady=(4, 2)
        )
        self._scope_var = tk.StringVar(value="all")
        ttk.Radiobutton(
            body,
            text="All enumerated devices (including offline/unknown)",
            variable=self._scope_var,
            value="all",
        ).grid(row=5, column=0, columnspan=2, sticky="w")
        ttk.Radiobutton(
            body,
            text="Only devices verified online",
            variable=self._scope_var,
            value="online",
        ).grid(row=6, column=0, columnspan=2, sticky="w")

        # --- Nodes multi-select ---
        ttk.Label(body, text="Nodes to include:", font=("", 10, "bold")).grid(
            row=7, column=0, columnspan=2, sticky="w", pady=(8, 2)
        )

        nodes_container = ttk.Frame(body)
        nodes_container.grid(row=8, column=0, columnspan=2, sticky="nsew")
        body.rowconfigure(8, weight=1)

        # Use a Canvas + inner Frame for a scrollable checkbox list
        canvas = tk.Canvas(
            nodes_container, highlightthickness=0, height=140, background="#ffffff"
        )
        nsb = ttk.Scrollbar(nodes_container, orient="vertical", command=canvas.yview)
        inner = ttk.Frame(canvas)
        canvas.configure(yscrollcommand=nsb.set)
        canvas.create_window((0, 0), window=inner, anchor="nw")
        inner.bind(
            "<Configure>",
            lambda _e: canvas.configure(scrollregion=canvas.bbox("all")),
        )
        canvas.grid(row=0, column=0, sticky="nsew")
        nsb.grid(row=0, column=1, sticky="ns")
        nodes_container.rowconfigure(0, weight=1)
        nodes_container.columnconfigure(0, weight=1)

        self._node_vars: Dict[str, tk.BooleanVar] = {}
        for n in available_nodes:
            name = n["name"]
            ip = n["ip"]
            total, online = device_counts.get(name, (0, 0))
            label = f"{name}   ({ip})"
            if total:
                label += f"   — {total} device{'s' if total != 1 else ''}"
                if online:
                    label += f", {online} online"
            var = tk.BooleanVar(value=(total > 0))  # default: only nodes we've enumerated
            self._node_vars[name] = var
            ttk.Checkbutton(
                inner,
                text=label,
                variable=var,
            ).pack(anchor="w", padx=8, pady=1)

        if not available_nodes:
            ttk.Label(
                inner,
                text="(no nodes — configure your site first)",
                foreground="#999",
            ).pack(anchor="w", padx=8, pady=4)

        # Quick "select/deselect all" row
        sel_row = ttk.Frame(body)
        sel_row.grid(row=9, column=0, columnspan=2, sticky="w", pady=(4, 0))
        ttk.Button(
            sel_row, text="All", width=6, command=lambda: self._select_all(True)
        ).pack(side="left", padx=2)
        ttk.Button(
            sel_row, text="None", width=6, command=lambda: self._select_all(False)
        ).pack(side="left", padx=2)

        # --- OK / Cancel ---
        btns = ttk.Frame(body)
        btns.grid(row=10, column=0, columnspan=2, sticky="e", pady=(14, 0))
        ttk.Button(btns, text="Cancel", command=self._cancel).pack(side="right", padx=4)
        ttk.Button(btns, text="Start Sweep", command=self._ok).pack(side="right", padx=4)

        self.bind("<Escape>", lambda _e: self._cancel())

        self._points_text.focus_set()
        _center_on_parent(self, parent)
        self.grab_set()

    def _select_all(self, state: bool) -> None:
        for v in self._node_vars.values():
            v.set(state)

    def _build_common_points_menu(self, parent_btn: ttk.Menubutton) -> None:
        """Construct the categorized 'Add common point' dropdown menu."""
        menu = tk.Menu(parent_btn, tearoff=0)
        # Group the catalog by category, preserving first-appearance order
        categories: List[str] = []
        by_cat: Dict[str, List[Tuple[int, str, str]]] = {}
        for cat, slot, name, desc in COMMON_POINTS_CATALOG:
            if cat not in by_cat:
                categories.append(cat)
                by_cat[cat] = []
            by_cat[cat].append((slot, name, desc))

        for cat in categories:
            sub = tk.Menu(menu, tearoff=0)
            for slot, name, desc in by_cat[cat]:
                # Label format: "(4) ROOM TEMP  — Room temperature sensor reading"
                label = f"({slot}) {name}   —   {desc}"
                sub.add_command(
                    label=label,
                    command=lambda n=name: self._append_point(n),
                )
            menu.add_cascade(label=cat, menu=sub)

        # Quick path: entire QUICK_SCAN_POINTS list as one click
        menu.add_separator()
        menu.add_command(
            label="Insert all 'quick' operational points",
            command=self._insert_quick_scan_set,
        )
        parent_btn["menu"] = menu

    def _append_point(self, name: str) -> None:
        """Append a point name to the textbox, one per line.
        Empty box → just the name; otherwise newline + name.
        Skips duplicates."""
        existing = [
            line.strip()
            for line in self._points_text.get("1.0", "end").splitlines()
            if line.strip()
        ]
        if name in existing:
            return  # already in the list; no-op
        if existing:
            self._points_text.insert("end-1c", "\n" + name)
        else:
            self._points_text.delete("1.0", "end")
            self._points_text.insert("1.0", name)
        # Ensure the cursor is visible at the end
        self._points_text.see("end")

    def _insert_quick_scan_set(self) -> None:
        """Replace textbox with the full QUICK_SCAN_POINTS list."""
        # We import lazily so widgets.py stays decoupled from p2_scanner
        try:
            import p2_scanner as _p2  # type: ignore
            quick = list(getattr(_p2, "QUICK_SCAN_POINTS", []))
        except Exception:
            quick = []
        if not quick:
            return
        self._points_text.delete("1.0", "end")
        self._points_text.insert("1.0", "\n".join(quick))

    def _ok(self) -> None:
        raw = self._points_text.get("1.0", "end").strip()
        # Split on newlines OR commas OR semicolons; allow extra whitespace
        lines = [
            line.strip()
            for raw_line in raw.splitlines()
            for line in raw_line.replace(";", ",").split(",")
        ]
        points = [p for p in lines if p]
        if not points:
            return  # Silently refuse - user hasn't entered anything

        selected_nodes = {
            name for name, var in self._node_vars.items() if var.get()
        }
        if not selected_nodes:
            return  # Must pick at least one node

        self.result = {
            "points": points,
            "scope": self._scope_var.get(),
            "nodes": selected_nodes,
        }
        self.destroy()

    def _cancel(self) -> None:
        self.result = None
        self.destroy()

    @classmethod
    def ask(
        cls,
        parent: tk.Misc,
        available_nodes: List[Dict],
        device_counts: Dict[str, Tuple[int, int]],
    ) -> Optional[Dict]:
        dlg = cls(parent, available_nodes, device_counts)
        dlg.wait_window()
        return dlg.result


class SweepResultsWindow(tk.Toplevel):
    """Non-modal results window for a building-wide sweep.

    Results are a flat list of dicts; each row corresponds to one
    (node, device, point) tuple, or an error entry for a device that
    couldn't be read at all. Sortable, filterable, exportable.
    """

    COLUMNS = (
        # (key, label, width, anchor)
        ("node", "Node", 90, "w"),
        ("device", "Device", 120, "w"),
        ("description", "Description", 160, "w"),
        ("slot", "Slot", 55, "center"),
        ("point", "Point", 160, "w"),
        ("value", "Value", 120, "e"),
        ("units", "Units", 65, "center"),
        ("status", "Status", 75, "center"),
    )

    def __init__(
        self,
        parent: tk.Misc,
        points: List[str],
        results: List[Dict],
        on_jump_to_device: Optional[callable] = None,
        on_resweep: Optional[callable] = None,
        on_export_csv: Optional[callable] = None,
        on_export_json: Optional[callable] = None,
    ) -> None:
        super().__init__(parent)
        self.title(f"Sweep Results — {', '.join(points)}")
        # Size set via _center_on_parent so position+size land together
        self._parent = parent

        self._results = list(results)
        self._points = list(points)
        self._on_jump_to_device = on_jump_to_device

        # --- Header ---
        header = ttk.Frame(self, padding=(12, 10))
        header.pack(fill="x")
        n_results = len(results)
        n_devices = len({(r.get("_node") or r.get("node"),
                          r.get("_device") or r.get("device")) for r in results})
        n_errors = sum(1 for r in results if "error" in r)
        n_commfault = sum(
            1 for r in results if r.get("comm_status") == "comm_fault"
        )
        import datetime
        ts = datetime.datetime.now().strftime("%Y-%m-%d %H:%M:%S")
        ttk.Label(
            header,
            text=f"Points: {', '.join(points)}",
            font=("", 11, "bold"),
        ).pack(anchor="w")
        summary = (
            f"{n_devices} device{'s' if n_devices != 1 else ''} swept  ·  "
            f"{n_results - n_errors} successful read{'s' if (n_results - n_errors) != 1 else ''}  ·  "
            f"{n_commfault} comm-fault  ·  "
            f"{n_errors} unreachable  ·  {ts}"
        )
        ttk.Label(header, text=summary, foreground="#555").pack(anchor="w", pady=(2, 0))

        # --- Toolbar ---
        toolbar = ttk.Frame(self, padding=(12, 0, 12, 6))
        toolbar.pack(fill="x")
        if on_resweep:
            ttk.Button(toolbar, text="Re-sweep", command=on_resweep).pack(side="left", padx=2)
        if on_export_csv:
            ttk.Button(
                toolbar, text="Export CSV…",
                command=lambda: on_export_csv(self._results, self._points),
            ).pack(side="left", padx=2)
        if on_export_json:
            ttk.Button(
                toolbar, text="Export JSON…",
                command=lambda: on_export_json(self._results, self._points),
            ).pack(side="left", padx=2)

        # Quick filter
        ttk.Separator(toolbar, orient="vertical").pack(side="left", fill="y", padx=10)
        ttk.Label(toolbar, text="Filter:").pack(side="left", padx=(0, 4))
        # master=self so the StringVar (and its trace callback) get cleaned
        # up when the window is destroyed — without it, repeatedly opening
        # and closing this window leaks one trace + one closure-over-self
        # per session.
        self._filter_var = tk.StringVar(master=self)
        self._filter_var.trace_add("write", lambda *a: self._render())
        ttk.Entry(toolbar, textvariable=self._filter_var, width=24).pack(side="left")

        self._hide_errors_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            toolbar,
            text="Hide unreachable",
            variable=self._hide_errors_var,
            command=self._render,
        ).pack(side="left", padx=(12, 0))

        # --- Table ---
        table_frame = ttk.Frame(self, padding=(12, 0, 12, 10))
        table_frame.pack(fill="both", expand=True)

        keys = [c[0] for c in self.COLUMNS]
        self._tree = ttk.Treeview(
            table_frame, columns=keys, show="headings", selectmode="browse"
        )
        for key, label, width, anchor in self.COLUMNS:
            self._tree.heading(
                key, text=label, command=lambda k=key: self._sort_by(k)
            )
            self._tree.column(
                key, width=width, anchor=anchor,
                stretch=(key in ("device", "description", "point")),
            )

        sby = ttk.Scrollbar(table_frame, orient="vertical", command=self._tree.yview)
        sbx = ttk.Scrollbar(table_frame, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=sby.set, xscrollcommand=sbx.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        sby.grid(row=0, column=1, sticky="ns")
        sbx.grid(row=1, column=0, sticky="ew")
        table_frame.rowconfigure(0, weight=1)
        table_frame.columnconfigure(0, weight=1)

        self._tree.tag_configure(
            "comm_fault", background="#ffeee5", foreground="#8a2a00"
        )
        self._tree.tag_configure(
            "error", background="#f0f0f0", foreground="#888"
        )
        self._tree.tag_configure(
            "node_break", background="#fafafa"
        )

        # Double-click → jump to device in main tree
        self._tree.bind("<Double-1>", self._on_double_click)

        # iid -> original result dict, for lookups on double-click
        self._iid_to_result: Dict[str, Dict] = {}

        self._sort_key = "node"
        self._sort_reverse = False
        self._render()

        _center_on_parent(self, self._parent, width=1000, height=560)

    # ------------------------------------------------------------------

    def _sort_by(self, key: str) -> None:
        if key == self._sort_key:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_key = key
            self._sort_reverse = False
        self._render()

    def _render(self) -> None:
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        self._iid_to_result.clear()

        filter_text = self._filter_var.get().strip().lower()
        hide_errors = self._hide_errors_var.get()

        def get_sortable(r: Dict, key: str):
            if key == "node":
                return (r.get("_node") or r.get("node") or "", )
            if key == "device":
                return (r.get("_device") or r.get("device") or "", )
            if key == "description":
                return (r.get("_description") or r.get("description") or "", )
            if key == "slot":
                s = r.get("point_slot")
                return (s if s is not None else 10_000, )
            if key == "point":
                return (r.get("point_name") or r.get("error") or "", )
            if key == "value":
                v = r.get("value")
                if v is None:
                    return (float("inf"), )
                try:
                    return (float(v), )
                except (TypeError, ValueError):
                    return (float("inf"), )
            if key == "units":
                return (r.get("units") or "", )
            if key == "status":
                return (r.get("comm_status") or ("error" if "error" in r else ""), )
            return ("", )

        rows = sorted(self._results, key=lambda r: get_sortable(r, self._sort_key),
                      reverse=self._sort_reverse)

        prev_node = None
        for r in rows:
            node = r.get("_node") or r.get("node") or ""
            dev = r.get("_device") or r.get("device") or ""
            desc = r.get("_description") or r.get("description") or ""
            slot = r.get("point_slot")
            slot_str = f"({slot})" if slot is not None else ""
            is_error = "error" in r

            if is_error:
                point_str = "—"
                value_str = f"({r['error']})"
                units_str = ""
                status_str = "— unreachable"
                tags = ["error"]
            else:
                point_str = r.get("point_name") or "?"
                val_text = r.get("value_text") or ""
                raw = r.get("value")
                if val_text:
                    try:
                        value_str = f"{val_text} ({int(raw)})" if raw is not None else val_text
                    except (TypeError, ValueError):
                        value_str = val_text
                elif raw is None:
                    value_str = "—"
                else:
                    try:
                        f = float(raw)
                        value_str = f"{f:.0f}" if abs(f - round(f)) < 0.01 else f"{f:.2f}"
                    except (TypeError, ValueError):
                        value_str = str(raw)
                units_str = r.get("units") or ""
                comm = r.get("comm_status") or ""
                if comm == "online":
                    status_str = "✓ OK"
                    tags = []
                elif comm == "comm_fault":
                    status_str = "✗ #COM"
                    tags = ["comm_fault"]
                else:
                    status_str = "—"
                    tags = []

            # Subtle alternating background between nodes (only useful in sort-by-node)
            if self._sort_key == "node" and prev_node is not None and node != prev_node:
                # (We could insert a blank row, but that clutters sortable tables.
                # Just tag for a subtle visual break instead.)
                pass
            prev_node = node

            # Simple text filter — match any column
            if filter_text:
                haystack = " ".join(str(x).lower() for x in (
                    node, dev, desc, slot_str, point_str, value_str, units_str, status_str
                ))
                if filter_text not in haystack:
                    continue
            if hide_errors and is_error:
                continue

            iid = self._tree.insert(
                "",
                "end",
                values=(node, dev, desc, slot_str, point_str, value_str, units_str, status_str),
                tags=tuple(tags),
            )
            self._iid_to_result[iid] = r

    def _on_double_click(self, _event) -> None:
        sel = self._tree.selection()
        if not sel or not self._on_jump_to_device:
            return
        r = self._iid_to_result.get(sel[0])
        if not r:
            return
        node = r.get("_node") or r.get("node")
        device = r.get("_device") or r.get("device")
        if node and device:
            self._on_jump_to_device(node, device)


# ═══════════════════════════════════════════════════════════════════════════
# HELP WINDOW
# ═══════════════════════════════════════════════════════════════════════════

# Help content is a list of (level, text) tuples. Level controls styling:
#   "h1"   — top-level heading
#   "h2"   — section heading
#   "p"    — body paragraph
#   "li"   — bullet item
#   "code" — inline monospace block (e.g. command example)
HELP_SECTIONS: List[Tuple[str, str]] = [
    ("h1", "P2 Scanner GUI — User Guide"),
    ("p", "A graphical front-end for the Siemens P2 protocol scanner. "
          "Wraps the p2_scanner library for interactive use against "
          "Siemens PXC/TEC controllers. Read-only — it never writes "
          "to a controller."),

    ("h2", "1. Getting started"),
    ("p", "Before the GUI can talk to anything, it needs to know three things "
          "about your site: the BLN (network) name, a scanner identity, and "
          "at least one PXC node with an IP. All three live in site.json."),
    ("li", "File → Edit Site Config… opens a dialog to edit everything at once."),
    ("li", "Discovery → Add Node Manually… opens a small name+IP dialog for "
           "adding a single node."),
    ("li", "Discovery → Port Scan Range… scans an IP range on TCP/5033 "
           "(the P2 port) for PXCs and offers to add any it finds."),
    ("p", "If site.json doesn't exist yet, the app starts with empty identity. "
          "The top toolbar always shows the current Network / Site / Scanner "
          "so you can tell at a glance what you're connected to."),

    ("h2", "2. Working with nodes"),
    ("p", "The left tree shows ⌬ BLN → node → device. Clicking a node "
          "selects it; the buttons below the tree act on the selected "
          "node. The primary row holds snappy operations; the secondary "
          "row (Walk All Points, PPCL Programs) holds slower panel-wide "
          "reads — see section 5."),
    ("li", "Enumerate FLN — asks the PXC to list every device on its FLN "
           "bus (opcode 0x0986). Populates the tree. Fast."),
    ("li", "Verify Online — reads ROOM TEMP on every enumerated device to "
           "see which ones are actually responding. Tree rows flip color "
           "(green online, red offline) live as each device is checked. "
           "Offline devices take ~6 seconds each on the wire; this is "
           "the PXC's own timeout and can't be shortened."),
    ("li", "Firmware — queries the PXC's model, firmware version, and build "
           "date. Covered in detail in section 5."),

    ("h2", "3. Reading points on a single device"),
    ("p", "Select a device in the tree, then use the detail panel on the right:"),
    ("li", "Scan All Points — reads every point defined in the device's "
           "application. Uses the point table from tecpoints.json."),
    ("li", "Quick Scan — reads a curated subset of operational points "
           "(ROOM TEMP, CTL STPT, HEAT.COOL, etc.) filtered to just those "
           "defined in this device's app, so small-app devices don't "
           "waste time on undefined names."),
    ("li", "Read Point… — reads one point you type. Accepts either a name "
           "('ROOM TEMP', 'HEAT.COOL') or a slot number (4, 29). Check "
           "'Force read of undefined slot' only if you're protocol-"
           "troubleshooting a slot that isn't in tecpoints.json."),
    ("p", "Results show up in the point table. Click column headers to sort. "
          "Point rows include: the slot number in parens, the point name, "
          "the value (digital points rendered as 'LABEL (raw)'), units, "
          "data type, and status (✓ OK or ✗ #COM)."),
    ("li", "Export CSV… / Export JSON… save the visible results to a file."),

    ("h2", "4. Sweeping points across many devices"),
    ("p", "Discovery → Sweep Points Across Devices… opens the sweep dialog. "
          "This is the 'how are all the room temps right now' workflow."),
    ("h2", "   4a. Picking points to read"),
    ("p", "The text area accepts one point per line. You can also paste a "
          "comma- or semicolon-separated list. Entries can be:"),
    ("li", "Point names — ROOM TEMP, HEAT.COOL, DAY CLG STPT, CTL STPT. "
           "Names work across all applications."),
    ("li", "Slot numbers — 4, 29, 35. Slots are app-specific: slot 4 is "
           "ROOM TEMP in the standard VAV family (2020-2027) but could "
           "mean something different in a fume hood or unit ventilator app. "
           "Use numbers if you really mean 'whatever lives at slot 4 in "
           "each device's app'; use names if you want the same concept "
           "regardless of app."),
    ("p", "The 'Add common point ▾' button above the text area offers "
          "categorized one-click insertion of the most frequently-swept "
          "points: Temperature, Setpoints, Mode, Airflow, Valves, Outputs, "
          "Status, and Meta. Slot numbers in the menu labels are the "
          "standard-VAV slot for reference; the button inserts the name, "
          "so it works across all apps."),
    ("p", "'Insert all quick operational points' at the bottom of the menu "
          "replaces the text area with the full QUICK_SCAN_POINTS list "
          "(18 points)."),

    ("h2", "   4b. Scope & nodes"),
    ("li", "All enumerated devices — reads every device regardless of "
           "status. Good for finding newly-offline devices."),
    ("li", "Only devices verified online — skips known-offline and "
           "never-verified devices. Fastest."),
    ("p", "The node checkbox list below shows how many devices each node "
          "has enumerated (and of those, how many are online). Nodes with "
          "no enumerated devices are unchecked by default; enumerate them "
          "first if you want them in the sweep."),

    ("h2", "   4c. Optimization: per-device point filter"),
    ("p", "Before calling the wire, the sweep filters each requested point "
          "through that device's application point table. If you sweep "
          "ROOM TEMP + HEAT.COOL across a mixed-app building and some "
          "devices run an app that doesn't define HEAT.COOL, those "
          "devices only get asked for ROOM TEMP. No wasted timeouts."),

    ("h2", "   4d. Results window"),
    ("p", "Opens in its own window so you can keep it visible while "
          "exploring other devices. Columns are Node, Device, Description, "
          "Slot, Point, Value, Units, Status. Click any column header to sort."),
    ("li", "Filter — live text filter across all columns. Type 'K4' to "
           "see only devices starting with K4; type '#COM' to see only "
           "comm-faulted reads."),
    ("li", "Hide unreachable — toggles showing devices that couldn't be "
           "read at all (no comm, bad handshake)."),
    ("li", "Re-sweep — re-opens the sweep dialog so you can tweak and "
           "run again."),
    ("li", "Export CSV… / Export JSON… save the full result set (not "
           "just what's filtered)."),
    ("li", "Double-click any row — selects that device in the main tree "
           "so you can drill in with Scan All / Read Point."),

    ("h2", "5. Panel-wide reads (Walk / Programs / Firmware)"),
    ("p", "The row of buttons below the tree — Walk All Points, PPCL "
          "Programs, Firmware — operate on a whole PXC panel rather than "
          "a single device. Walk and Programs can take 10–30 seconds on a "
          "busy panel, so each prompts for confirmation before running."),
    ("li", "Firmware — queries the PXC for its model, firmware version, "
           "and build date. The GUI first tries the newer 0x010C compact "
           "sysinfo opcode (richer output on PME1300-era panels, includes "
           "a build date) and transparently falls back to legacy 0x0100 "
           "on older firmware. The log line tells you which opcode worked."),
    ("li", "Walk All Points — enumerates every point the PXC knows about "
           "via opcode 0x0981. This is more complete than Enumerate FLN: "
           "it includes PPCL variables, schedule points, global analogs, "
           "and panel-level Title entries alongside the FLN device points. "
           "Results open in a window with a sortable Device / Subkey / "
           "Point / Value / Units / Description table, a filter box, and "
           "a 'Hide title entries' toggle. Export as CSV or JSON. Walks "
           "are also archived in session history, so you can diff two "
           "walks of the same panel across time to see what came and "
           "went."),
    ("p", "Subkeys: some PXC points use a compound identity — two name "
          "fields (e.g. BCCW / DAY.NGT) where a normal point has one. "
          "The Subkey column is the second field, empty for normal "
          "points. When diffing walks, entries are matched by (device, "
          "subkey, point) so compound entries don't collide."),
    ("li", "PPCL Programs — dumps the full PPCL source text of every "
           "program on the PXC via opcode 0x0985. Opens a master-detail "
           "view: program list on the left (name, module tag, line count), "
           "read-only monospace source on the right. A find bar "
           "highlights every match in the current program. Comment lines "
           "(lines tagged 'C' in PPCL convention) render in green. Export "
           "all programs as a JSON archive."),
    ("p", "Firmware-dialect note: the scanner auto-detects whether a PXC "
          "speaks the legacy (PME1252-era) or modern (PME1300/AAS) P2 "
          "wire dialect. If you used an earlier version and some panels "
          "seemed unreachable, they should now respond. The first connect "
          "to a modern panel is about 2 seconds slower while the dialect "
          "is probed; subsequent connects are fast. Nothing to configure."),

    ("h2", "6. Scan history (View → Scan History…)"),
    ("p", "Every scan and sweep you run this session is archived in memory "
          "with a timestamp. Open the history window to browse, reopen, "
          "or compare previous scans without redoing them."),
    ("li", "Open — loads the selected entry. Device scans restore into the "
           "main detail panel; sweep entries reopen their results window."),
    ("li", "Compare… — with exactly two entries selected (Ctrl-click or "
           "Shift-click), opens a side-by-side diff. Same-device device "
           "scans and same-points sweeps produce row-by-row matching "
           "with changed values highlighted. Use 'Show only changed "
           "values' to filter to deltas only."),
    ("li", "Delete — removes selected entries. Clear All — empties the "
           "whole history."),
    ("p", "History is in-memory only — it's cleared when the app closes. "
          "To save a scan permanently, use Export CSV / Export JSON from "
          "the point table or the sweep results window."),

    ("h2", "7. Cold-discovering a new site (CLI only)"),
    ("p", "When you're onboarding a site where nothing is configured — you "
          "don't know the BLN network name, which PXCs exist, or what "
          "node names they use — cold discovery handles it via a tiered "
          "dictionary attack against common Siemens naming conventions. "
          "That workflow lives in the CLI scanner, not the GUI, because "
          "it involves probe bursts that warrant their own delay flags "
          "and warnings."),
    ("p", "Run from a terminal in the scanner folder:"),
    ("code", "    python p2_scanner.py --cold-discover --range 192.0.2.0/24 --save site.json"),
    ("p", "Add --cold-delay 2 during production hours for a 2-second pause "
          "between probes. On sites that have Siemens MulticastEnabled on, "
          "you can skip probes entirely with --listen-push 60 (passive listen "
          "for BLN multicast announcements). See the main p2_scanner "
          "README for the full flag list and safety notes."),
    ("p", "Caveat — cold-discover uses legacy-dialect probes only. On an "
          "all-modern greenfield site (everything PME1300 / AAS), cold "
          "discovery may fail to fingerprint anything. Workaround: if you "
          "know any one panel IP in advance, point the scanner directly "
          "at it with -n NODEx — that path does auto-detect the dialect "
          "correctly."),
    ("p", "Once cold-discover has written a site.json, come back to the "
          "GUI and use File → Load Config… to pick it up."),

    ("h2", "8. Tips & troubleshooting"),
    ("li", "Handshake fails — the BLN name is wrong, or the scanner name "
           "format doesn't match what the site expects. Some sites require "
           "<SITE>DCC-SVR|5034 (the Desigo CC server identity) instead "
           "of the generic default."),
    ("li", "Verify takes forever — expected for sites with many offline "
           "devices. Each offline device eats ~6s of PXC timeout. "
           "A 65-device verify with all offline is ~6-7 minutes. "
           "The tree updates live so you can tell it's actually working."),
    ("li", "Device shows #COM — the PXC returned cached data but the "
           "FLN bus can't reach the device. Check wiring and the device's "
           "own power."),
    ("li", "Quick Scan returned nothing — the device's app doesn't have "
           "any QUICK_SCAN_POINTS defined. Try Scan All Points instead."),
    ("li", "'Busy' indicator stuck — only one scanner operation runs at "
           "a time by design (PXCs have a small peer-session budget). "
           "Wait for the current task to finish."),
    ("li", "Debug reads checkbox — top-right toggle. Turns on verbose "
           "hex logging for point reads that fail to parse. Useful for "
           "protocol troubleshooting; noisy for normal use."),

    ("h2", "9. Keyboard shortcuts"),
    ("li", "Enter in Read Point dialog — submit."),
    ("li", "Escape in any dialog — cancel."),
    ("li", "Double-click a device in any tree — selects it."),
    ("li", "Click column headers in any table — sort; click again to reverse."),

    ("h2", "10. Files it creates"),
    ("li", ".p2_gui_scanner_path — remembers where p2_scanner.py is, so "
           "you don't have to re-browse on every launch."),
    ("li", "site.json — only when you click Save Config. The GUI never "
           "writes to disk automatically."),
    ("li", "Exported CSV/JSON — only where and when you choose."),
]


class HelpWindow(tk.Toplevel):
    """Scrollable in-app user guide."""

    def __init__(self, parent: tk.Misc) -> None:
        super().__init__(parent)
        self.title("P2 Scanner GUI — User Guide")
        self.minsize(560, 400)
        self._parent = parent

        # Header bar with close button
        header = ttk.Frame(self, padding=(12, 8))
        header.pack(fill="x")
        ttk.Label(
            header,
            text="User Guide",
            font=("", 12, "bold"),
        ).pack(side="left")
        ttk.Button(header, text="Close", command=self.destroy).pack(side="right")

        # Body: text widget with scrollbar
        body = ttk.Frame(self, padding=(0, 0, 0, 0))
        body.pack(fill="both", expand=True)

        try:
            import tkinter.font as tkfont
            default_family = tkfont.nametofont("TkDefaultFont").cget("family")
        except Exception:
            default_family = "Helvetica"

        text = tk.Text(
            body,
            wrap="word",
            padx=18,
            pady=12,
            bg="#ffffff",
            borderwidth=0,
            relief="flat",
            font=(default_family, 10),
        )
        sby = ttk.Scrollbar(body, orient="vertical", command=text.yview)
        text.configure(yscrollcommand=sby.set)
        text.grid(row=0, column=0, sticky="nsew")
        sby.grid(row=0, column=1, sticky="ns")
        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=1)

        # Tag styles
        text.tag_configure(
            "h1", font=(default_family, 16, "bold"),
            foreground="#111", spacing1=4, spacing3=8,
        )
        text.tag_configure(
            "h2", font=(default_family, 12, "bold"),
            foreground="#222", spacing1=12, spacing3=4,
        )
        text.tag_configure(
            "p", spacing1=2, spacing3=6, lmargin1=0, lmargin2=0,
        )
        text.tag_configure(
            "li", spacing1=1, spacing3=2,
            lmargin1=20, lmargin2=36,
        )
        text.tag_configure(
            "code", font=("Courier", 9),
            background="#f0f0f0", foreground="#333",
        )

        # Render the help content
        for level, content in HELP_SECTIONS:
            if level == "h1":
                text.insert("end", content + "\n", "h1")
            elif level == "h2":
                text.insert("end", content + "\n", "h2")
            elif level == "p":
                text.insert("end", content + "\n", "p")
            elif level == "li":
                text.insert("end", "  •  " + content + "\n", "li")
            elif level == "code":
                text.insert("end", content + "\n", "code")

        text.configure(state="disabled")

        self.bind("<Escape>", lambda _e: self.destroy())

        _center_on_parent(self, self._parent, width=780, height=640)


# ═══════════════════════════════════════════════════════════════════════════
# SCAN HISTORY — in-memory session store + browser + compare
# ═══════════════════════════════════════════════════════════════════════════

class ScanHistory:
    """Holds every scan/sweep done this session with a timestamp so the
    user can go back, reopen, and compare. In-memory only — cleared on
    application exit (disk persistence is a future feature)."""

    def __init__(self) -> None:
        self._entries: List[Dict] = []
        self._next_id = 1

    def add_device_scan(
        self,
        node: str,
        device: str,
        application: Optional[int],
        results: List[Dict],
        scan_type: str = "full",
    ) -> Dict:
        """Record a per-device scan (full / quick / single-point)."""
        import time
        entry = {
            "id": self._next_id,
            "kind": "device",
            "timestamp": time.time(),
            "node": node,
            "device": device,
            "application": application or 0,
            "scan_type": scan_type,  # 'full' | 'quick' | 'single'
            "results": [dict(r) for r in results],  # defensive copy
        }
        self._next_id += 1
        self._entries.append(entry)
        return entry

    def add_sweep(
        self,
        points: List[str],
        target_count: int,
        results: List[Dict],
    ) -> Dict:
        """Record a building-wide sweep."""
        import time
        entry = {
            "id": self._next_id,
            "kind": "sweep",
            "timestamp": time.time(),
            "points": list(points),
            "target_count": target_count,
            "results": [dict(r) for r in results],
        }
        self._next_id += 1
        self._entries.append(entry)
        return entry

    def add_walk(
        self,
        node: str,
        entries: List[Dict],
    ) -> Dict:
        """Record a Walk All Points run on a single PXC."""
        import time
        entry = {
            "id": self._next_id,
            "kind": "walk",
            "timestamp": time.time(),
            "node": node,
            "entries": [dict(e) for e in entries],  # defensive copy
        }
        self._next_id += 1
        self._entries.append(entry)
        return entry

    def all(self) -> List[Dict]:
        return list(self._entries)

    def get(self, entry_id: int) -> Optional[Dict]:
        for e in self._entries:
            if e["id"] == entry_id:
                return e
        return None

    def for_device(self, node: str, device: str) -> List[Dict]:
        return [
            e for e in self._entries
            if e["kind"] == "device"
            and e["node"] == node
            and e["device"] == device
        ]

    def remove(self, entry_id: int) -> bool:
        for i, e in enumerate(self._entries):
            if e["id"] == entry_id:
                del self._entries[i]
                return True
        return False

    def clear(self) -> None:
        self._entries.clear()

    def __len__(self) -> int:
        return len(self._entries)


def _format_timestamp(ts: float) -> str:
    import datetime
    return datetime.datetime.fromtimestamp(ts).strftime("%Y-%m-%d %H:%M:%S")


def _summarize_entry(entry: Dict) -> Tuple[str, str, str, str]:
    """Return (timestamp, kind_label, target_label, detail) tuple for display."""
    ts = _format_timestamp(entry["timestamp"])
    if entry["kind"] == "device":
        scan_type = entry.get("scan_type", "full")
        kind_label = {
            "full": "Full scan",
            "quick": "Quick scan",
            "single": "Single point",
        }.get(scan_type, "Scan")
        target_label = f"{entry['node']} / {entry['device']}"
        n = len(entry.get("results", []))
        app = entry.get("application", 0) or 0
        detail = f"{n} point{'s' if n != 1 else ''}"
        if app:
            detail += f"  ·  app {app}"
    elif entry["kind"] == "walk":
        kind_label = "Walk points"
        target_label = entry.get("node", "?")
        entries = entry.get("entries", [])
        n_total = len(entries)
        n_titles = sum(
            1 for e in entries
            if e.get("value") is None and e.get("description")
        )
        n_points = n_total - n_titles
        detail = f"{n_points} point{'s' if n_points != 1 else ''}"
        if n_titles:
            detail += f"  ·  {n_titles} title{'s' if n_titles != 1 else ''}"
    else:  # sweep
        kind_label = "Sweep"
        target_label = ", ".join(entry.get("points", []))
        n = len(entry.get("results", []))
        t = entry.get("target_count", 0)
        detail = f"{t} device{'s' if t != 1 else ''}  ·  {n} rows"
    return ts, kind_label, target_label, detail


class HistoryWindow(tk.Toplevel):
    """Browser for ScanHistory. Click-to-open, shift-click for compare."""

    def __init__(
        self,
        parent: tk.Misc,
        history: ScanHistory,
        on_open_entry,
        on_compare_entries,
    ) -> None:
        super().__init__(parent)
        self.title("Scan History")
        self.minsize(600, 320)
        self._parent = parent

        self._history = history
        self._on_open = on_open_entry
        self._on_compare = on_compare_entries

        # Header
        header = ttk.Frame(self, padding=(12, 10))
        header.pack(fill="x")
        ttk.Label(
            header,
            text="Session scan history",
            font=("", 12, "bold"),
        ).pack(side="left")
        ttk.Label(
            header,
            text="  (in-memory; cleared when the app closes)",
            foreground="#888",
        ).pack(side="left")
        ttk.Button(header, text="Close", command=self.destroy).pack(side="right")

        # Toolbar
        toolbar = ttk.Frame(self, padding=(12, 0, 12, 6))
        toolbar.pack(fill="x")
        ttk.Button(toolbar, text="Open", command=self._open_selected).pack(
            side="left", padx=2
        )
        ttk.Button(
            toolbar, text="Compare…", command=self._compare_selected
        ).pack(side="left", padx=2)
        ttk.Button(
            toolbar, text="Delete", command=self._delete_selected
        ).pack(side="left", padx=2)
        ttk.Separator(toolbar, orient="vertical").pack(
            side="left", fill="y", padx=8
        )
        ttk.Button(toolbar, text="Clear All", command=self._clear_all).pack(
            side="left", padx=2
        )
        ttk.Label(
            toolbar,
            text="  (Ctrl-click to select two entries for compare)",
            foreground="#888",
        ).pack(side="left", padx=(12, 0))

        # Table
        body = ttk.Frame(self, padding=(12, 0, 12, 10))
        body.pack(fill="both", expand=True)

        cols = ("time", "kind", "target", "detail")
        self._tree = ttk.Treeview(
            body, columns=cols, show="headings", selectmode="extended"
        )
        self._tree.heading("time", text="When")
        self._tree.heading("kind", text="Type")
        self._tree.heading("target", text="Target")
        self._tree.heading("detail", text="Detail")
        self._tree.column("time", width=160, anchor="w")
        self._tree.column("kind", width=110, anchor="w")
        self._tree.column("target", width=260, anchor="w", stretch=True)
        self._tree.column("detail", width=180, anchor="w")

        sby = ttk.Scrollbar(body, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=sby.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        sby.grid(row=0, column=1, sticky="ns")
        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=1)

        self._iid_to_id: Dict[str, int] = {}
        self._tree.bind("<Double-1>", lambda _e: self._open_selected())

        self.bind("<Escape>", lambda _e: self.destroy())
        self.refresh()

        _center_on_parent(self, self._parent, width=880, height=480)

    def refresh(self) -> None:
        for iid in self._tree.get_children():
            self._tree.delete(iid)
        self._iid_to_id.clear()
        # Most-recent first
        entries = sorted(
            self._history.all(),
            key=lambda e: e["timestamp"],
            reverse=True,
        )
        for e in entries:
            ts, kind, target, detail = _summarize_entry(e)
            iid = self._tree.insert("", "end", values=(ts, kind, target, detail))
            self._iid_to_id[iid] = e["id"]

    def _selected_ids(self) -> List[int]:
        return [self._iid_to_id[iid] for iid in self._tree.selection()]

    def _open_selected(self) -> None:
        ids = self._selected_ids()
        if not ids:
            return
        entry = self._history.get(ids[0])
        if entry and self._on_open:
            self._on_open(entry)

    def _compare_selected(self) -> None:
        ids = self._selected_ids()
        if len(ids) != 2:
            from tkinter import messagebox
            messagebox.showinfo(
                "Pick two entries",
                "Compare needs exactly two scans selected. Ctrl-click "
                "(or Shift-click) to select two rows.",
                parent=self,
            )
            return
        e1 = self._history.get(ids[0])
        e2 = self._history.get(ids[1])
        if e1 and e2 and self._on_compare:
            # Pass them in chronological order (older first) so the compare
            # view can label them "Before" / "After"
            if e1["timestamp"] > e2["timestamp"]:
                e1, e2 = e2, e1
            self._on_compare(e1, e2)

    def _delete_selected(self) -> None:
        ids = self._selected_ids()
        if not ids:
            return
        for eid in ids:
            self._history.remove(eid)
        self.refresh()

    def _clear_all(self) -> None:
        from tkinter import messagebox
        if not messagebox.askyesno(
            "Clear history?",
            f"Remove all {len(self._history)} history entries? This cannot be undone.",
            parent=self,
        ):
            return
        self._history.clear()
        self.refresh()


class CompareWindow(tk.Toplevel):
    """Side-by-side comparison of two ScanHistory entries."""

    def __init__(
        self,
        parent: tk.Misc,
        entry_before: Dict,
        entry_after: Dict,
    ) -> None:
        super().__init__(parent)
        self.title("Compare Scans")
        self.minsize(720, 400)
        self._parent = parent

        # Header with the two entries' summaries
        header = ttk.Frame(self, padding=(12, 10))
        header.pack(fill="x")

        compatible, reason = self._compatibility(entry_before, entry_after)
        if compatible:
            title = "Compare scans"
        else:
            title = f"Compare scans  —  {reason}"
        ttk.Label(header, text=title, font=("", 12, "bold")).pack(anchor="w")

        cols_frame = ttk.Frame(header)
        cols_frame.pack(fill="x", pady=(6, 0))
        for col, entry, label in (
            (0, entry_before, "Before"),
            (1, entry_after, "After"),
        ):
            box = ttk.Frame(cols_frame)
            box.grid(row=0, column=col, sticky="ew", padx=(0, 12))
            cols_frame.columnconfigure(col, weight=1)
            ts, kind, target, detail = _summarize_entry(entry)
            ttk.Label(box, text=f"{label}:", foreground="#666").pack(anchor="w")
            ttk.Label(box, text=f"{kind}  ·  {target}", font=("", 10, "bold")).pack(anchor="w")
            ttk.Label(box, text=f"{ts}  ·  {detail}", foreground="#666").pack(anchor="w")

        # Toolbar: filter changed-only
        tools = ttk.Frame(self, padding=(12, 0, 12, 6))
        tools.pack(fill="x")
        self._changed_only_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            tools,
            text="Show only changed values",
            variable=self._changed_only_var,
            command=self._render,
        ).pack(side="left")

        # Table: depends on whether entries are compatible
        body = ttk.Frame(self, padding=(12, 0, 12, 10))
        body.pack(fill="both", expand=True)

        self._body = body
        self._entry_before = entry_before
        self._entry_after = entry_after
        self._compatible = compatible
        self._reason = reason

        self._build_table()
        self._render()

        self.bind("<Escape>", lambda _e: self.destroy())

        _center_on_parent(self, self._parent, width=1040, height=600)

    @staticmethod
    def _compatibility(e1: Dict, e2: Dict) -> Tuple[bool, str]:
        if e1["kind"] != e2["kind"]:
            return False, "different scan types — row matching disabled"
        if e1["kind"] == "device":
            if e1["node"] != e2["node"] or e1["device"] != e2["device"]:
                return False, "different devices — row matching disabled"
        elif e1["kind"] == "sweep":
            if set(e1.get("points", [])) != set(e2.get("points", [])):
                return False, "different point sets — row matching disabled"
        elif e1["kind"] == "walk":
            if e1.get("node") != e2.get("node"):
                return False, "different nodes — row matching disabled"
        return True, "same target"

    def _build_table(self) -> None:
        # Clear any existing children
        for w in self._body.winfo_children():
            w.destroy()

        if self._entry_before["kind"] == "device":
            cols = ("slot", "name", "before", "after", "delta", "change")
            labels = ("Slot", "Point Name", "Before", "After", "Δ", "Change")
            widths = (60, 180, 140, 140, 80, 80)
        elif self._entry_before["kind"] == "walk":
            cols = ("device", "subkey", "point", "before", "after", "delta", "change")
            labels = ("Device", "Subkey", "Point", "Before", "After", "Δ", "Change")
            widths = (140, 80, 180, 130, 130, 80, 80)
        else:  # sweep
            cols = ("node", "device", "point", "before", "after", "delta", "change")
            labels = ("Node", "Device", "Point", "Before", "After", "Δ", "Change")
            widths = (90, 120, 160, 130, 130, 80, 80)

        self._tree = ttk.Treeview(
            self._body, columns=cols, show="headings"
        )
        for c, lbl, w in zip(cols, labels, widths):
            self._tree.heading(c, text=lbl)
            anchor = "e" if c in ("before", "after", "delta") else "w"
            self._tree.column(c, width=w, anchor=anchor)

        sby = ttk.Scrollbar(self._body, orient="vertical", command=self._tree.yview)
        self._tree.configure(yscrollcommand=sby.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        sby.grid(row=0, column=1, sticky="ns")
        self._body.rowconfigure(0, weight=1)
        self._body.columnconfigure(0, weight=1)

        # Row tags
        self._tree.tag_configure(
            "changed", background="#fff4e0"
        )
        self._tree.tag_configure(
            "only_before", background="#f0f4ff", foreground="#444"
        )
        self._tree.tag_configure(
            "only_after", background="#f0fff4", foreground="#444"
        )

    def _format_value(self, r: Optional[Dict]) -> str:
        if r is None:
            return "—"
        if "error" in r:
            return f"({r['error']})"
        val = r.get("value")
        val_text = r.get("value_text") or ""
        if val_text:
            try:
                return f"{val_text} ({int(val)})" if val is not None else val_text
            except (TypeError, ValueError):
                return val_text
        if val is None:
            return "—"
        try:
            f = float(val)
            return f"{f:.0f}" if abs(f - round(f)) < 0.01 else f"{f:.2f}"
        except (TypeError, ValueError):
            return str(val)

    def _numeric(self, r: Optional[Dict]) -> Optional[float]:
        if r is None or "error" in r:
            return None
        v = r.get("value")
        if v is None:
            return None
        try:
            return float(v)
        except (TypeError, ValueError):
            return None

    def _delta(self, b: Optional[Dict], a: Optional[Dict]) -> str:
        bn, an = self._numeric(b), self._numeric(a)
        if bn is None or an is None:
            return ""
        d = an - bn
        if abs(d) < 0.005:
            return ""
        return f"{d:+.2f}" if abs(d) < 100 else f"{d:+.0f}"

    def _changed(self, b: Optional[Dict], a: Optional[Dict]) -> bool:
        # Different error state → changed
        b_err = b is None or "error" in (b or {})
        a_err = a is None or "error" in (a or {})
        if b_err != a_err:
            return True
        if b_err and a_err:
            return False
        # Compare rendered value strings
        return self._format_value(b) != self._format_value(a)

    def _render(self) -> None:
        for iid in self._tree.get_children():
            self._tree.delete(iid)

        changed_only = self._changed_only_var.get()

        if self._entry_before["kind"] == "device":
            self._render_device(changed_only)
        elif self._entry_before["kind"] == "walk":
            self._render_walk(changed_only)
        else:
            self._render_sweep(changed_only)

    def _render_walk(self, changed_only: bool) -> None:
        """Diff two Walk All Points runs on the same node. Entries are keyed
        by (device, subkey, point) — the subkey disambiguates compound-name
        entries where the same device has multiple records (e.g. BCCW has
        one entry per PPCL variable attached to it)."""

        def key(e: Dict) -> Tuple[str, str, str]:
            return (
                e.get("device", "") or "",
                e.get("subkey", "") or "",
                e.get("point", "") or "",
            )

        def as_result(e: Dict) -> Dict:
            # Walk entries use 'value'/'units' keys like scan results,
            # so they feed _format_value and _delta directly.
            return e

        before = {key(e): as_result(e) for e in self._entry_before.get("entries", [])}
        after = {key(e): as_result(e) for e in self._entry_after.get("entries", [])}
        all_keys = sorted(set(before) | set(after))

        for k in all_keys:
            device, subkey, point = k
            b = before.get(k)
            a = after.get(k)
            bv = self._format_value(b)
            av = self._format_value(a)
            delta = self._delta(b, a)
            changed = self._changed(b, a)
            change_str = "⬤" if changed else ""
            tags = []
            if b and not a:
                tags.append("only_before")
                change_str = "removed"
            elif a and not b:
                tags.append("only_after")
                change_str = "new"
            elif changed:
                tags.append("changed")
            if changed_only and not changed and b and a:
                continue
            self._tree.insert(
                "", "end",
                values=(device, subkey, point, bv, av, delta, change_str),
                tags=tuple(tags),
            )

    def _render_device(self, changed_only: bool) -> None:
        before = {r.get("point_name"): r for r in self._entry_before["results"]}
        after = {r.get("point_name"): r for r in self._entry_after["results"]}
        all_names = sorted(set(before) | set(after),
                           key=lambda n: ((before.get(n) or after.get(n) or {}).get("point_slot") or 10_000, n))

        for name in all_names:
            b = before.get(name)
            a = after.get(name)
            slot = ((b or a) or {}).get("point_slot")
            slot_str = f"({slot})" if slot is not None else ""
            bv = self._format_value(b)
            av = self._format_value(a)
            delta = self._delta(b, a)
            changed = self._changed(b, a)
            change_str = "⬤" if changed else ""
            tags = []
            if b and not a:
                tags.append("only_before")
                change_str = "removed"
            elif a and not b:
                tags.append("only_after")
                change_str = "new"
            elif changed:
                tags.append("changed")
            if changed_only and not changed and b and a:
                continue
            self._tree.insert(
                "", "end",
                values=(slot_str, name, bv, av, delta, change_str),
                tags=tuple(tags),
            )

    def _render_sweep(self, changed_only: bool) -> None:
        # Key rows by (node, device, point_name)
        def key(r: Dict) -> Tuple[str, str, str]:
            node = r.get("_node") or r.get("node") or ""
            dev = r.get("_device") or r.get("device") or ""
            pt = r.get("point_name") or ""
            return (node, dev, pt)

        before = {key(r): r for r in self._entry_before["results"]}
        after = {key(r): r for r in self._entry_after["results"]}
        all_keys = sorted(set(before) | set(after))

        for k in all_keys:
            node, dev, pt = k
            b = before.get(k)
            a = after.get(k)
            bv = self._format_value(b)
            av = self._format_value(a)
            delta = self._delta(b, a)
            changed = self._changed(b, a)
            change_str = "⬤" if changed else ""
            tags = []
            if b and not a:
                tags.append("only_before")
                change_str = "removed"
            elif a and not b:
                tags.append("only_after")
                change_str = "new"
            elif changed:
                tags.append("changed")
            if changed_only and not changed and b and a:
                continue
            self._tree.insert(
                "", "end",
                values=(node, dev, pt, bv, av, delta, change_str),
                tags=tuple(tags),
            )


# ═══════════════════════════════════════════════════════════════════════════
# WALK ALL POINTS WINDOW
# ═══════════════════════════════════════════════════════════════════════════

class WalkPointsWindow(tk.Toplevel):
    """Results viewer for conn.enumerate_all_points() — the full panel walk
    via 0x0981 which includes FLN devices plus panel-internal PPCL
    variables, scheduled points, global analogs, and Title entries.

    Two row shapes come back in the same list:
      * Regular:  {device, point, value, units, description=''}
      * Title:    {device==point, value=None, units='', description='label'}
    """

    COLUMNS = (
        ("device", "Device", 180, "w"),
        ("subkey", "Subkey", 85,  "w"),
        ("point",  "Point", 200, "w"),
        ("value",  "Value", 110, "e"),
        ("units",  "Units", 70,  "center"),
        ("desc",   "Description / Title", 260, "w"),
    )

    def __init__(
        self,
        parent: tk.Misc,
        node_name: str,
        entries: List[Dict],
        on_export_csv: Optional[Callable] = None,
        on_export_json: Optional[Callable] = None,
    ) -> None:
        super().__init__(parent)
        self.title(f"All Points — {node_name}")
        self.minsize(760, 440)
        self._parent = parent

        self._entries = list(entries)
        self._node_name = node_name

        # Header
        header = ttk.Frame(self, padding=(12, 10))
        header.pack(fill="x")
        ttk.Label(
            header,
            text=f"Panel-wide point walk: {node_name}",
            font=("", 11, "bold"),
        ).pack(anchor="w")

        n_total = len(entries)
        n_titles = sum(
            1 for e in entries
            if e.get("value") is None and e.get("description")
        )
        n_points = n_total - n_titles
        summary_parts = [f"{n_total} entr{'ies' if n_total != 1 else 'y'}"]
        if n_points:
            summary_parts.append(
                f"{n_points} point read{'s' if n_points != 1 else ''}"
            )
        if n_titles:
            summary_parts.append(
                f"{n_titles} title entr{'ies' if n_titles != 1 else 'y'}"
            )
        ttk.Label(
            header, text="  ·  ".join(summary_parts), foreground="#555"
        ).pack(anchor="w", pady=(2, 0))

        # Toolbar
        toolbar = ttk.Frame(self, padding=(12, 0, 12, 6))
        toolbar.pack(fill="x")
        if on_export_csv:
            ttk.Button(
                toolbar, text="Export CSV…",
                command=lambda: on_export_csv(self._entries, self._node_name),
            ).pack(side="left", padx=2)
        if on_export_json:
            ttk.Button(
                toolbar, text="Export JSON…",
                command=lambda: on_export_json(self._entries, self._node_name),
            ).pack(side="left", padx=2)
        ttk.Separator(toolbar, orient="vertical").pack(
            side="left", fill="y", padx=10
        )
        ttk.Label(toolbar, text="Filter:").pack(side="left", padx=(0, 4))
        # master=self anchors the trace lifetime to this window
        self._filter_var = tk.StringVar(master=self)
        self._filter_var.trace_add("write", lambda *a: self._render())
        ttk.Entry(toolbar, textvariable=self._filter_var, width=24).pack(side="left")

        self._hide_titles_var = tk.BooleanVar(value=False)
        ttk.Checkbutton(
            toolbar,
            text="Hide title entries",
            variable=self._hide_titles_var,
            command=self._render,
        ).pack(side="left", padx=(12, 0))

        ttk.Button(toolbar, text="Close", command=self.destroy).pack(side="right", padx=2)

        # Table
        body = ttk.Frame(self, padding=(12, 0, 12, 10))
        body.pack(fill="both", expand=True)
        keys = [c[0] for c in self.COLUMNS]
        self._tree = ttk.Treeview(body, columns=keys, show="headings")
        for key, label, width, anchor in self.COLUMNS:
            self._tree.heading(
                key, text=label, command=lambda k=key: self._sort_by(k)
            )
            self._tree.column(
                key, width=width, anchor=anchor,
                stretch=(key in ("point", "desc")),
            )
        sby = ttk.Scrollbar(body, orient="vertical", command=self._tree.yview)
        sbx = ttk.Scrollbar(body, orient="horizontal", command=self._tree.xview)
        self._tree.configure(yscrollcommand=sby.set, xscrollcommand=sbx.set)
        self._tree.grid(row=0, column=0, sticky="nsew")
        sby.grid(row=0, column=1, sticky="ns")
        sbx.grid(row=1, column=0, sticky="ew")
        body.rowconfigure(0, weight=1)
        body.columnconfigure(0, weight=1)

        # Title entries get a faint background so they read as labels
        # rather than values
        self._tree.tag_configure(
            "title", background="#f5f0e8", foreground="#6a5020"
        )

        self._sort_key = "device"
        self._sort_reverse = False
        self._render()

        self.bind("<Escape>", lambda _e: self.destroy())

        _center_on_parent(self, self._parent, width=980, height=560)

    def _sort_by(self, key: str) -> None:
        if key == self._sort_key:
            self._sort_reverse = not self._sort_reverse
        else:
            self._sort_key = key
            self._sort_reverse = False
        self._render()

    def _render(self) -> None:
        for iid in self._tree.get_children():
            self._tree.delete(iid)

        filter_text = self._filter_var.get().strip().lower()
        hide_titles = self._hide_titles_var.get()

        def is_title(e: Dict) -> bool:
            return (
                e.get("value") is None
                and bool(e.get("description"))
            )

        def sort_key(e: Dict):
            k = self._sort_key
            if k == "device":
                return (e.get("device", ""),)
            if k == "subkey":
                return (e.get("subkey", "") or "",)
            if k == "point":
                return (e.get("point", ""),)
            if k == "value":
                v = e.get("value")
                if v is None:
                    return (float("inf"),)
                try:
                    return (float(v),)
                except (TypeError, ValueError):
                    return (float("inf"),)
            if k == "units":
                return (e.get("units", ""),)
            if k == "desc":
                return (e.get("description", ""),)
            return ("",)

        rows = sorted(
            self._entries, key=sort_key, reverse=self._sort_reverse
        )

        for e in rows:
            title = is_title(e)
            if hide_titles and title:
                continue

            device = e.get("device", "") or ""
            subkey = e.get("subkey", "") or ""
            point = e.get("point", "") or ""
            raw = e.get("value")
            units = e.get("units", "") or ""
            desc = e.get("description", "") or ""

            if raw is None:
                value_str = "—"
            else:
                try:
                    f = float(raw)
                    value_str = f"{f:.0f}" if abs(f - round(f)) < 0.01 else f"{f:.2f}"
                except (TypeError, ValueError):
                    value_str = str(raw)

            if filter_text:
                haystack = " ".join(
                    str(x).lower() for x in (device, subkey, point, value_str, units, desc)
                )
                if filter_text not in haystack:
                    continue

            tags = ("title",) if title else ()
            self._tree.insert(
                "", "end",
                values=(device, subkey, point, value_str, units, desc),
                tags=tags,
            )


# ═══════════════════════════════════════════════════════════════════════════
# PPCL PROGRAMS WINDOW
# ═══════════════════════════════════════════════════════════════════════════

class ProgramsWindow(tk.Toplevel):
    """Master-detail viewer for conn.read_programs() — PPCL source dumps.

    Left: program list (name + module tag). Right: read-only monospace
    source. Includes an in-source find bar for searching the currently-
    selected program.
    """

    def __init__(
        self,
        parent: tk.Misc,
        node_name: str,
        programs: List[Dict],
        on_export: Optional[Callable] = None,
    ) -> None:
        super().__init__(parent)
        self.title(f"PPCL Programs — {node_name}")
        self.minsize(700, 420)
        self._parent = parent

        self._programs = list(programs)
        self._node_name = node_name

        # Header
        header = ttk.Frame(self, padding=(12, 10))
        header.pack(fill="x")
        ttk.Label(
            header,
            text=f"PPCL source: {node_name}",
            font=("", 11, "bold"),
        ).pack(anchor="w")
        total_lines = sum(p.get("code", "").count("\n") for p in programs)
        ttk.Label(
            header,
            text=f"{len(programs)} program{'s' if len(programs) != 1 else ''}"
                 f"  ·  {total_lines} total lines",
            foreground="#555",
        ).pack(anchor="w", pady=(2, 0))

        # Toolbar
        toolbar = ttk.Frame(self, padding=(12, 0, 12, 6))
        toolbar.pack(fill="x")
        if on_export:
            ttk.Button(
                toolbar, text="Export All…",
                command=lambda: on_export(self._programs, self._node_name),
            ).pack(side="left", padx=2)
        ttk.Separator(toolbar, orient="vertical").pack(
            side="left", fill="y", padx=10
        )
        ttk.Label(toolbar, text="Find in source:").pack(side="left", padx=(0, 4))
        # master=self anchors the trace lifetime to this window
        self._find_var = tk.StringVar(master=self)
        self._find_var.trace_add("write", lambda *a: self._find_in_source())
        find_entry = ttk.Entry(toolbar, textvariable=self._find_var, width=24)
        find_entry.pack(side="left")
        ttk.Button(toolbar, text="Next", command=self._find_next).pack(
            side="left", padx=(4, 0)
        )
        ttk.Button(toolbar, text="Close", command=self.destroy).pack(
            side="right", padx=2
        )

        # Split body: list | source
        body = ttk.Panedwindow(self, orient="horizontal")
        body.pack(fill="both", expand=True, padx=12, pady=(0, 10))

        # Left: program list
        left = ttk.Frame(body)
        body.add(left, weight=1)
        cols = ("name", "module", "lines")
        self._prog_tree = ttk.Treeview(
            left, columns=cols, show="headings", selectmode="browse"
        )
        self._prog_tree.heading("name", text="Program")
        self._prog_tree.heading("module", text="Module")
        self._prog_tree.heading("lines", text="Lines")
        self._prog_tree.column("name", width=160, anchor="w")
        self._prog_tree.column("module", width=60, anchor="center")
        self._prog_tree.column("lines", width=55, anchor="e")
        psb = ttk.Scrollbar(left, orient="vertical", command=self._prog_tree.yview)
        self._prog_tree.configure(yscrollcommand=psb.set)
        self._prog_tree.grid(row=0, column=0, sticky="nsew")
        psb.grid(row=0, column=1, sticky="ns")
        left.rowconfigure(0, weight=1)
        left.columnconfigure(0, weight=1)
        self._prog_tree.bind(
            "<<TreeviewSelect>>", lambda _e: self._on_select_program()
        )

        # Right: source text
        right = ttk.Frame(body)
        body.add(right, weight=3)

        try:
            import tkinter.font as tkfont
            mono_family = "Consolas" if "Consolas" in tkfont.families() else "Courier"
        except Exception:
            mono_family = "Courier"

        self._source = tk.Text(
            right,
            wrap="none",
            font=(mono_family, 10),
            bg="#fcfcf8",
            fg="#222",
            padx=10,
            pady=8,
            borderwidth=0,
        )
        ssy = ttk.Scrollbar(right, orient="vertical", command=self._source.yview)
        ssx = ttk.Scrollbar(right, orient="horizontal", command=self._source.xview)
        self._source.configure(yscrollcommand=ssy.set, xscrollcommand=ssx.set)
        self._source.grid(row=0, column=0, sticky="nsew")
        ssy.grid(row=0, column=1, sticky="ns")
        ssx.grid(row=1, column=0, sticky="ew")
        right.rowconfigure(0, weight=1)
        right.columnconfigure(0, weight=1)

        self._source.tag_configure(
            "search_hit", background="#ffe58a", foreground="#222"
        )
        self._source.tag_configure(
            "comment", foreground="#0b7"
        )

        # Populate program list
        self._iid_to_idx: Dict[str, int] = {}
        for i, prog in enumerate(self._programs):
            name = prog.get("name", "?")
            mod = prog.get("module", "") or ""
            code = prog.get("code", "") or ""
            lines = code.count("\n") + (0 if code.endswith("\n") or not code else 1)
            iid = self._prog_tree.insert(
                "", "end", values=(name, mod, lines)
            )
            self._iid_to_idx[iid] = i

        self._source.configure(state="disabled")

        # Auto-select first program
        first = self._prog_tree.get_children()
        if first:
            self._prog_tree.selection_set(first[0])
            self._prog_tree.focus(first[0])
            # Call the handler directly — the <<TreeviewSelect>> event from
            # selection_set() fires asynchronously, so if the caller opens
            # the window and immediately queries the source text it'd be
            # empty. Populate it synchronously here.
            self._on_select_program()

        self.bind("<Escape>", lambda _e: self.destroy())

        _center_on_parent(self, self._parent, width=940, height=600)

    def _on_select_program(self) -> None:
        sel = self._prog_tree.selection()
        if not sel:
            return
        idx = self._iid_to_idx.get(sel[0])
        if idx is None:
            return
        prog = self._programs[idx]
        self._source.configure(state="normal")
        self._source.delete("1.0", "end")
        code = prog.get("code", "") or "(empty program)"
        self._source.insert("1.0", code)

        # Faint coloring for PPCL comment lines (start with 'C ' after the
        # line number, or are the bare 'C' filler)
        self._source.tag_remove("comment", "1.0", "end")
        line_count = int(self._source.index("end-1c").split(".")[0])
        for ln in range(1, line_count + 1):
            line = self._source.get(f"{ln}.0", f"{ln}.end")
            stripped = line.strip()
            # PPCL convention: "NNNN    C <comment>" or "NNNN    C"
            parts = stripped.split(None, 2)
            if len(parts) >= 2 and parts[1].upper() == "C":
                self._source.tag_add("comment", f"{ln}.0", f"{ln}.end")

        self._source.configure(state="disabled")
        self._source.yview_moveto(0)
        # Re-apply any active find
        self._find_in_source()

    def _find_in_source(self) -> None:
        """Highlight all occurrences of the find-text in the current source."""
        self._source.configure(state="normal")
        try:
            self._source.tag_remove("search_hit", "1.0", "end")
            needle = self._find_var.get()
            if not needle:
                return
            start = "1.0"
            while True:
                pos = self._source.search(needle, start, "end", nocase=True)
                if not pos:
                    break
                end = f"{pos}+{len(needle)}c"
                self._source.tag_add("search_hit", pos, end)
                start = end
        finally:
            self._source.configure(state="disabled")

    def _find_next(self) -> None:
        """Scroll to the next search hit past the current view."""
        needle = self._find_var.get()
        if not needle:
            return
        current_top = self._source.index("@0,0")
        # Search from after current_top; wrap to start if nothing found
        pos = self._source.search(
            needle, f"{current_top}+1c", "end", nocase=True
        )
        if not pos:
            pos = self._source.search(needle, "1.0", "end", nocase=True)
        if pos:
            self._source.see(pos)
