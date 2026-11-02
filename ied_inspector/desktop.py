"""Desktop mode: the same user interface in a native application window (pywebview),
plus the start-up dialog that lets the user choose between desktop window and browser.

pywebview is optional:  pip install "ied-inspector[gui]"
  Windows: uses the Microsoft Edge WebView2 runtime (part of Windows 10/11)
  Linux  : uses GTK + WebKit2 (e.g. apt install python3-gi gir1.2-webkit2-4.1) or Qt
"""
import os
import sys

ASSETS = os.path.join(getattr(sys, "_MEIPASS", os.path.dirname(os.path.dirname(os.path.abspath(__file__)))),
                      "ied_inspector", "assets") if hasattr(sys, "_MEIPASS") else \
    os.path.join(os.path.dirname(os.path.abspath(__file__)), "assets")


def has_display():
    if sys.platform.startswith("linux"):
        if os.environ.get("WAYLAND_DISPLAY"):
            return True
        if not os.environ.get("DISPLAY"):
            return False
        # GTK terminates the whole process if the X display cannot be opened, so test it first
        try:
            import ctypes
            import ctypes.util
            name = ctypes.util.find_library("X11")
            if not name:
                return True
            x11 = ctypes.CDLL(name)
            x11.XOpenDisplay.restype = ctypes.c_void_p
            x11.XOpenDisplay.argtypes = [ctypes.c_char_p]
            dpy = x11.XOpenDisplay(None)
            if not dpy:
                return False
            x11.XCloseDisplay.argtypes = [ctypes.c_void_p]
            x11.XCloseDisplay(dpy)
        except Exception:
            pass
    return True


def desktop_available():
    """(available, reason) – can a desktop window be opened on this computer?"""
    if not has_display():
        return False, "no graphical display (SSH / server session)"
    try:
        import webview  # noqa: F401
    except Exception:
        return False, 'the desktop window needs pywebview: pip install "ied-inspector[gui]"'
    return True, ""


def choose_mode(saved="ask"):
    """Return 'gui' or 'web' and whether to remember it. Shows a small dialog when needed."""
    ok, why = desktop_available()
    if saved in ("gui", "web"):
        return (saved if (saved == "web" or ok) else "web"), False
    if not has_display():
        return "web", False
    try:
        import tkinter as tk
        from tkinter import ttk
    except Exception:
        return ("gui" if ok else "web"), False

    from . import __version__
    result = {"mode": None, "remember": False}
    root = tk.Tk()
    root.title("IED Inspector")
    root.resizable(False, False)
    try:
        ico = tk.PhotoImage(file=os.path.join(ASSETS, "icon64.png"))
        root.iconphoto(True, ico)
    except Exception:
        ico = None
    bg, ink, muted, accent = "#16212b", "#e8edf1", "#9aa7b3", "#5a9be0"
    root.configure(bg=bg)
    frm = tk.Frame(root, bg=bg, padx=28, pady=22)
    frm.pack()
    head = tk.Frame(frm, bg=bg)
    head.pack(anchor="w")
    if ico:
        tk.Label(head, image=ico, bg=bg).pack(side="left", padx=(0, 12))
    tk.Label(head, text="IED Inspector", font=("Segoe UI", 18, "bold"), fg=ink, bg=bg).pack(side="left")
    tk.Label(head, text=f"  v{__version__}", font=("Segoe UI", 10), fg=muted, bg=bg).pack(side="left", pady=(8, 0))
    tk.Label(frm, text="How do you want to open the tool?", font=("Segoe UI", 11), fg=ink, bg=bg).pack(anchor="w", pady=(16, 10))

    def pick(m):
        result["mode"] = m
        result["remember"] = bool(rem.get())
        root.destroy()

    def big_button(parent, title, sub, cmd, enabled=True):
        b = tk.Frame(parent, bg="#223140" if enabled else "#1c262f", highlightthickness=1,
                     highlightbackground=accent if enabled else "#2c3a46", cursor="hand2" if enabled else "arrow",
                     padx=16, pady=12, width=240)
        t1 = tk.Label(b, text=title, font=("Segoe UI", 12, "bold"), fg=ink if enabled else muted, bg=b["bg"], anchor="w")
        t2 = tk.Label(b, text=sub, font=("Segoe UI", 9), fg=muted, bg=b["bg"], justify="left", anchor="w", wraplength=210)
        t1.pack(anchor="w")
        t2.pack(anchor="w", pady=(4, 0))
        if enabled:
            for w in (b, t1, t2):
                w.bind("<Button-1>", lambda e: cmd())
        return b

    row = tk.Frame(frm, bg=bg)
    row.pack(anchor="w")
    big_button(row, "Desktop window", "Opens as a normal application window." if ok else why,
               lambda: pick("gui"), ok).pack(side="left", padx=(0, 12), fill="y")
    big_button(row, "Web browser", "Opens in your default browser (http://127.0.0.1).",
               lambda: pick("web")).pack(side="left", fill="y")
    rem = tk.IntVar(value=0)
    style = ttk.Style(root)
    style.configure("Dark.TCheckbutton", background=bg, foreground=ink)
    ttk.Checkbutton(frm, text="Remember my choice (change it later in Settings, or start with --ask)",
                    variable=rem, style="Dark.TCheckbutton").pack(anchor="w", pady=(14, 0))
    root.bind("<Return>", lambda e: pick("gui" if ok else "web"))
    root.bind("<Escape>", lambda e: root.destroy())
    root.update_idletasks()
    w, h = root.winfo_width(), root.winfo_height()
    root.geometry(f"+{(root.winfo_screenwidth() - w) // 2}+{(root.winfo_screenheight() - h) // 3}")
    root.attributes("-topmost", True)
    root.after(400, lambda: root.attributes("-topmost", False))
    root.mainloop()
    if result["mode"] is None:              # dialog closed with X / Esc -> quit
        return None, False
    return result["mode"], result["remember"]


def log_path():
    """Log file next to the exe / program folder; falls back to the home folder if not writable."""
    base = os.path.dirname(sys.executable) if getattr(sys, "frozen", False) else \
        os.path.dirname(os.path.dirname(os.path.abspath(__file__)))
    for d in (base, os.path.expanduser("~")):
        p = os.path.join(d, "ied_inspector.log")
        try:
            with open(p, "a", encoding="utf-8"):
                return p
        except OSError:
            continue
    return None


def log(msg):
    import time as _t
    p = log_path()
    if p:
        with open(p, "a", encoding="utf-8") as f:
            f.write(f"{_t.strftime('%Y-%m-%d %H:%M:%S')}  {msg}\n")
    return p


def webview2_version():
    """Installed Microsoft Edge WebView2 runtime version (Windows), or None."""
    if not sys.platform.startswith("win"):
        return None
    try:
        import winreg
        key = r"SOFTWARE\WOW6432Node\Microsoft\EdgeUpdate\Clients\{F3017226-FE2A-4295-8BDF-00C3A9A7E4C5}"
        for hive, k in ((winreg.HKEY_LOCAL_MACHINE, key), (winreg.HKEY_CURRENT_USER, key.replace("WOW6432Node\\", "")),
                        (winreg.HKEY_LOCAL_MACHINE, key.replace("WOW6432Node\\", ""))):
            try:
                with winreg.OpenKey(hive, k) as h:
                    v = winreg.QueryValueEx(h, "pv")[0]
                    if v and v != "0.0.0.0":
                        return v
            except OSError:
                continue
    except Exception:
        pass
    return None


def diagnostics():
    """Text block for --diag: everything needed to see why the desktop window does not open."""
    import platform
    lines = [f"IED Inspector desktop diagnostics",
             f"  python      : {sys.version.split()[0]} ({platform.architecture()[0]}), frozen exe: {bool(getattr(sys, 'frozen', False))}",
             f"  system      : {platform.platform()}",
             f"  display     : {'yes' if has_display() else 'NO'}"]
    try:
        import webview
        try:
            from importlib.metadata import version as _v
            pv = _v("pywebview")
        except Exception:
            pv = getattr(webview, "__version__", "?")
        lines.append(f"  pywebview   : {pv} ({os.path.dirname(webview.__file__)})")
        libdir = os.path.join(os.path.dirname(webview.__file__), "lib")
        if sys.platform.startswith("win"):
            need = ["Microsoft.Web.WebView2.Core.dll", "Microsoft.Web.WebView2.WinForms.dll",
                    os.path.join("runtimes", "win-x64", "native", "WebView2Loader.dll")]
            for n in need:
                lines.append(f"    {'ok     ' if os.path.exists(os.path.join(libdir, n)) else 'MISSING'} webview/lib/{n}")
    except Exception as e:
        lines.append(f"  pywebview   : NOT AVAILABLE ({e!r})")
    if sys.platform.startswith("win"):
        try:
            import clr  # noqa: F401  (pythonnet)
            lines.append("  pythonnet   : ok")
        except Exception as e:
            lines.append(f"  pythonnet   : FAILED ({e!r})")
        ico = os.path.join(ASSETS, "window.ico")
        try:
            import clr
            clr.AddReference("System.Drawing")
            from System.Drawing import Icon  # noqa
            Icon(ico).Dispose()
            lines.append("  window icon : ok (System.Drawing accepts window.ico)")
        except Exception as e:
            lines.append(f"  window icon : FAILED ({e!r}) – start with IED_INSPECTOR_NO_ICON=1 as a workaround")
        v = webview2_version()
        lines.append(f"  WebView2    : {v or 'NOT FOUND – install the Evergreen runtime from https://go.microsoft.com/fwlink/p/?LinkId=2124703'}")
    else:
        try:
            import gi
            gi.require_version("WebKit2", "4.1")
            from gi.repository import WebKit2  # noqa: F401
            lines.append("  GTK WebKit2 : ok")
        except Exception as e:
            lines.append(f"  GTK WebKit2 : not available ({e!r}); Qt backend would need PyQt6 + PyQt6-WebEngine")
    lines.append(f"  log file    : {log_path()}")
    return "\n".join(lines)


def show_console():
    if sys.platform.startswith("win"):
        try:
            import ctypes
            hwnd = ctypes.windll.kernel32.GetConsoleWindow()
            if hwnd:
                ctypes.windll.user32.ShowWindow(hwnd, 5)   # SW_SHOW
        except Exception:
            pass


def error_box(title, text):
    """Visible error message even when the console is hidden."""
    try:
        import tkinter as tk
        from tkinter import messagebox
        r = tk.Tk()
        r.withdraw()
        messagebox.showerror(title, text, parent=r)
        r.destroy()
    except Exception:
        print(f"{title}: {text}", flush=True)


def run_window(url, title="IED Inspector"):
    """Open the UI in a native window; returns when the window is closed. Raises on failure.
    The console is hidden only after the window has really appeared."""
    import webview
    webview.settings["ALLOW_DOWNLOADS"] = True                  # report / pcap downloads
    webview.settings["OPEN_EXTERNAL_LINKS_IN_BROWSER"] = True   # npcap.com, GitHub … open in the browser
    win = webview.create_window(title, url, width=1440, height=920, min_size=(960, 600),
                                text_select=True, background_color="#1b2229")
    shown = {"ok": False}

    def on_shown():
        shown["ok"] = True
        log("desktop window shown")
        hide_own_console()
    try:
        win.events.shown += on_shown
    except Exception:
        pass
    kwargs = {"private_mode": True}
    # Windows (WinForms) loads the icon with System.Drawing.Icon: it must be a classic BMP-based .ico,
    # a PNG (or a PNG-compressed .ico) crashes the .NET UI thread. GTK/Qt want a PNG.
    icon = os.path.join(ASSETS, "window.ico" if sys.platform.startswith("win") else "icon256.png")
    if os.path.exists(icon) and os.environ.get("IED_INSPECTOR_NO_ICON") != "1":
        kwargs["icon"] = icon
    if sys.platform.startswith("win"):
        kwargs["gui"] = "edgechromium"      # never fall back to the old Internet Explorer engine
        if not webview2_version():
            raise RuntimeError("Microsoft Edge WebView2 runtime not found – install it from "
                               "https://go.microsoft.com/fwlink/p/?LinkId=2124703 or use the browser mode")
    log(f"starting desktop window ({kwargs.get('gui', 'auto')} backend) for {url}")
    webview.start(**kwargs)
    if not shown["ok"]:
        raise RuntimeError("the desktop window did not open (pywebview returned without showing it)")


def hide_own_console():
    """Windows: hide the console window in desktop mode, but only if this program owns it
    (started by double-click). A console the user started us from is left alone."""
    if not sys.platform.startswith("win"):
        return
    try:
        import ctypes
        k32 = ctypes.windll.kernel32
        procs = (ctypes.c_uint * 4)()
        if k32.GetConsoleProcessList(procs, 4) <= 1:
            hwnd = k32.GetConsoleWindow()
            if hwnd:
                ctypes.windll.user32.ShowWindow(hwnd, 0)   # SW_HIDE
    except Exception:
        pass
