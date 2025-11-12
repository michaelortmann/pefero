#!/usr/bin/env python
# SPDX-License-Identifier: MIT
# Copyright (c) 2025 Michael Ortmann
# We use ruff as a code formatter to keep the code style consistent (and to
# avoid off-topic discussions)
import getopt
import hashlib
import socket
import ssl
import sys
import tkinter as tk
from tkinter import font, scrolledtext, ttk

######## AutocompleteEntry ########

# https://github.com/TkinterEP/ttkwidgets/blob/ebaa7d412e432453b4a65b53d005dd8f8e4651ca/ttkwidgets/autocomplete/autocomplete_entry.py

tk_umlauts = [
    "odiaeresis",
    "adiaeresis",
    "udiaeresis",
    "Odiaeresis",
    "Adiaeresis",
    "Udiaeresis",
    "ssharp",
]


class AutocompleteEntry(ttk.Entry):
    """
    Subclass of :class:`ttk.Entry` that features autocompletion.

    To enable autocompletion use :meth:`set_completion_list` to define
    a list of possible strings to hit.
    To cycle through hits use down and up arrow keys.
    """

    def __init__(self, master=None, completevalues=None, **kwargs):
        """
        Create an AutocompleteEntry.

        :param master: master widget
        :type master: widget
        :param completevalues: autocompletion values
        :type completevalues: list
        :param kwargs: keyword arguments passed to the :class:`ttk.Entry` initializer
        """
        ttk.Entry.__init__(self, master, **kwargs)
        self._completion_list = completevalues
        self.set_completion_list(completevalues)
        self._hits = []
        self._hit_index = 0
        self.position = 0

    def set_completion_list(self, completion_list):
        """
        Set a new auto completion list

        :param completion_list: completion values
        :type completion_list: list
        """
        self._completion_list = sorted(
            completion_list, key=str.lower
        )  # Work with a sorted list
        self._hits = []
        self._hit_index = 0
        self.position = 0
        self.bind("<KeyRelease>", self.handle_keyrelease)

    def autocomplete(self, delta=0):
        """
        Autocomplete the Entry.

        :param delta: 0, 1 or -1: how to cycle through possible hits
        :type delta: int
        """
        if (
            delta
        ):  # need to delete selection otherwise we would fix the current position
            self.delete(self.position, tk.END)
        else:  # set position to end so selection starts where textentry ended
            self.position = len(self.get())
        # collect hits
        _hits = []
        for element in self._completion_list:
            if element.lower().startswith(
                self.get().lower()
            ):  # Match case-insensitively
                _hits.append(element)
        # if we have a new hit list, keep this in mind
        if _hits != self._hits:
            self._hit_index = 0
            self._hits = _hits
        # only allow cycling if we are in a known hit list
        if _hits == self._hits and self._hits:
            self._hit_index = (self._hit_index + delta) % len(self._hits)
        # now finally perform the auto completion
        if self._hits:
            self.delete(0, tk.END)
            self.insert(0, self._hits[self._hit_index])
            self.select_range(self.position, tk.END)

    def handle_keyrelease(self, event):
        """
        Event handler for the keyrelease event on this widget.

        :param event: Tkinter event
        """
        if event.keysym == "BackSpace":
            self.delete(self.index(tk.INSERT), tk.END)
            self.position = self.index(tk.END)
        if event.keysym == "Left":
            if self.position < self.index(tk.END):  # delete the selection
                self.delete(self.position, tk.END)
            else:
                self.position -= 1  # delete one character
                self.delete(self.position, tk.END)
        if event.keysym == "Right":
            self.position = self.index(tk.END)  # go to end (no selection)
        # if event.keysym == "Down":
        #     self.autocomplete(1)  # cycle to next hit
        # if event.keysym == "Up":
        #     self.autocomplete(-1)  # cycle to previous hit
        if event.keysym == "Return":
            self.handle_return(None)
            return
        if len(event.keysym) == 1 or event.keysym in tk_umlauts:
            self.autocomplete()

    def handle_return(self, event):
        """
        Function to bind to the Enter/Return key so if Enter is pressed the selection is cleared.

        :param event: Tkinter event
        """
        self.icursor(tk.END)
        self.selection_clear()

    def config(self, **kwargs):
        """Alias for configure"""
        self.configure(**kwargs)

    def configure(self, **kwargs):
        """Configure widget specific keyword arguments in addition to :class:`ttk.Entry` keyword arguments."""
        if "completevalues" in kwargs:
            self.set_completion_list(kwargs.pop("completevalues"))
        return ttk.Entry.configure(self, **kwargs)

    def cget(self, key):
        """Return value for widget specific keyword arguments"""
        if key == "completevalues":
            return self._completion_list
        return ttk.Entry.cget(self, key)

    def keys(self):
        """Return a list of all resource names of this widget."""
        keys = ttk.Entry.keys(self)
        keys.append("completevalues")
        return keys

    def __setitem__(self, key, value):
        self.configure(**{key: value})

    def __getitem__(self, item):
        return self.cget(item)


######## Main ########


# We use a class to hold global state because:
# - It avoids accidentally re-binding global names locally by shadowing, which plagues the 'global' keyword usage.
# - It avoids namespace collisions that plague the 'root.*' approach.
# - It prevents key typos that plague dictionary key access.
# - It allows simple access via dot notation
# - It is KISS / 'suckless' compared to full OOP.
class g:
    echo = True  # True for normal text, False for password input
    history_len = -1  # skip login username
    history = []
    history_cursor = -1  # skip login username
    send_hello = True
    user = None
    handshake = True
    tls = False
    fingerprint_want = None
    workaround_1849 = True  # https://github.com/eggheads/eggdrop/pull/1849
    certfile = None
    keyfile = None
    host = None
    port = 3333


eggdrop_commands = [  # for autocompletion
    ".who",
    ".away",
    ".quit",
    ".whom",
    ".me",
    ".page",
    ".match",
    ".motd",
    ".bots",
    ".newpass",
    ".chat",
    ".handle",
    ".whoami",
    ".echo",
    ".strip",
    ".su",
    ".trace",
    ".fixcodes",
    ".bottree",
    ".vbottree",
    ".botinfo",
    ".relay",
    ".-host",
    ".fprint",
    ".chfinger",
    ".back",
    ".note",
    ".-account",
    ".addlog",
    ".console",
    ".match",
    ".whois",
    ".resetconsole",
    ".+bot",
    ".botattr",
    ".chhandle",
    ".chpass",
    ".+host",
    ".-bot",
    ".link",
    ".chaddr",
    ".boot",
    ".unlink",
    ".banner",
    ".dccstat",
    ".+account",
    ".chattr",
    ".save",
    ".backup",
    ".reload",
    ".status",
    ".traffic",
    ".uptime",
    ".+user",
    ".+ignore",
    ".comment",
    ".binds",
    ".ignores",
    ".-user",
    ".-ignore",
    ".dccstat",
    ".debug",
    ".rehash",
    ".restart",
    ".module",
    ".die",
    ".simul",
    ".loadmod",
    ".unloadmod",
    ".language",
    ".set",
    ".tcl",
    ".rehelp",
    ".modules",
    ".+lang",
    ".-lang",
    ".+lsec",
    ".-lsec",
    ".lstat",
    ".relang",
    ".ldump",
    ".help",
    ".help all",
    ".tcl pysource",
]


# callback for return key in entry widget, send text from entry to
# socket and update history
def key_return(event):
    s = entry.get()
    sock.send(f"{s}\n".encode())
    entry.delete(0, tk.END)
    if g.echo:
        scrolled_text.configure(state=tk.NORMAL)
        scrolled_text.insert(tk.END, s + "\n")
        scrolled_text.configure(state=tk.DISABLED)
        scrolled_text.see(tk.END)
        if g.history_len > -1:  # skip login username
            g.history.append(s)
        g.history_len += 1
        g.history_cursor = g.history_len


# callback for up key in entry widget, cycle through history buffer
def key_up(event):
    if g.history_cursor > 0:
        g.history_cursor -= 1
        entry.delete(0, tk.END)
        entry.insert(tk.INSERT, g.history[g.history_cursor])
    return


# callback for up key in entry widget, cycle through history buffer
def key_down(event):
    g.history_cursor
    if (g.history_cursor + 1) < g.history_len:
        g.history_cursor += 1
        entry.delete(0, tk.END)
        entry.insert(tk.INSERT, g.history[g.history_cursor])
    return


# callback for tab key in entry widget, disable focus change
def key_tab(event):
    entry.insert(tk.INSERT, "\t")
    return "break"


# like a select() loop, read from socket, write to scrolltext widget, scroll
# to the end
# this is busy polling via root.after(100). we could explore event loop
# integration and threading with tk, but i got it to a point that is good
# enough.
def socketloop():
    alldata = b""
    while True:
        try:
            data = sock.recv(1024)

            # this is working, but "select for write" would be better
            if g.send_hello:
                # send TLN_IAC + TLN_DO + TLN_STATUS so that eggdrop detects telnet and
                # sends telnet control codes like echo on/off so that we can
                # disable echo for password input
                if not g.user:
                    sock.send(b"\xff\xfd\x05")
                if g.user:
                    sock.send(b"\xff\xfd\x05" + f"{g.user}\n".encode())
                    g.history_cursor = 0
                    g.history_len = 0
                g.send_hello = False

            # we must first print alldata, so we raise here, and catch it after we printed alldata
            if not data:
                raise ConnectionError("connection closed")

            alldata += data
        except (BlockingIOError, ssl.SSLWantReadError, ConnectionError) as err:
            if alldata:
                text = statusline.cget("text")
                if g.handshake:
                    if g.tls:
                        cert = sock.getpeercert(True)
                        fingerprint = hashlib.sha256(cert).hexdigest()
                        fingerprint = ":".join(
                            fingerprint[i : i + 2]
                            for i in range(0, len(fingerprint), 2)
                        )
                        fingerprint = fingerprint.upper()
                        if g.fingerprint_want:
                            g.fingerprint_want = g.fingerprint_want.upper()
                            if fingerprint == g.fingerprint_want:
                                statusline.config(
                                    text=f"{text} tls={sock.version()} fingerprint=verified"
                                )
                            else:
                                scrolled_text.configure(state=tk.NORMAL)
                                scrolled_text.insert(
                                    tk.END,
                                    f"got  fingerprint={fingerprint}\nwant fingerprint={g.fingerprint_want}\n",
                                )
                                scrolled_text.configure(state=tk.DISABLED)
                                statusline.config(
                                    text=f"{text} tls={sock.version()} fingerprint=mismatch"
                                )
                                entry.delete(0, tk.END)
                                entry.insert(
                                    tk.INSERT, "Fingerprint mismatch, connection closed"
                                )
                                entry.configure(state="disabled")
                                return
                        else:
                            statusline.config(
                                text=f"{text} tls={sock.version()} fingerprint=not verified"
                            )
                    else:
                        statusline.config(text=f"{text} tls=no")
                    g.handshake = False
                if g.workaround_1849:
                    if (
                        alldata[0] == ord("[")
                        and ord("0") <= alldata[1] <= ord("9")
                        and ord("0") <= alldata[2] <= ord("9")
                        and alldata[3] == ord(":")
                    ):
                        alldata = alldata[4:]
                    g.workaround_1849 = False

                # toggle echo on/off
                index = alldata.find(b"\xff\xfb\x01")  # TLN_IAC + TLN_WILL + TLN_ECHO
                if index > -1:
                    entry.configure(show="*")
                    g.echo = False
                else:
                    index = alldata.find(
                        b"\xff\xfc\x01"
                    )  # TLN_IAC + TLN_WONT + TLN_ECHO
                    if index > -1:
                        entry.configure(show="")
                        g.echo = True

                # remove telnet control codes
                alldata = bytes(
                    c for c in alldata if c not in (0x01, 0x05, 0x0D, 0xFB, 0xFC, 0xFF)
                )

                # enable the following line for debug
                # print("alldata:", alldata.hex())
                bold = False
                for text in alldata.decode().split("\x1b\x5b"):  # telnet escape code
                    if text.startswith("\x30\x6d"):
                        bold = False
                        text = text[2:]
                    elif text.startswith("\x31\x6d"):
                        bold = True
                        text = text[2:]
                    scrolled_text.configure(state=tk.NORMAL)
                    if not bold:
                        scrolled_text.insert(tk.END, text)
                    else:
                        scrolled_text.insert(tk.END, text, "bold")
                    scrolled_text.configure(state=tk.DISABLED)
                scrolled_text.see(tk.END)
            if isinstance(err, ConnectionError):
                entry.delete(0, tk.END)
                entry.configure(show="")
                entry.insert(tk.INSERT, "Connection closed")
                entry.configure(state="disabled")
                return
            break
    root.after(100, socketloop)


# getopt

try:
    opts, args = getopt.getopt(
        sys.argv[1:],
        "p:c:k:f:l:hv",
        ["port=", "cert=", "key=", "fingerprint=", "user=", "help", "version"],
    )
except getopt.GetoptError as e:
    print(f"{e}\nTry '{sys.argv[0]} --help' for more information.", file=sys.stderr)
    sys.exit(1)  # EXIT_FAILURE

for opt, arg in opts:
    if opt in ("-p", "--port"):
        if arg.startswith("+"):
            g.tls = True
            g.port = int(arg[1:])
        else:
            g.port = int(arg)
    elif opt in ("-c", "--cert"):
        g.certfile = arg
    elif opt in ("-k", "--key"):
        g.keyfile = arg
    elif opt in ("-f", "--fingerprint"):
        g.fingerprint_want = arg
    elif opt in ("-l", "--user"):
        g.user = arg
    elif opt in ("-h", "--help"):
        print(
            f"Usage: {sys.argv[0]} [OPTION]... HOST\n"
            "\n"
            "  -p, --port=PORT        port\n"
            "                         default 3333\n"
            "                         prefix with + to enable TLS\n"
            "  -c, --cert=FILE        use CertFP with TLS certificate FILE\n"
            "  -k, --key=FILE         use CertFP with TLS key FILE\n"
            "  -f, --fingerprint=HASH use certificate pinning\n"
            "                         verify eggdrop cert fingerprint equals sha256 HASH\n"
            "                         e.g.: DE:AD:BE:EF:DE:AD:BE:EF:DE:AD:BE:EF:DE:AD:BE:EF:DE:AD:BE:EF:DE:AD:BE:EF:DE:AD:BE:EF:DE:AD:BE:EF\n"
            "                         see: openssl x509 -in eggdrop.crt -noout -fingerprint -sha256\n"
            "  -l, --user=USER        attempt automatic login as USER\n"
            "  -h, --help             display this help and exit\n"
            "  -v, --version          output version information and exit"
        )
        sys.exit()
    elif opt in ("-v", "--version"):
        print(
            "pefero eggdrop telnet client\n"
            "SPDX-License-Identifier: MIT\n"
            "Copyright (c) 2025 Michael Ortmann\n"
            "https://codeberg.org/mortmann/pefero"
        )
        sys.exit()

if len(args) == 0:
    print(
        f"missing host\nTry '{sys.argv[0]} --help' for more information.",
        file=sys.stderr,
    )
    sys.exit(1)  # EXIT_FAILURE

g.host = args[0]

# init unblocking io sock

try:
    sock = socket.create_connection((g.host, g.port))
except Exception as e:
    print(f"Error: {e}: host={g.host} port={g.port}", file=sys.stderr)
    sys.exit(1)  # EXIT_FAILURE

sock.setblocking(False)

if g.tls:
    context = ssl.create_default_context()

    # accept self signed cert
    context.check_hostname = False
    context.verify_mode = ssl.CERT_NONE

    if g.certfile and g.keyfile:
        context.load_cert_chain(certfile=g.certfile, keyfile=g.keyfile)
    sock = context.wrap_socket(
        sock, server_hostname=g.host, do_handshake_on_connect=False
    )
    sock.setblocking(False)

# init tk gui, 3 widgets, top ScrolledText, middle statusline Label, bottom AutocompleteEntry

root = tk.Tk()
icon = "iVBORw0KGgoAAAANSUhEUgAAACAAAAAgCAMAAABEpIrGAAAAAXNSR0IB2cksfwAAAARnQU1BAACxjwv8YQUAAAAgY0hSTQAAeiYAAICEAAD6AAAAgOgAAHUwAADqYAAAOpgAABdwnLpRPAAAAq9QTFRFAAAAAAAAAAAAra2tCIS9Y1JKxs7W9+/vraWtAIS1paWlOYS1nKWc77WlSnOUY2NaSlpzQoStKTlCrYx7vb3GpYxzvbXG772U77WUhHuE57WMzr3GCIzGGCExe3t7Qmt7EAgIQlJavb21c2tzKSExCAgAWnOt1tbeQjE5Unulva21CAAA1s7etbWta2trUnOlhHtzta2ta2NrEIS9597eAIStWmNaOYStIYS9CHvWOVpra4R7nKWUUnuUAHvOUlpzSmuMlIRrQoSlMTFCQlpjxq2c97WUOWN7AITeOUpaOTk5762MOTE5EITGMUpSSmt7GBAIMUJSMTExSlJaEBAA3t7elJScSjk5KSkpIYTGEAAAjJSUITEhQjkxvbWtKSEpQkJSjHtz7/f/GIS9vZyM1s7Wa2tj797ehHtrzsbOKYS9KSkYIYS1vca9KSEYWnOUc2NaWlpzY2uMCHu9AIzWAITWpZylOTExnJycUlJaCAgYGCEhnJScMUJKSlJSKYTGSnu1e2tr9///Y1palIyUSkJSlHtzjJSMKSEhjIyMQkJK7/f3pZyUztbGzs7GhISEhHNjGCEQMYS9zsbG5+fve4R7KYS1QkI5WmuM1rWcUlpjnJyl5+fezqWU57WcY2uECITWAIzOWmt7EBAYAITOOXutWlJaEAgYITE5CAgQMYTGABAInJSUMUJC////tbW9ISE5IRAYe4SESnutlJSMSkpKAAAISjkplIyM9/f3Y2NzrZyUxr29AIy9AIS91s7G7+/vpaWtOYS97+fvACEY5+fnQnuUQoS1KXvO3rWcc2NKpYx71q2UEHu1zqWMCIzOGBAYCITOEBgQKXu9xr3GKTk5AIzGWmtzEBAQAITGEAgQvb29KSk5ITExvbW9a3NzABAAUnutUkpKtbW1a2tz8lVRDQAAAAF0Uk5TAEDm2GYAAAABYktHRACIBR1IAAAACXBIWXMAAAsTAAALEwEAmpwYAAAAB3RJTUUH6QoVFhYE07bx6gAAAYlJREFUGBl9wTFr20AYBuD3Q/QitGRJsph48HJFNIaWkincmjmEazfT5QKmoxYbOnqoIOAWa6t+w4uHDj3wYA+3FLx5dpf+kEYlTS3JzvOgTm3cCM9JVcAzrNs4h8OcXZK0Dge4ZcG/FPZyReAjhX1C4JOANh2WHA40H6jvU40WrcJZKOyQ9IUPW7Rsh+mxiNymzEW+iggaUhFNMpFI+GCYoGYs3ZFlZSEjVsaokfhWCrJLUnL6Y1JQczVMup68Im3+mZU+GgbpGSsf/PYdySRGw+DocktyGpPJ+7QvaFKanfFNP7CiVECTU9xh0aYK/ufQ5hSfeIs9XOA/DnsFVjypccCrO/kikbU4aPrx9PTnXGG/4P1cTV6O1BsgWI2G34EsX/S6v6JodqlIWtScnJCMs3Ppda8zE5O0qFl5knNjPnUuMmMmJB1qVt90ebQ2a93z58bclGq+wo6Omo7XJsuyu9Dr5NeZMVkeYUcIYaMv8smPRYCbDe7v4+Q1GqxeYFYCKAG48i0e/QGeSM/RGAvf9wAAAABJRU5ErkJggg=="
photo_image = tk.PhotoImage(data=icon)
root.iconphoto(False, photo_image)
root.title(f"pefero {g.host} {g.port}")

# define a normal and bold monospace font
font_normal = font.nametofont("TkFixedFont")
font_normal.configure(size=12)
font_bold = font.Font(
    family=font_normal.cget("family"), size=font_normal.cget("size"), weight=font.BOLD
)

entry = AutocompleteEntry(
    root, textvariable=tk.StringVar(), font=font_normal, completevalues=eggdrop_commands
)
entry.pack(fill=tk.X, side=tk.BOTTOM)
entry.bind("<Return>", key_return)
entry.bind("<Up>", key_up)
entry.bind("<Down>", key_down)
entry.bind("<Tab>", key_tab)
entry.focus()

statusline = ttk.Label(
    root, text=f"connection: host={g.host} port={g.port}", font=font_normal
)
statusline.pack(fill=tk.X, side=tk.BOTTOM)

scrolled_text = scrolledtext.ScrolledText(root, font=font_normal, state=tk.DISABLED)
scrolled_text.pack(fill=tk.BOTH, expand=True)
scrolled_text.tag_configure("bold", font=font_bold)

root.after(10, socketloop)
root.mainloop()
