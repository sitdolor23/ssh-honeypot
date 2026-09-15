# SPDX-FileCopyrightText: 2014 Upi Tamminen <desaster@gmail.com>
# SPDX-FileCopyrightText: 2014-2026 Michel Oosterhof <michel@oosterhof.net>
#
# SPDX-License-Identifier: BSD-3-Clause
from __future__ import annotations
import re
import shlex
import socket
import time
import posixpath
from datetime import datetime, timezone
from typing import TYPE_CHECKING
from twisted.conch import recvline
from twisted.conch.insults import insults
from twisted.internet import defer, error
from twisted.logger import Logger
from twisted.protocols.policies import TimeoutMixin
from twisted.python import failure
from cowrie.core.config import CowrieConfig
from cowrie.llm.llm import LLMClient
if TYPE_CHECKING:
    from cowrie.core.events import EventLog
def strip_markdown(text: str) -> str:
    """
    Remove markdown code block formatting from LLM responses.
    """
    # Remove ```language\n...\n``` blocks, keeping the content
    text = re.sub(r"```\w*\n?", "", text)
    # Remove any remaining backticks
    text = text.replace("`", "")
    return text.strip()
# Matches a fake shell prompt (e.g. 'student@svr04:/path$ ' or 'svr04:/path# ')
# ANYWHERE in the text, not just alone on its own line — models frequently
# hallucinate a whole fake prompt+command+prompt transcript inline rather
# than emitting only the command's output.
_PROMPT_INLINE_RE = re.compile(r"\S+@\S+:[^\s$#]*[#$]\s*")
_PROMPT_INLINE_RE2 = re.compile(r"(?<!\S)\S+:[^\s$#]*[#$]\s*")
def strip_fake_prompt(text: str, command: str = "") -> str:
    """
    Remove hallucinated shell prompts and, if present, a leading echo of the
    command itself, that the LLM sometimes includes in its own response
    instead of returning only the command's real output.
    """
    text = _PROMPT_INLINE_RE.sub("", text)
    text = _PROMPT_INLINE_RE2.sub("", text)
    lines = [ln.strip() for ln in text.split("\n") if ln.strip()]
    # Drop a leading line that's just an echo of the command we sent —
    # some models narrate "ran your command" instead of showing output.
    if lines and command and lines[0].lower() == command.strip().lower():
        lines = lines[1:]
    return "\n".join(lines).strip()
# Patterns commonly used in prompt injection attempts against LLM-backed
# systems. Matched before input ever reaches the LLM, so an attacker cannot
# use natural-language instructions to override the shell simulation.
INJECTION_PATTERNS = [
    r"ignore (all )?(previous|prior) instructions",
    r"forget (all )?(previous|prior)? ?instructions",
    r"forget everything",
    r"disregard (all )?(previous|prior) instructions",
    r"you are now",
    r"new instructions?:",
    r"system prompt",
    r"act as (a|an)?",
    r"pretend (you are|to be)",
    r"stop (simulating|pretending|being)",
    r"break character",
    r"reveal (your|the) (system )?prompt",
    r"what (are|is) your (instructions|system prompt)",
]
class HoneyPotBaseProtocol(insults.TerminalProtocol, TimeoutMixin):
    """
    Base protocol for interactive and non-interactive use
    """
    _log = Logger()
    # The session's event emitter, set from the transport in connectionMade.
    events: EventLog
    def __init__(self, avatar):
        self.user = avatar
        self.environ = avatar.environ
        self.hostname: str = self.user.server.hostname
        self.pp = None
        self.logintime: float
        self.realClientIP: str
        self.realClientPort: int
        self.kippoIP: str
        self.kippoIPv6: str = ""
        self.clientIP: str
        self.sessionno: int
        self.factory = None
        self.cwd = "/"
        self.fs_cache: dict[tuple[str, str], str] = {}
        self.data = None
        self.password_input = False
        # Lightweight, session-local tracking of paths *this session* has
        # created or removed via touch/mkdir/rm — NOT a full pre-made
        # filesystem tree. Values: "file", "dir", or "deleted". Anything
        # not in here is unknown and left entirely to the LLM to invent,
        # same as before.
        self._local_paths: dict[str, str] = {}
        self._last_command_sent = ""
        # True while an LLM call is in flight. A real shell doesn't read
        # your next line until the current command finishes, so without
        # this, typing ahead while a slow LLM response is pending lets the
        # async write land in the middle of whatever you're currently
        # typing — that's what corrupted 'cd' into 'ccd' and glued
        # 'whoami; pwd; date' onto the front of an unrelated 'env' response.
        self._command_pending = False
        # Input (characters and Enter presses) that arrived while
        # _command_pending was True, queued instead of dropped so a burst
        # of several commands sent without waiting for each prompt (common
        # for scripted/automated clients) doesn't lose everything after
        # the first. Replayed by _drain_queued_input once we're free again.
        self._queued_input: list[tuple] = []
        self._MAX_QUEUED_INPUT = 4096
        # Best-effort per-directory listing cache. Populated lazily the
        # first time 'ls' is run somewhere (seeded from whatever the LLM
        # invents), then kept in sync locally by touch/mkdir/rm so files
        # created/removed this session actually show up — without this,
        # 'ls' has no idea those commands ran at all, since they bypass
        # the LLM entirely. Directories never seeded stay fully
        # LLM-invented, same as before.
        self._dir_listing_cache: dict[str, list[str]] = {}
        self._pending_ls_dir: str | None = None
        # Whether the in-flight/most recent pending 'ls' request for
        # _pending_ls_dir included -a/-A, so '.' and '..' can be added
        # back in at display time. They're deliberately never stored
        # inside _dir_listing_cache itself (see _parse_ls_names) since
        # they're not real per-directory state — a plain 'ls' right
        # after 'ls -a' in the same directory must NOT show them.
        self._pending_ls_show_all: bool = False
        # Directories where a blank 'ls' response has already triggered
        # one silent retry this session (see _retry_ls) — capped at one
        # retry per directory so a model that keeps returning nothing
        # can't loop forever.
        self._ls_retried: set[str] = set()
    def getProtoTransport(self):
        """
        Due to protocol nesting differences, we need provide how we grab
        the proper transport to access underlying SSH information. Meant to be
        overridden for other protocols.
        """
        return self.terminal.transport.session.conn.transport
    def connectionMade(self) -> None:
        pt = self.getProtoTransport()
        self.factory = pt.factory
        # The session's event emitter, owned by the transport. Kept across
        # connectionLost so work that outlives the session can still emit an
        # attributed, late-flagged event.
        self.events = pt.events
        self.sessionno = pt.transport.sessionno
        self.realClientIP = pt.transport.getPeer().host
        self.realClientPort = pt.transport.getPeer().port
        self.logintime = time.time()
        # 180s was cutting real sessions short (observed an auto-logout
        # after only two quick 'ls' round-trips during testing); 300s
        # gives slower/manual attacker interaction more realistic room
        # before disconnecting. Still fully configurable via cowrie.cfg.
        timeout = CowrieConfig.getint("honeypot", "interactive_timeout", fallback=300)
        self.setTimeout(timeout)
        # Source IP of client in user visible reports (can be fake or real)
        self.clientIP = CowrieConfig.get(
            "honeypot", "fake_addr", fallback=self.realClientIP
        )
        # Source IP of server in user visible reports (can be fake or real)
        if CowrieConfig.has_option("honeypot", "internet_facing_ip"):
            self.kippoIP = CowrieConfig.get("honeypot", "internet_facing_ip")
        else:
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_DGRAM) as s:
                    s.connect(("8.8.8.8", 80))
                    self.kippoIP = s.getsockname()[0]
            except OSError:
                self.kippoIP = "192.168.0.1"
        # IPv6 GUA of server in user visible reports (can be fake or real)
        if CowrieConfig.has_option("honeypot", "internet_facing_ipv6"):
            self.kippoIPv6 = CowrieConfig.get("honeypot", "internet_facing_ipv6")
        else:
            try:
                with socket.socket(socket.AF_INET6, socket.SOCK_DGRAM) as s:
                    s.connect(
                        ("2001:4860:4860::8888", 80)
                    )  # NOSONAR - probe target to detect host GUA, not a secret
                    addr = s.getsockname()[0]
                    # Only use GUA, not link-local
                    self.kippoIPv6 = addr if not addr.lower().startswith("fe80") else ""
            except Exception:
                self.kippoIPv6 = ""
    def timeoutConnection(self) -> None:
        """
        this logs out when connection times out
        """
        ret = failure.Failure(error.ProcessTerminated(exitCode=1))
        self.terminal.transport.processEnded(ret)
    def connectionLost(self, reason):
        """
        Called when the connection is shut down.
        Clear any circular references here, and any external references to
        this Protocol. The connection has been closed.
        """
        self.setTimeout(None)
        insults.TerminalProtocol.connectionLost(self, reason)
        self.terminal = None  # (this should be done by super above)
        self.pp = None
        self.user = None
        self.environ = None
    def lineReceived(self, line: bytes) -> None:
        """
        IMPORTANT
        Before this, all data is 'bytes'. Here it converts to 'string' and
        commands work with string rather than bytes.
        """
        string = line.decode("utf8")
        self.events.dispatch("cowrie.command.input", "CMD: %(input)s", input=string)
        stripped = string.strip()
        # Handle 'exit'/'logout' locally so the connection actually closes,
        # instead of sending it to the LLM (which would just hallucinate a
        # response and leave the session hanging open).
        if stripped in ("exit", "logout"):
            if self.terminal is not None:
                self.terminal.loseConnection()
            return
        # 'cd'/'touch'/'mkdir'/'rm' are handled locally so they're silent on
        # success (like the real commands) and 'cd' can't land on something
        # this session already knows isn't a directory. This is NOT a full
        # pre-made filesystem — it only tracks paths this session itself
        # touched, so it can't catch every inconsistency the LLM invents.
        # 'pwd'/'whoami'/'hostname'/'id'/'uname' (common forms) are also
        # answered locally here: they're fully deterministic from data we
        # already have (username, hostname, configured kernel/OS strings),
        # so answering instantly both guarantees a correct, consistent
        # answer and avoids the multi-second LLM round-trip every other
        # command pays — a real shell answers these near-instantly, so
        # routing them through the LLM anyway was itself a subtle
        # behavioral tell (every single command taking the same couple of
        # seconds regardless of how trivial it is).
        if self._try_local_command(stripped):
            return
        # Likewise, 'cat' on a path this session knows about is answered
        # locally (empty for a touch'd file, error for something removed)
        # instead of letting the LLM hallucinate content or a "not found"
        # for a file it has no way of knowing was just created.
        if self._try_local_cat(stripped):
            return
        # Detect obvious prompt injection attempts and treat them as an
        # unrecognized command, rather than letting them reach the LLM.
        lowered = stripped.lower()
        if any(re.search(pattern, lowered) for pattern in INJECTION_PATTERNS):
            if self.terminal is not None:
                self.terminal.write(f"-bash: {stripped}: command not found\n".encode())
            self._show_prompt()
            return
        # Use LLM client to get a response
        self._process_command_with_llm(string)
    def _write(self, text: str) -> None:
        if self.terminal is not None:
            self.terminal.write(text.encode("utf-8"))
    def _home_dir(self) -> str:
        username = getattr(self.user, "username", "") if self.user else ""
        if username == "root":
            return "/root"
        return f"/home/{username}" if username else "/"
    def _writable_by_current_user(self, path: str) -> bool:
        """
        Rough (not a full permission model) stand-in for what a non-root
        login could actually create/delete/modify on a real system: their
        own home directory, and '/tmp'. Root can write anywhere. Nothing
        was checking this before -- confirmed live that a non-root login
        could 'rm /etc/passwd' or 'mkdir /etc' with no pushback at all,
        which no real Linux system would ever allow.
        """
        if self.user.username == "root":
            return True
        home = self._home_dir()
        return (
            path == home
            or path.startswith(home + "/")
            or path == "/tmp"
            or path.startswith("/tmp/")
        )
    def _resolve_path(self, arg: str) -> str:
        if not arg or arg == "~":
            return self._home_dir()
        if arg.startswith("~/"):
            arg = posixpath.join(self._home_dir(), arg[2:])
        if not arg.startswith("/"):
            arg = posixpath.join(self.cwd, arg)
        return posixpath.normpath(arg)
    def _sync_dir_cache(self, path: str, status: str) -> None:
        """
        If the parent directory of `path` already has a seeded ls cache
        (i.e. 'ls' has been run there before), update it immediately so a
        touch/mkdir/rm is visible on the very next ls, not just the first
        one ever run in that directory.
        """
        parent, base = posixpath.split(path)
        names = self._dir_listing_cache.get(parent)
        if names is None:
            return
        if status == "deleted":
            if base in names:
                names.remove(base)
        elif base not in names:
            names.append(base)
    # Matches both 'total 123' (block count) and 'total 40K' / 'total 1.2M'
    # (the -h human-readable form) — without the unit suffix, a header like
    # 'total 40K' wasn't recognized at all and 'total'/'40K' leaked through
    # as fake filenames.
    _LS_TOTAL_RE = re.compile(r"^total\s+[\d.]+[kmgtKMGT]?$", re.IGNORECASE)
    # First column of an 'ls -l' style line: d=dir, l=symlink, -=regular
    # file, b/c=block/char device, p=FIFO, s=socket. Missing b/c/p/s meant
    # device-node lines (e.g. 'crw-r----- 1 root tty 4, 1 Aug 17 18:27
    # console' under /dev) fell through to naive whitespace splitting,
    # exploding permissions/major-minor numbers/dates into fake filenames.
    _LS_DASHL_RE = re.compile(r"^[dlbcps\-][rwxst\-]{9}\s")
    _LS_ERROR_RE = re.compile(
        r"permission denied|no such file or directory|cannot access|not a directory",
        re.IGNORECASE,
    )
    # Catch-all sanity check applied after slash-stripping: a real filename
    # is letters/digits with common punctuation (. _ - + ~) in the middle,
    # optionally one leading dot for a hidden file. This rejects whatever
    # symbol-soup the model emits instead of real content (observed: a
    # whole 'ls' response of just ':";') without needing to special-case
    # every garbage pattern individually.
    _PLAUSIBLE_NAME_RE = re.compile(r"^\.?[A-Za-z0-9](?:[A-Za-z0-9._+~-]*[A-Za-z0-9])?$")
    # A bare 'ls -l' permission-bits string (e.g. 'lrwxrwxrwx',
    # 'drwxr-xr-x') showing up as a standalone token rather than at the
    # start of a proper -l formatted line (already handled by
    # _LS_DASHL_RE) — observed leaking through as if it were a filename
    # when the model mixes -l-style fragments into an otherwise
    # plain, space-separated listing.
    _LS_PERM_BITS_RE = re.compile(r"^[dlbcps\-][rwxst\-]{9}$")
    # Bare shell command/builtin names (and a couple of narration words)
    # the model sometimes echoes back instead of returning only real
    # directory contents — e.g. narrating "here's the output of `ls -l`"
    # or leaking the typed flag verbatim into the listing (observed: a
    # '/etc' listing that included literal 'ls' and '-l' as if they were
    # files). None of these are ever themselves plausible entries in a
    # real listing, so they're filtered as noise regardless of which
    # parsing branch encounters them.
    _LS_COMMAND_WORDS = frozenset(
        {
            "ls", "cd", "cat", "pwd", "cp", "mv", "rm", "mkdir", "rmdir",
            "touch", "sudo", "echo", "grep", "find", "chmod", "chown",
            "exit", "logout", "clear", "history", "whoami", "uname", "date",
            "head", "tail", "less", "more", "man", "which", "ps", "kill",
            "curl", "wget", "ssh", "scp", "vim", "vi", "nano", "output",
        }
    )
    # The model is told to include these in every '/' listing, but doesn't
    # always comply. These are the same on every real Linux install, so
    # rather than keep re-asking the model to remember them, guarantee
    # they're present whenever '/' gets cached, merged with whatever else
    # the model contributed.
    _STANDARD_ROOT_DIRS = (
        "bin", "boot", "dev", "etc", "home", "lib", "lib64", "media", "mnt",
        "opt", "proc", "root", "run", "sbin", "srv", "sys", "tmp", "usr",
        "var",
    )
    # The model reliably invents this exact personal-desktop folder set
    # (or a subset of it) for directories that have nothing to do with a
    # user's home — /media was observed returning this verbatim, identical
    # to /home/<user>. Prompt wording alone ("don't reuse another
    # directory's listing") isn't a hard guarantee, so this is enforced
    # deterministically wherever a listing is accepted, same pattern as
    # the '/home' override just above.
    _PERSONAL_FOLDER_NAMES = frozenset(
        {"Desktop", "Documents", "Downloads", "Music", "Pictures", "Videos", ".ssh"}
    )
    # Fixed contents for directories that either have to be empty (mount
    # points) or are hit so often, and were the source of so many
    # cross-directory-contradiction bugs (root-dir-name leakage,
    # personal-folder leakage, even an unrelated Debian 7 "wheezy" file
    # showing up under a Debian 12 system), that generating them via the
    # LLM every session just isn't worth the risk. '/etc' in particular
    # was the site of most of the listing bugs found during testing --
    # unlike '/home/<user>', a real '/etc' looks basically the same on
    # every install regardless of username, so there's no personalization
    # value being given up by fixing it. Never sent to the LLM at all --
    # same "don't trust the model, just decide" approach already used for
    # '/home' and the standard root directories.
    _DETERMINISTIC_LISTINGS = {
        "/media": (),
        "/mnt": (),
        "/etc": (
            "adduser.conf", "alternatives", "apache2", "apt", "bash.bashrc",
            "ca-certificates", "cron.d", "cron.daily", "crontab", "dpkg",
            "fstab", "group", "hostname", "hosts", "hosts.allow",
            "hosts.deny", "init.d", "issue", "logrotate.d", "machine-id",
            "mysql", "network", "nginx", "nsswitch.conf", "passwd",
            "profile", "resolv.conf", "rsyslog.conf", "security",
            "services", "shadow", "skel", "ssh", "ssl", "sudoers",
            "sudoers.d", "sysctl.conf", "systemd", "timezone", "udev",
            "update-motd.d",
        ),
        # Non-PID entries only -- these are identical on every real Linux
        # system regardless of what's actually running, unlike the
        # numbered PID directories (which would need to line up with
        # whatever 'ps aux' claims is running to be worth simulating, not
        # attempted here). This is the fix for the '/proc' gibberish
        # ('fsnergy' and similar) flagged early in testing and never
        # resolved until now.
        "/proc": (
            "1", "self", "acpi", "buddyinfo", "bus", "cgroups", "cmdline",
            "consoles", "cpuinfo", "crypto", "devices", "diskstats", "dma",
            "driver", "execdomains", "filesystems", "fs", "interrupts",
            "iomem", "ioports", "irq", "kallsyms", "kmsg", "loadavg",
            "locks", "meminfo", "misc", "modules", "mounts", "mtrr", "net",
            "partitions", "sched_debug", "scsi", "slabinfo", "stat",
            "swaps", "sys", "sysrq-trigger", "sysvipc", "thread-self",
            "timer_list", "tty", "uptime", "version", "vmstat", "zoneinfo",
        ),
        # The complete standard set on any real Linux install -- this is
        # the fix for the '/sys' truncated-word bug ('machi' and similar)
        # flagged early in testing and never resolved until now.
        "/sys": (
            "block", "bus", "class", "dev", "devices", "firmware", "fs",
            "kernel", "module", "power",
        ),
        "/var": (
            "backups", "cache", "lib", "local", "lock", "log", "mail",
            "opt", "run", "spool", "tmp", "www",
        ),
    }
    def _personal_folders_allowed(self, directory: str) -> bool:
        """
        True only for the directories a real Linux system would plausibly
        show Desktop/Documents/Downloads/Music/Pictures/Videos-style
        folders in: the logged-in user's own home directory (or something
        under it), /root, or /tmp. Everywhere else -- especially /media,
        /mnt, and any system directory -- these names are never legitimate
        and get filtered out of a listing if the model produces them.
        """
        home_dir = f"/home/{self.user.username}"
        return (
            directory == home_dir
            or directory.startswith(home_dir + "/")
            or directory in ("/root", "/tmp")
            or directory.startswith("/root/")
            or directory.startswith("/tmp/")
        )
    def _apply_deterministic_listing_overrides(self, directory, names, confidently_empty):
        """
        Applies every deterministic correction to a raw, freshly LLM-parsed
        (or probed) list of directory entries before it's accepted as
        `directory`'s listing. Shared by the live 'ls' path
        (_handle_llm_response) and the silent 'cd' validation probe
        (_probe_dir_listing) so a new rule only ever needs to be added
        once -- exactly the kind of divergence that let '/media' end up
        serving '/home's listing in the first place (the '/home' override
        used to exist in both places independently; a later general rule
        easily could've been added to only one, same as almost happened
        here with root-name leakage).

        Currently enforces three things the model has been observed getting
        wrong despite prompt instructions saying otherwise: personal
        folders (Desktop/Documents/.ssh/...) showing up outside a real home
        directory, the standard root-level names (bin/boot/dev/...) being
        reused as if they were some other directory's own contents
        (observed for '/opt', in addition to the earlier '/media' case),
        and the logged-in username itself appearing as a bare top-level
        entry somewhere other than under '/home' (observed: 'test1'
        showing up directly in '/' alongside real system directories).

        Returns (names, confidently_empty) -- confidently_empty may flip
        to True if filtering removed everything the model returned; that's
        treated as a legitimate empty-directory answer rather than an
        ambiguous parse miss, since retrying would almost certainly just
        reproduce the same invented content.
        """
        if directory == "/home":
            return [self.user.username], confidently_empty
        filtered = names
        if not self._personal_folders_allowed(directory):
            filtered = [n for n in filtered if n not in self._PERSONAL_FOLDER_NAMES]
        # The username itself is only ever a valid *entry name* directly
        # under '/home' (handled above, forced to exactly that). Seeing it
        # as a bare top-level name anywhere else is always wrong.
        filtered = [n for n in filtered if n != self.user.username]
        if directory != "/":
            filtered = [n for n in filtered if n not in self._STANDARD_ROOT_DIRS]
        if names and not filtered and not confidently_empty:
            confidently_empty = True
        return filtered, confidently_empty
    def _is_noise_token(self, tok: str) -> bool:
        """
        True if `tok` is clearly not a real filename fragment: a flag, a
        bare number, a '.'/'..' entry, a path fragment, a size/total
        header word, or a shell command/builtin name the model echoed
        instead of real output. Shared by every parsing branch in
        _parse_ls_names so the '-l' style branch can't let through a
        class of garbage the plain-token branch already knows to reject
        (this used to be the case: '-l' style lines took their last
        field unfiltered, which is how flag/command fragments on a
        mangled line ended up displayed as if they were files).
        """
        if not tok or tok.startswith("-"):
            return True
        if tok.isdigit():
            return True
        # '.' / '..' are only meaningful under 'ls -a', and they're
        # re-added separately (see _handle_llm_response /
        # _try_local_command) based on whether -a was actually passed —
        # never cache them as ordinary entries here.
        if tok in (".", ".."):
            return True
        # A token that still contains '/' after stripping leading/
        # trailing slashes is a fragment of a whole path (e.g.
        # 'boot/vmlinuz-...', or a symlink target like 'usr/lib'), never
        # a single real filename a plain 'ls' would emit on its own.
        if "/" in tok.strip("/"):
            return True
        if tok.lower() == "total" or tok.lower() in self._LS_COMMAND_WORDS:
            return True
        if self._LS_PERM_BITS_RE.match(tok):
            return True
        # A human-readable size figure like '40K'/'1.2M' mixed in among
        # other tokens on the same line rather than on its own
        # 'total 40K' line — _LS_TOTAL_RE only catches the latter.
        if re.fullmatch(r"[\d.]+[kmgtKMGT]", tok):
            return True
        return False
    def _parse_ls_names(self, text: str) -> list:
        """
        Best-effort extraction of filenames from an LLM-generated 'ls'
        response. Model formatting varies (space-separated, one per line,
        or -l style with a permission string prefix), so this is
        heuristic, not exact.
        """
        tokens = []
        for line in text.split("\n"):
            line = line.strip()
            if not line or self._LS_TOTAL_RE.match(line):
                continue
            if self._LS_DASHL_RE.match(line):
                # -l style: permissions/owner/size columns, filename is the
                # last whitespace-separated field on the line (or, for a
                # symlink, the target after '->'). Run it through the same
                # noise filter as every other token instead of taking it
                # unconditionally — a mangled line matching this prefix
                # shouldn't get a free pass for its trailing field.
                parts = line.split()
                if parts and not self._is_noise_token(parts[-1]):
                    tokens.append(parts[-1])
                continue
            for tok in line.split():
                if self._is_noise_token(tok):
                    continue
                tokens.append(tok)
        names = []
        seen = set()
        for tok in tokens:
            # strip (not just rstrip) so a model-prefixed '/home' collapses
            # onto the same entry as a bare 'home' instead of appearing as
            # two separate, duplicate-looking names.
            name = tok.strip("/")
            if not name or name in seen:
                continue
            if not self._PLAUSIBLE_NAME_RE.match(name):
                continue
            seen.add(name)
            names.append(name)
        return names
    # ---- Fixed hardware/OS profile -------------------------------------
    # A handful of recon commands (nproc, free, df, lscpu, /proc/cpuinfo,
    # /proc/meminfo, /etc/os-release, lsb_release, bash --version) each
    # describe the same underlying "machine" from a different angle.
    # Scripted attackers/loaders sometimes cross-check one against another
    # (e.g. does 'nproc' agree with /proc/cpuinfo's core count) -- left to
    # the LLM independently per command, nothing guarantees agreement even
    # within one session. These are all derived from a few cowrie.cfg
    # values (or built-in fallbacks matching the Debian 12/x86_64 profile
    # already fixed via kernel_version/ssh_version), so every one of these
    # commands tells the same consistent story.
    def _cpu_cores(self) -> int:
        return CowrieConfig.getint("shell", "cpu_cores", fallback=4)
    def _cpu_model(self) -> str:
        return CowrieConfig.get(
            "shell", "cpu_model", fallback="Intel(R) Xeon(R) CPU E5-2670 v3 @ 2.30GHz"
        )
    def _cpu_mhz(self) -> str:
        return CowrieConfig.get("shell", "cpu_mhz", fallback="2300.000")
    def _mem_total_kb(self) -> int:
        return CowrieConfig.getint("shell", "mem_total_kb", fallback=8137368)
    def _disk_profile(self):
        return (
            CowrieConfig.get("shell", "disk_total", fallback="20G"),
            CowrieConfig.get("shell", "disk_used", fallback="8.1G"),
            CowrieConfig.get("shell", "disk_avail", fallback="11G"),
            CowrieConfig.get("shell", "disk_use_pct", fallback="44%"),
        )
    def _bash_version(self) -> str:
        return CowrieConfig.get("shell", "bash_version", fallback="5.2.15(1)-release")
    def _proc_cpuinfo_text(self) -> str:
        cores = self._cpu_cores()
        model = self._cpu_model()
        mhz = self._cpu_mhz()
        try:
            bogomips = f"{float(mhz) * 2:.2f}"
        except ValueError:
            bogomips = "4600.00"
        flags = (
            "fpu vme de pse tsc msr pae mce cx8 apic sep mtrr pge mca cmov pat "
            "pse36 clflush mmx fxsr sse sse2 ss ht syscall nx pdpe1gb rdtscp lm "
            "constant_tsc rep_good nopl xtopology nonstop_tsc pni pclmulqdq "
            "ssse3 fma cx16 sse4_1 sse4_2 x2apic movbe popcnt aes xsave avx f16c "
            "rdrand hypervisor lahf_lm abm invpcid_single ssbd ibrs ibpb stibp "
            "fsgsbase bmi1 avx2 smep bmi2 erms invpcid xsaveopt"
        )
        blocks = []
        for i in range(cores):
            blocks.append(
                f"processor\t: {i}\n"
                f"vendor_id\t: GenuineIntel\n"
                f"cpu family\t: 6\n"
                f"model\t\t: 63\n"
                f"model name\t: {model}\n"
                f"stepping\t: 2\n"
                f"microcode\t: 0x1\n"
                f"cpu MHz\t\t: {mhz}\n"
                f"cache size\t: 30720 KB\n"
                f"physical id\t: 0\n"
                f"siblings\t: {cores}\n"
                f"core id\t\t: {i}\n"
                f"cpu cores\t: {cores}\n"
                f"apicid\t\t: {i}\n"
                f"initial apicid\t: {i}\n"
                f"fpu\t\t: yes\n"
                f"fpu_exception\t: yes\n"
                f"cpuid level\t: 20\n"
                f"wp\t\t: yes\n"
                f"flags\t\t: {flags}\n"
                f"bogomips\t: {bogomips}\n"
                f"clflush size\t: 64\n"
                f"cache_alignment\t: 64\n"
                f"address sizes\t: 46 bits physical, 48 bits virtual\n"
                f"power management:\n"
            )
        return "\n".join(blocks).rstrip("\n")
    def _proc_meminfo_text(self) -> str:
        total = self._mem_total_kb()
        return (
            f"MemTotal:       {total:>10} kB\n"
            f"MemFree:        {int(total * 0.50):>10} kB\n"
            f"MemAvailable:   {int(total * 0.65):>10} kB\n"
            f"Buffers:        {int(total * 0.02):>10} kB\n"
            f"Cached:         {int(total * 0.33):>10} kB\n"
            f"SwapCached:              0 kB\n"
            f"SwapTotal:               0 kB\n"
            f"SwapFree:                0 kB\n"
            f"Dirty:                 372 kB\n"
            f"Writeback:               0 kB\n"
            f"AnonPages:      {int(total * 0.10):>10} kB\n"
            f"Mapped:         {int(total * 0.03):>10} kB\n"
            f"Shmem:          {int(total * 0.01):>10} kB\n"
            f"Slab:           {int(total * 0.02):>10} kB"
        )
    def _proc_version_text(self) -> str:
        kernel_version = CowrieConfig.get("shell", "kernel_version", fallback="6.1.0-21-amd64")
        kernel_build = CowrieConfig.get(
            "shell", "kernel_build_string",
            fallback="#1 SMP PREEMPT_DYNAMIC Debian 6.1.90-1 (2024-05-03)",
        )
        return (
            f"Linux version {kernel_version} (buildd@debian) "
            f"(gcc-12 (Debian 12.2.0-14) 12.2.0, GNU ld (GNU Binutils for Debian) 2.40) "
            f"{kernel_build}"
        )
    def _etc_os_release_text(self) -> str:
        return (
            'PRETTY_NAME="Debian GNU/Linux 12 (bookworm)"\n'
            'NAME="Debian GNU/Linux"\n'
            'VERSION_ID="12"\n'
            'VERSION="12 (bookworm)"\n'
            "VERSION_CODENAME=bookworm\n"
            "ID=debian\n"
            'HOME_URL="https://www.debian.org/"\n'
            'SUPPORT_URL="https://www.debian.org/support"\n'
            'BUG_REPORT_URL="https://bugs.debian.org/"'
        )
    def _lsb_release_text(self) -> str:
        return (
            "No LSB modules are available.\n"
            "Distributor ID:\tDebian\n"
            "Description:\tDebian GNU/Linux 12 (bookworm)\n"
            "Release:\t12\n"
            "Codename:\tbookworm"
        )
    def _lscpu_text(self) -> str:
        cores = self._cpu_cores()
        model = self._cpu_model()
        mhz = self._cpu_mhz()
        try:
            bogomips = f"{float(mhz) * 2:.2f}"
        except ValueError:
            bogomips = "4600.00"
        return (
            "Architecture:            x86_64\n"
            "  CPU op-mode(s):        32-bit, 64-bit\n"
            "  Byte Order:            Little Endian\n"
            f"CPU(s):                  {cores}\n"
            f"  On-line CPU(s) list:   0-{cores - 1}\n"
            "Vendor ID:               GenuineIntel\n"
            f"  Model name:            {model}\n"
            "    CPU family:          6\n"
            "    Model:               63\n"
            "    Thread(s) per core:  1\n"
            f"    Core(s) per socket:  {cores}\n"
            "    Socket(s):           1\n"
            "    Stepping:            2\n"
            f"    BogoMIPS:            {bogomips}\n"
            "Virtualization features:\n"
            "  Hypervisor vendor:     KVM\n"
            "  Virtualization type:   full\n"
            "Caches (sum of all):\n"
            f"  L1d:                   {cores * 32}K\n"
            f"  L1i:                   {cores * 32}K\n"
            f"  L2:                    {cores * 256}K\n"
            "  L3:                    30720K"
        )
    def _nproc_text(self) -> str:
        return str(self._cpu_cores())
    def _free_h_text(self) -> str:
        def hi(kb: float) -> str:
            mb = kb / 1024
            if mb >= 1024:
                return f"{mb / 1024:.1f}Gi"
            return f"{mb:.0f}Mi"
        total = self._mem_total_kb()
        used = hi(total * 0.19)
        free = hi(total * 0.50)
        shared = hi(total * 0.005)
        buff_cache = hi(total * 0.305)
        available = hi(total * 0.65)
        return (
            "               total        used        free      shared  buff/cache   available\n"
            f"Mem:       {hi(total):>7}     {used:>7}     {free:>7}     {shared:>7}     {buff_cache:>7}     {available:>7}\n"
            "Swap:             0B          0B          0B"
        )
    def _df_h_text(self) -> str:
        total, used, avail, pct = self._disk_profile()
        return (
            "Filesystem      Size  Used Avail Use% Mounted on\n"
            "udev            2.0G     0  2.0G   0% /dev\n"
            "tmpfs           395M  1.1M  394M   1% /run\n"
            f"/dev/sda1        {total}  {used}   {avail}  {pct} /\n"
            "tmpfs           2.0G     0  2.0G   0% /dev/shm\n"
            "tmpfs           5.0M     0  5.0M   0% /run/lock\n"
            "tmpfs           395M     0  395M   1% /run/user/1000"
        )
    def _bash_version_text(self) -> str:
        version = self._bash_version()
        return (
            f"GNU bash, version {version} (x86_64-pc-linux-gnu)\n"
            "Copyright (C) 2022 Free Software Foundation, Inc.\n"
            "License GPLv3+: GNU GPL version 3 or later <http://gnu.org/licenses/gpl.html>\n"
            "\n"
            "This is free software; you are free to change and redistribute it.\n"
            "There is NO WARRANTY, to the extent permitted by law."
        )
    # ---- Fixed /etc/passwd + /etc/shadow --------------------------------
    # etc/userdb.txt's final catch-all rule ('*:x:*') accepts almost any
    # username, so the logged-in user could plausibly be anything an
    # attacker typed -- not just the handful of usernames userdb.txt
    # special-cases. '/etc/passwd' must reflect whoever is actually logged
    # in (self.user.username), or a session logged in as e.g. 'oracle' or
    # some made-up name would have 'whoami' correctly answer with that name
    # while an independently LLM-generated '/etc/passwd' quite possibly
    # doesn't list them at all -- an easy inconsistency to check for.
    _STANDARD_PASSWD_LINES = (
        "root:x:0:0:root:/root:/bin/bash",
        "daemon:x:1:1:daemon:/usr/sbin:/usr/sbin/nologin",
        "bin:x:2:2:bin:/bin:/usr/sbin/nologin",
        "sys:x:3:3:sys:/dev:/usr/sbin/nologin",
        "sync:x:4:65534:sync:/bin:/bin/sync",
        "games:x:5:60:games:/usr/games:/usr/sbin/nologin",
        "man:x:6:12:man:/var/cache/man:/usr/sbin/nologin",
        "lp:x:7:7:lp:/var/spool/lpd:/usr/sbin/nologin",
        "mail:x:8:8:mail:/var/mail:/usr/sbin/nologin",
        "news:x:9:9:news:/var/spool/news:/usr/sbin/nologin",
        "uucp:x:10:10:uucp:/var/spool/uucp:/usr/sbin/nologin",
        "proxy:x:13:13:proxy:/bin:/usr/sbin/nologin",
        "www-data:x:33:33:www-data:/var/www:/usr/sbin/nologin",
        "backup:x:34:34:backup:/var/backups:/usr/sbin/nologin",
        "list:x:38:38:Mailing List Manager:/var/list:/usr/sbin/nologin",
        "irc:x:39:39:ircd:/var/run/ircd:/usr/sbin/nologin",
        "gnats:x:41:41:Gnats Bug-Reporting System (admin):/var/lib/gnats:/usr/sbin/nologin",
        "nobody:x:65534:65534:nobody:/nonexistent:/usr/sbin/nologin",
        "_apt:x:100:65534::/nonexistent:/usr/sbin/nologin",
        "systemd-network:x:101:102:systemd Network Management,,,:/run/systemd:/usr/sbin/nologin",
        "systemd-resolve:x:102:103:systemd Resolver,,,:/run/systemd:/usr/sbin/nologin",
        "messagebus:x:103:104::/nonexistent:/usr/sbin/nologin",
        "sshd:x:104:65534::/run/sshd:/usr/sbin/nologin",
    )
    _STANDARD_PASSWD_USERNAMES = frozenset(
        line.split(":", 1)[0] for line in _STANDARD_PASSWD_LINES
    )
    def _etc_passwd_text(self) -> str:
        lines = list(self._STANDARD_PASSWD_LINES)
        username = self.user.username
        if username and username not in self._STANDARD_PASSWD_USERNAMES:
            lines.append(f"{username}:x:1000:1000::{self._home_dir()}:/bin/bash")
        return "\n".join(lines)
    def _etc_shadow_text(self) -> str:
        # Only ever shown to a root login (gated in _try_local_cat) -- real
        # shadow is unreadable by anyone else. Non-root accounts get a
        # locked '*' hash; root gets a plausible-looking (but fake) one.
        username = self.user.username
        extra = ""
        if username and username not in self._STANDARD_PASSWD_USERNAMES:
            extra = f"\n{username}:*:19800:0:99999:7:::"
        return (
            "root:$6$3x7Kj9Lm$q8vN2yT4hRz1cWjXsPfL0kOe6bDgFhYtQmZaRcVnBxSjKlUoIpEwRt3YvNc8MdLqAeXcVbGhTyUj1:19800:0:99999:7:::\n"
            "daemon:*:19700:0:99999:7:::\n"
            "bin:*:19700:0:99999:7:::\n"
            "sys:*:19700:0:99999:7:::\n"
            "sync:*:19700:0:99999:7:::\n"
            "games:*:19700:0:99999:7:::\n"
            "man:*:19700:0:99999:7:::\n"
            "lp:*:19700:0:99999:7:::\n"
            "mail:*:19700:0:99999:7:::\n"
            "news:*:19700:0:99999:7:::\n"
            "uucp:*:19700:0:99999:7:::\n"
            "proxy:*:19700:0:99999:7:::\n"
            "www-data:*:19700:0:99999:7:::\n"
            "backup:*:19700:0:99999:7:::\n"
            "list:*:19700:0:99999:7:::\n"
            "irc:*:19700:0:99999:7:::\n"
            "gnats:*:19700:0:99999:7:::\n"
            "nobody:*:19700:0:99999:7:::\n"
            "_apt:*:19700:0:99999:7:::\n"
            "systemd-network:*:19700:0:99999:7:::\n"
            "systemd-resolve:*:19700:0:99999:7:::\n"
            "messagebus:*:19700:0:99999:7:::\n"
            "sshd:*:19700:0:99999:7:::" + extra
        )
    def _fixed_cat_text(self, path: str) -> str | None:
        """
        Content for the fixed system files that get deterministic answers
        (see the profile methods above) -- '/etc/shadow' is handled
        separately in _try_local_cat since it also needs a privilege check,
        not just fixed text.
        """
        if path == "/etc/os-release":
            return self._etc_os_release_text()
        if path == "/proc/version":
            return self._proc_version_text()
        if path == "/proc/cpuinfo":
            return self._proc_cpuinfo_text()
        if path == "/proc/meminfo":
            return self._proc_meminfo_text()
        if path == "/etc/passwd":
            return self._etc_passwd_text()
        return None
    def _uname_text(self, args) -> str | None:
        """
        Computes the exact text a real 'uname' with these args would print
        (no trailing newline), or None if the flag/arg form isn't one we
        recognize -- in which case the caller should fall back to the LLM
        rather than risk an incomplete deterministic answer. Pulled out
        into its own method (rather than inlined in the 'uname' branch of
        _try_local_command) so the piped-command path below can compute
        the same text without duplicating the flag-parsing logic -- two
        copies of this drifting apart is exactly the kind of bug this
        project has hit before (see the old separate /home overrides).
        """
        valid_short = set("asnrvmo")
        long_map = {
            "--all": "a", "--kernel-name": "s", "--nodename": "n",
            "--kernel-release": "r", "--kernel-version": "v",
            "--machine": "m", "--operating-system": "o",
        }
        flags = "".join(a[1:] for a in args if a.startswith("-") and not a.startswith("--"))
        long_flags = [a for a in args if a.startswith("--")]
        positional = [a for a in args if not a.startswith("-")]
        if (
            positional
            or any(c not in valid_short for c in flags)
            or any(lf not in long_map for lf in long_flags)
        ):
            return None
        for lf in long_flags:
            flags += long_map[lf]
        want_all = "a" in flags
        kernel_version = CowrieConfig.get("shell", "kernel_version", fallback="6.1.0-21-amd64")
        kernel_build = CowrieConfig.get(
            "shell", "kernel_build_string",
            fallback="#1 SMP PREEMPT_DYNAMIC Debian 6.1.90-1 (2024-05-03)",
        )
        hw_platform = CowrieConfig.get("shell", "hardware_platform", fallback="x86_64")
        os_name = CowrieConfig.get("shell", "operating_system", fallback="GNU/Linux")
        fields = []
        if want_all or "s" in flags or not flags:
            fields.append("Linux")
        if want_all or "n" in flags:
            fields.append(self.hostname)
        if want_all or "r" in flags:
            fields.append(kernel_version)
        if want_all or "v" in flags:
            fields.append(kernel_build)
        if want_all or "m" in flags:
            fields.append(hw_platform)
        if want_all or "o" in flags:
            fields.append(os_name)
        return " ".join(fields)
    # Matches the awk program half of the single piped idiom
    # _try_local_piped_command supports: '{print $N}' or '{printf $N}',
    # optionally with a trailing ';' and/or surrounding whitespace --
    # covers the common quoting variations attackers/loader scripts use
    # ('{print $1}', '{ print $1 }', '{printf $1}').
    _PIPE_AWK_FIELD_RE = re.compile(r"^\{\s*print(f)?\s*\$(\d+)\s*;?\s*\}$")
    # Shell operator tokens that should never be treated as a filename
    # argument by touch/mkdir/rm -- see _has_unquoted_chain_operator.
    _SHELL_OPERATOR_TOKENS = frozenset({"&", "&&", "||", ";", "|"})
    @staticmethod
    def _find_unquoted_pipe(s: str) -> int:
        """
        Index of the first '|' that's outside any quoted section, or -1.
        Needed because shlex.split() only splits on whitespace -- a
        no-space pipe like 'uname -m|awk ...' (a style real attacker/
        loader one-liners commonly use) would otherwise glue onto its
        neighboring token ('-m|awk') instead of being recognized as a
        pipe at all.
        """
        in_single = in_double = False
        for i, ch in enumerate(s):
            if ch == "'" and not in_double:
                in_single = not in_single
            elif ch == '"' and not in_single:
                in_double = not in_double
            elif ch == "|" and not in_single and not in_double:
                return i
        return -1
    def _try_local_piped_command(self, stripped: str) -> bool:
        """
        Handles one specific piped shape deterministically: a supported
        local command piped into a single-field awk extractor, e.g.
        'uname -m | awk {print $1}'. This is a very common recon/loader
        one-liner (grab just the CPU architecture for a follow-up download
        URL) -- frequent enough on this honeypot that routing it through
        the LLM every time was both slow (a fingerprintable delay on an
        otherwise-instant command) and risky for consistency (the LLM has
        no guarantee of returning the same architecture string a plain
        'uname -m' moments later in the same session would).

        Only this exact 'command | awk {print/printf $N}' shape is
        handled; anything else containing a pipe still falls through to
        the LLM unchanged, same as before this method existed.
        """
        idx = self._find_unquoted_pipe(stripped)
        if idx == -1:
            return False
        try:
            left = shlex.split(stripped[:idx])
            right = shlex.split(stripped[idx + 1 :])
        except ValueError:
            return False
        if not left or len(right) != 2 or right[0] != "awk":
            return False
        match = self._PIPE_AWK_FIELD_RE.match(right[1].strip())
        if not match:
            return False
        is_printf = match.group(1) == "f"
        field_index = int(match.group(2)) - 1
        if field_index < 0:
            return False
        left_cmd, left_args = left[0], left[1:]
        if left_cmd == "uname":
            text = self._uname_text(left_args)
        elif left_cmd == "whoami" and not left_args:
            text = self.user.username
        elif left_cmd == "hostname" and not left_args:
            text = self.hostname
        elif left_cmd == "pwd" and not left_args:
            text = self.cwd
        else:
            text = None
        if text is None:
            return False
        fields = text.split()
        value = fields[field_index] if field_index < len(fields) else ""
        self._write(value + ("\n" if not is_printf else ""))
        self._show_prompt()
        return True
    @staticmethod
    def _has_unquoted_chain_operator(s: str) -> bool:
        """
        True if s contains a top-level (outside quotes) ';', '&&', or '||'
        -- shell command-chaining/separator operators nothing here has any
        concept of. Without this check, a line like 'touch test.txt && cat
        notes.txt' got shlex-split into ['touch', 'test.txt', '&&', 'cat',
        'notes.txt'], and the touch handler -- which treats every non-flag
        token as a filename to create -- blindly created bogus local files
        literally named '&&', 'cat', and 'notes.txt' alongside the real
        'test.txt'. Those then leaked into every later 'ls /' as fake
        entries (observed live: '&& . .. bin boot cat dev etc ... notes.txt
        ... test.txt ...'). Bailing out here sends the whole line to the
        LLM as free text instead, same as any other command with no local
        handler -- no worse than before this method existed, just no
        longer actively corrupting session state.
        """
        in_single = in_double = False
        i, n = 0, len(s)
        while i < n:
            ch = s[i]
            if ch == "'" and not in_double:
                in_single = not in_single
            elif ch == '"' and not in_single:
                in_double = not in_double
            elif not in_single and not in_double:
                if ch == ";":
                    return True
                if s[i : i + 2] in ("&&", "||"):
                    return True
            i += 1
        return False
    def _try_local_command(self, stripped: str) -> bool:
        """
        Handle cd/touch/mkdir/rm deterministically using only what this
        session itself has created/removed. Returns True if handled.
        """
        if not stripped:
            return False
        if self._has_unquoted_chain_operator(stripped):
            return False
        if "|" in stripped:
            return self._try_local_piped_command(stripped)
        try:
            parts = shlex.split(stripped)
        except ValueError:
            return False
        if not parts:
            return False
        cmd, args = parts[0], parts[1:]
        if cmd == "pwd":
            # We already know self.cwd with full confidence (it's what we
            # build the prompt from), so answer directly instead of
            # trusting the LLM to transcribe it back correctly — it has
            # been observed dropping part of the path on longer cwds.
            self._write(self.cwd + "\n")
            self._show_prompt()
            return True
        if cmd == "whoami":
            if args:
                # Real whoami takes no meaningful arguments -- an unusual
                # form falls through to the LLM rather than risk a wrong
                # deterministic answer for a case we haven't accounted for.
                return False
            self._write(self.user.username + "\n")
            self._show_prompt()
            return True
        if cmd == "hostname":
            valid_flags = {"s", "f", "A", "d", "y", "i"}
            flags = "".join(a[1:] for a in args if a.startswith("-") and not a.startswith("--"))
            positional = [a for a in args if not a.startswith("-")]
            if positional or any(c not in valid_flags for c in flags):
                # A positional arg means setting the hostname (needs root
                # and doesn't apply here); an unrecognized flag falls
                # through to the LLM rather than guess. With no domain
                # configured, -s/-f/-A/-d/-y/-i all reduce to the same
                # bare hostname anyway.
                return False
            self._write(self.hostname + "\n")
            self._show_prompt()
            return True
        if cmd == "id":
            flags = "".join(a[1:] for a in args if a.startswith("-") and not a.startswith("--"))
            positional = [a for a in args if not a.startswith("-")]
            is_root = self.user.username == "root"
            uid = 0 if is_root else 1000
            uname = self.user.username
            if positional:
                # 'id someoneelse' -- not a user we track anything about,
                # let the LLM improvise rather than answer for our own user.
                return False
            if flags == "":
                self._write(f"uid={uid}({uname}) gid={uid}({uname}) groups={uid}({uname})\n")
            elif flags == "u":
                self._write(f"{uid}\n")
            elif flags == "un":
                self._write(f"{uname}\n")
            elif flags == "g":
                self._write(f"{uid}\n")
            elif flags == "gn":
                self._write(f"{uname}\n")
            else:
                # Uncommon flag combo (-G, -a, etc.) -- fall through
                # rather than risk an incomplete/wrong deterministic answer.
                return False
            self._show_prompt()
            return True
        if cmd == "uname":
            text = self._uname_text(args)
            if text is None:
                return False
            self._write(text + "\n")
            self._show_prompt()
            return True
        # Part of the same fixed hardware/OS profile as 'uname' above --
        # only the exact flag forms actually seen in practice are handled
        # deterministically; anything else falls through to the LLM rather
        # than risk an incomplete/wrong deterministic answer.
        if cmd == "nproc" and (not args or args == ["--all"]):
            self._write(self._nproc_text() + "\n")
            self._show_prompt()
            return True
        if cmd == "free" and args == ["-h"]:
            self._write(self._free_h_text() + "\n")
            self._show_prompt()
            return True
        if cmd == "df" and args == ["-h"]:
            self._write(self._df_h_text() + "\n")
            self._show_prompt()
            return True
        if cmd == "bash" and args == ["--version"]:
            self._write(self._bash_version_text() + "\n")
            self._show_prompt()
            return True
        if cmd == "lsb_release" and args == ["-a"]:
            self._write(self._lsb_release_text() + "\n")
            self._show_prompt()
            return True
        if cmd == "lscpu" and not args:
            self._write(self._lscpu_text() + "\n")
            self._show_prompt()
            return True
        if cmd == "ls":
            flags = [a for a in args if a.startswith("-")]
            paths = [a for a in args if not a.startswith("-")]
            show_all = any(c in "aA" for f in flags for c in f[1:])
            target = self._resolve_path(paths[0]) if paths else self.cwd
            cached = self._dir_listing_cache.get(target)
            if cached is None and target in self._DETERMINISTIC_LISTINGS:
                self._dir_listing_cache[target] = list(self._DETERMINISTIC_LISTINGS[target])
                cached = self._dir_listing_cache[target]
            if cached is not None:
                # '.' and '..' are never stored in the cache itself
                # (they're not real per-directory state) — add them back
                # in at display time whenever -a/-A was passed, same as a
                # real 'ls -a' always showing them regardless of whether
                # the directory has any other content.
                if show_all:
                    names = list(cached) + [".", ".."]
                else:
                    names = [n for n in cached if not n.startswith(".")]
                if names:
                    self._write("  ".join(sorted(names)) + "\n")
                self._show_prompt()
                return True
            # Not seeded yet — remember which directory (and whether -a
            # was requested) this targets so the LLM's response can seed
            # the cache once it comes back, then let this first call go
            # to the LLM as normal.
            self._pending_ls_dir = target
            self._pending_ls_show_all = show_all
            return False
        if cmd.startswith("/") or cmd in ("~",) or cmd.startswith("~/"):
            # A bare path typed as if it were a command (no 'ls'/'cd'), e.g.
            # someone just types '/etc'. Real bash tries to execute it and
            # fails with 'Is a directory' or a not-found/permission error —
            # it never lists the contents. Only answer locally when we
            # actually know the path's status (from our own session state
            # or an already-seeded directory listing); otherwise fall
            # through to the LLM as before, unchanged.
            target = self._resolve_path(cmd)
            local_status = self._local_paths.get(target)
            if local_status == "deleted":
                self._write(f"-bash: {cmd}: No such file or directory\n")
                self._show_prompt()
                return True
            if local_status == "file":
                self._write(f"-bash: {cmd}: Permission denied\n")
                self._show_prompt()
                return True
            is_dir = self._known_dir_status(target)
            if is_dir is True:
                self._write(f"-bash: {cmd}: Is a directory\n")
                self._show_prompt()
                return True
            if is_dir is False:
                self._write(f"-bash: {cmd}: No such file or directory\n")
                self._show_prompt()
                return True
            return False
        if cmd == "cd":
            arg = stripped[2:].strip()
            target = self._resolve_path(arg) if arg else self._home_dir()
            known = self._local_paths.get(target)
            if known == "deleted":
                self._write(f"-bash: cd: {arg or target}: No such file or directory\n")
                self._show_prompt()
                return True
            if known == "file":
                self._write(f"-bash: cd: {arg or target}: Not a directory\n")
                self._show_prompt()
                return True
            # Trivially-safe navigation that never needs validating: home,
            # root, '.', or anywhere we're already inside (we necessarily
            # passed through every segment of our own cwd to get here).
            if (
                not arg
                or arg == "~"
                or target == "/"
                or target == self.cwd
                or (self.cwd + "/").startswith(target.rstrip("/") + "/")
            ):
                self.cwd = target
                self._show_prompt()
                return True
            # A genuinely new path — validate it segment by segment
            # (silently probing the LLM for any directory we haven't
            # already seen) before committing to it, so cd can't land
            # anywhere a real ls wouldn't show (e.g. a typo'd directory).
            self._command_pending = True
            self._validate_and_cd(arg, target)
            return True
        if cmd == "touch":
            for a in args:
                # '_has_unquoted_chain_operator' already catches the common
                # '&&'/'||'/';' cases before we ever get here, but a lone
                # '&' (backgrounding, e.g. 'touch foo &') is a single token
                # shlex won't flag on its own -- skip stray shell-operator
                # tokens directly too, rather than creating a file literally
                # named '&'.
                if a.startswith("-") or a in self._SHELL_OPERATOR_TOKENS:
                    continue
                path = self._resolve_path(a)
                already_exists = (
                    path == "/etc/shadow"
                    or self._fixed_cat_text(path) is not None
                    or self._local_paths.get(path) in ("file", "dir")
                    or self._known_dir_status(path) is True
                )
                if not self._writable_by_current_user(path):
                    # Confirmed live: a non-root login could touch/rm/mkdir
                    # anywhere at all (e.g. '/etc/passwd') with no
                    # permission check whatsoever -- a real system would
                    # refuse this for anything not owned by that user.
                    self._write(f"touch: cannot touch '{a}': Permission denied\n")
                    continue
                if already_exists:
                    # Real touch on an EXISTING file only updates its
                    # timestamp -- it never truncates the content. Without
                    # this, touching a fixed system file (e.g.
                    # '/etc/passwd') marked it as a fresh empty local file,
                    # so 'cat' afterward read back nothing instead of the
                    # real deterministic content — confirmed live.
                    continue
                self._local_paths[path] = "file"
                self._sync_dir_cache(path, "file")
            # real touch is silent on success
            self._show_prompt()
            return True
        if cmd == "mkdir":
            for a in args:
                if a.startswith("-") or a in self._SHELL_OPERATOR_TOKENS:
                    continue
                path = self._resolve_path(a)
                # Checking only _local_paths missed directories that exist
                # but were never explicitly mkdir'd this session -- e.g.
                # 'mkdir /etc' silently "succeeded" instead of reporting
                # 'File exists', confirmed live. _known_dir_status also
                # knows about the standard root dirs and anything already
                # seen via a real 'ls'.
                if (
                    self._local_paths.get(path) in ("file", "dir")
                    or self._known_dir_status(path) is True
                ):
                    self._write(f"mkdir: cannot create directory '{a}': File exists\n")
                    continue
                if not self._writable_by_current_user(path):
                    self._write(f"mkdir: cannot create directory '{a}': Permission denied\n")
                    continue
                self._local_paths[path] = "dir"
                self._sync_dir_cache(path, "dir")
            # silent on success, matching real mkdir
            self._show_prompt()
            return True
        if cmd == "rm":
            flags = "".join(a[1:] for a in args if a.startswith("-"))
            recursive = "r" in flags or "R" in flags
            force = "f" in flags
            for a in args:
                if a.startswith("-") or a in self._SHELL_OPERATOR_TOKENS:
                    continue
                path = self._resolve_path(a)
                if not self._writable_by_current_user(path):
                    # Confirmed live: 'rm /etc/passwd' as a non-root login
                    # silently succeeded, with nothing checking whether
                    # this user could actually touch that path at all.
                    if not force:
                        self._write(f"rm: cannot remove '{a}': Permission denied\n")
                    continue
                known = self._local_paths.get(path)
                if known == "deleted":
                    if not force:
                        self._write(f"rm: cannot remove '{a}': No such file or directory\n")
                    continue
                if known == "dir" and not recursive:
                    self._write(f"rm: cannot remove '{a}': Is a directory\n")
                    continue
                # Unknown or a known file (or dir with -r): we have no full
                # tree to check against, only our own session's history, so
                # assume it existed per the ongoing narrative and remove it.
                self._local_paths[path] = "deleted"
                self._sync_dir_cache(path, "deleted")
            # silent on success, matching real rm
            self._show_prompt()
            return True
        return False
    def _known_dir_status(self, path: str):
        """
        True/False if we're confident whether `path` is a real directory,
        None if we don't know yet (neither locally created/removed, nor
        present in a directory listing we've already seeded).
        """
        status = self._local_paths.get(path)
        if status == "dir":
            return True
        if status in ("file", "deleted"):
            return False
        if path in self._DETERMINISTIC_LISTINGS:
            # 'cd media'/'cd etc' as literally the first command (before
            # '/' has ever been ls'd) would otherwise trigger a silent LLM
            # probe here to confirm the directory exists. These are
            # guaranteed to exist (see _STANDARD_ROOT_DIRS) and have fixed
            # contents (see _DETERMINISTIC_LISTINGS), so answer directly
            # instead of depending on command order, and seed their own
            # listing cache too for when they're actually ls'd next.
            self._dir_listing_cache.setdefault(path, list(self._DETERMINISTIC_LISTINGS[path]))
            return True
        cached = self._dir_listing_cache.get(posixpath.dirname(path) or "/")
        if cached is not None:
            return posixpath.basename(path) in cached
        return None
    def _blank_response_means_empty(self, directory: str) -> bool:
        """
        A blank/unparseable LLM response for 'ls' is ambiguous — it might
        mean a genuinely empty directory, or it might just mean the
        model's whole reply got stripped away (e.g. it echoed nothing but
        a fake prompt). '/' and its standard top-level children (/etc,
        /bin, /dev, ...) are guaranteed by our own system prompt to never
        be empty, so a blank response there must be a parse miss — don't
        cache it as empty, let the next ls retry. Anywhere else, a
        genuinely empty directory is plausible, so keep the old behavior.
        """
        if directory == "/":
            return False
        parent, _ = posixpath.split(directory)
        return parent != "/"
    def _probe_dir_listing(self, directory: str, on_result) -> None:
        """
        Silently asks the LLM what's really in `directory` — without
        touching cwd, command_history, fs_cache, or the visible terminal —
        then calls on_result(names) with a list of entries, or
        on_result(None) if the directory doesn't appear to exist. Used to
        validate cd targets against directories we haven't run a real ls
        in yet, so cd can't land anywhere a real ls wouldn't show.
        """
        if not hasattr(self, "llm_client"):
            self.llm_client = LLMClient()
            self.command_history = []
        now = datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y")
        root_hint = (
            " The root directory '/' of a real Linux system always contains the"
            " standard top-level directories bin, boot, dev, etc, home, lib,"
            " lib64, media, mnt, opt, proc, root, run, sbin, srv, sys, tmp, usr,"
            " var, plus any user files — it is not a home-directory-style"
            " listing."
            if directory == "/"
            else ""
        )
        home_hint = (
            " '/home' itself must never directly contain personal files or"
            " folders like Desktop, Documents, Downloads, Music, Pictures, or"
            " Videos — it contains only one subdirectory per user account"
            " (e.g. a directory named after each user), never those personal"
            " folders directly."
            if directory == "/home"
            else ""
        )
        mount_hint = (
            " This is a mount-point directory, not a personal or"
            " system-config one — on a typical system with nothing plugged"
            " in or mounted it is usually completely empty, and if not empty"
            " it contains only a plausible mount name (e.g. a USB drive or"
            " network share label), never Desktop/Documents/Downloads-style"
            " personal folders and never config files."
            if directory in ("/media", "/mnt")
            else ""
        )
        probe_prompt = (
            f"You are simulating a Linux server at {self.hostname} accessed via "
            f"SSH as user {self.user.username}. The current date and time is "
            f"{now}. Respond ONLY with the exact raw output of running "
            f"'ls -a {directory}' on this system — no commentary, no markdown. "
            f"Separate every filename with exactly two spaces on a single line."
            f"{root_hint}{home_hint}{mount_hint} Its contents should be plausible and specific to this"
            f" directory's likely purpose, not a generic reused listing. All"
            f" filenames must be plain ASCII English, never non-Latin scripts."
            f" If this is a system directory (/etc, /var, /usr, /bin, /sbin, /lib,"
            f" /opt, /run, /boot, /sys, /proc, /dev), only include real"
            f" system/config files typical of that exact path — never personal or"
            f" user-named files there. Every filename must be a complete, real,"
            f" plausible name — never a bare number, a single character, or a"
            f" sentence fragment on its own. /etc specifically should only"
            f" contain names of real, well-known Debian/Ubuntu packages,"
            f" services, or their standard config files (examples: passwd,"
            f" shadow, hostname, hosts, fstab, crontab, resolv.conf, ssh, apt,"
            f" systemd, network, dpkg, alternatives, cron.d, logrotate.d,"
            f" security, default, init.d, ssl) — never vague or made-up names"
            f" like 'custom.conf', 'settings.conf', or 'app.conf'."
            f" If the directory does not exist, respond with the exact realistic "
            f"error message for that case instead."
        )
        d: defer.Deferred[str] = self.llm_client.get_response([probe_prompt])
        def _handle(response):
            text = ""
            if response:
                text = strip_markdown(response)
                text = strip_fake_prompt(text)
            if text and self._LS_ERROR_RE.search(text):
                on_result(None)
                return
            content_lines = [ln for ln in text.split("\n") if ln.strip()] if text else []
            has_total_only = bool(content_lines) and all(
                self._LS_TOTAL_RE.match(ln.strip()) for ln in content_lines
            )
            confidently_empty = has_total_only or (
                not text and self._blank_response_means_empty(directory)
            )
            names = self._parse_ls_names(text) if text else []
            names, confidently_empty = self._apply_deterministic_listing_overrides(
                directory, names, confidently_empty
            )
            if names or confidently_empty:
                if directory == "/":
                    for d in self._STANDARD_ROOT_DIRS:
                        if d not in names:
                            names.append(d)
            else:
                on_result(None)
                return
            self._dir_listing_cache[directory] = names
            on_result(names)
        def _handle_err(err):
            self._log.failure("cd probe error", failure=err)
            on_result(None)
        d.addCallback(_handle)
        d.addErrback(_handle_err)
    def _validate_and_cd(self, arg: str, full_target: str) -> None:
        """
        Walks from '/' down to full_target one segment at a time. Any
        segment we already know about (locally created, or a directory
        we've already ls'd/probed) is checked for free; the first unknown
        segment triggers a silent probe of its parent. Only commits the
        cd once every segment along the way is confirmed to exist —
        rejects as soon as one doesn't, without probing further segments.
        """
        segments = [s for s in full_target.strip("/").split("/") if s]
        def step(index: int, current: str) -> None:
            if index >= len(segments):
                self._command_pending = False
                self.cwd = full_target
                self._show_prompt()
                self._drain_queued_input()
                return
            candidate = posixpath.normpath(posixpath.join(current, segments[index]))
            result = self._known_dir_status(candidate)
            if result is True:
                step(index + 1, candidate)
                return
            if result is False:
                self._command_pending = False
                self._write(f"-bash: cd: {arg}: No such file or directory\n")
                self._show_prompt()
                self._drain_queued_input()
                return
            def _on_probe(names, current=current, candidate=candidate, index=index):
                base = posixpath.basename(candidate)
                if names is not None and base in names:
                    step(index + 1, candidate)
                else:
                    self._command_pending = False
                    self._write(f"-bash: cd: {arg}: No such file or directory\n")
                    self._show_prompt()
                    self._drain_queued_input()
            self._probe_dir_listing(current, _on_probe)
        step(0, "/")
    def _try_local_cat(self, stripped: str) -> bool:
        try:
            parts = shlex.split(stripped)
        except ValueError:
            return False
        if len(parts) < 2 or parts[0] != "cat":
            return False
        targets = [a for a in parts[1:] if not a.startswith("-")]
        if not targets:
            return False
        for t in targets:
            path = self._resolve_path(t)
            known = self._local_paths.get(path)
            if known == "deleted":
                self._write(f"cat: {t}: No such file or directory\n")
                self._show_prompt()
                return True
            if known == "dir":
                self._write(f"cat: {t}: Is a directory\n")
                self._show_prompt()
                return True
            if known == "file":
                # Created via touch this session, so it's genuinely empty —
                # real cat on an empty file prints nothing.
                self._show_prompt()
                return True
            if known is None:
                # A handful of system files get fixed, deterministic
                # content instead of letting the LLM invent (and
                # potentially contradict, across separate calls or against
                # other commands like whoami/uname) something plausible.
                # Session-local state (touch/rm above) always takes
                # priority over these — if this session already removed
                # one of these paths, that's respected, not overridden.
                if path == "/etc/shadow":
                    if self.user.username == "root":
                        self._write(self._etc_shadow_text() + "\n")
                    else:
                        self._write("cat: /etc/shadow: Permission denied\n")
                    self._show_prompt()
                    return True
                fixed = self._fixed_cat_text(path)
                if fixed is not None:
                    self._write(fixed + "\n")
                    self._show_prompt()
                    return True
                # If this path is a directory we're actually confident
                # about (a hardcoded one like '/var/log', or one already
                # seen via a real 'ls' this session), say so directly
                # instead of letting the LLM guess — confirmed live giving
                # the wrong answer ('No such file or directory' for
                # '/var/log', which very much exists).
                if self._known_dir_status(path) is True:
                    self._write(f"cat: {t}: Is a directory\n")
                    self._show_prompt()
                    return True
        return False
    def _build_system_context(self, exec_command: str = "") -> str:
        """
        Build the system context prompt, using the configured template if present.
        Supports variables: {hostname}, {username}, {ip}, {ip6}, {client_ip}, {cwd}.
        For exec commands a tighter default is used to suppress conversational output.
        """
        if exec_command:
            default = (
                "You are simulating a Linux server that has been accessed via SSH "
                "with a command to execute. "
                "Respond with ONLY the output that would be displayed after executing this command. "
                "Keep responses realistic, including appropriate error messages for invalid commands."
            )
            config_key = "system_prompt_exec"
        else:
            default = (
                "You are simulating a Linux server that has been accessed via SSH. "
                "Respond as if you were the shell on this system. "
                "Your response should be the output that would be displayed after executing the command. "
                "Keep responses realistic, including appropriate error messages for invalid commands. "
                "For file paths, maintain consistent state with previous commands."
            )
            config_key = "system_prompt"
        template = CowrieConfig.get("llm", config_key, fallback=default)
        context = template.format_map(
            {
                "hostname": self.hostname,
                "username": self.user.username,
                "ip": getattr(self, "kippoIP", ""),
                "ip6": getattr(self, "kippoIPv6", ""),
                "client_ip": getattr(self, "clientIP", ""),
                "cwd": self.cwd,
            }
        )
        now = datetime.now(timezone.utc).strftime("%a %b %d %H:%M:%S UTC %Y")
        context += (
            f" The hostname is '{self.hostname}' and username is '{self.user.username}'."
            f" The current working directory is '{self.cwd}'."
            f" The current date and time is {now} — use this exact value for any"
            f" 'date' command or timestamps, do not invent a different one."
            f" When listing directory contents (e.g. for 'ls'), separate every"
            f" filename with exactly two spaces on a single line — never run two"
            f" filenames together with no space between them, and never put a"
            f" path separator ('/') inside a single filename — a directory"
            f" listing entry is always just a bare name, never a partial path."
        )
        if self._pending_ls_dir == "/":
            # Only include this when '/' itself is actually being listed —
            # this text used to be sent unconditionally on every command,
            # and its vivid, detailed list of root's contents was strong
            # enough to make the model anchor on it and repeat it back as
            # the answer for completely different directories (e.g. 'ls
            # /lib' returning root's listing verbatim). The standard root
            # entries are guaranteed at the code level regardless (see
            # _STANDARD_ROOT_DIRS), so this is purely a nudge for '/'
            # itself and never needs to leak into other directories' prompts.
            context += (
                f" The root directory '/' of a real Linux system always contains the"
                f" standard top-level directories bin, boot, dev, etc, home, lib,"
                f" lib64, media, mnt, opt, proc, root, run, sbin, srv, sys, tmp, usr,"
                f" var — an 'ls' of '/' must include the standard ones relevant to the"
                f" command, not just user files, and must not be a home-directory-style"
                f" listing."
            )
        if self._pending_ls_dir in ("/media", "/mnt"):
            # Same rationale as the '/' and '/home' hints above: only
            # included when this exact directory is being listed, since the
            # detail is specific to it and shouldn't bleed into other
            # directories' prompts. '/media' and '/mnt' are mount points,
            # not personal folders or config directories — the model was
            # observed returning /home's Desktop/Documents/Downloads/etc
            # listing verbatim for '/media' with no hint telling it
            # otherwise.
            context += (
                f" '{self._pending_ls_dir}' is a mount-point directory — on a"
                f" typical system with nothing plugged in or mounted it is"
                f" usually completely empty, and if not empty it contains"
                f" only a plausible mount name (e.g. a USB drive or network"
                f" share label), never Desktop/Documents/Downloads-style"
                f" personal folders and never config files."
            )
        context += (
            f" Every directory's contents must be plausible and specific to that"
            f" exact directory's own purpose — never reuse or copy another"
            f" directory's listing, and never reuse the root directory's"
            f" top-level names (bin, boot, dev, etc, home, lib, ...) as the"
            f" contents of any other directory."
            f" All invented filenames and directory names must be in plain ASCII"
            f" English (or standard config/package naming conventions) — never use"
            f" non-Latin scripts or other languages for a file or directory name."
            f" System directories (/etc, /var, /usr, /bin, /sbin, /lib, /opt, /run,"
            f" /boot, /sys, /proc, /dev) must only contain real system/config files"
            f" typical of that exact path on a genuine Linux install — never"
            f" personal, user-named, or project files there. Personal or"
            f" user-created content only belongs under /home/{self.user.username},"
            f" /root, or /tmp. The '/home' directory itself must never directly"
            f" contain personal files or folders such as Desktop, Documents,"
            f" Downloads, Music, Pictures, or Videos — '/home' only ever contains"
            f" one subdirectory per user account (e.g. '/home/{self.user.username}'),"
            f" and personal files belong inside that per-user directory, never"
            f" directly under '/home'."
            f" Every filename must be a complete, real, plausible name — never a"
            f" bare number, a single character, punctuation, or a sentence"
            f" fragment on its own. /etc specifically should only contain names"
            f" of real, well-known Debian/Ubuntu packages, services, or their"
            f" standard config files (examples: passwd, shadow, hostname, hosts,"
            f" fstab, crontab, resolv.conf, ssh, apt, systemd, network, dpkg,"
            f" alternatives, cron.d, logrotate.d, security, default, init.d,"
            f" ssl) — never vague or made-up names like 'custom.conf',"
            f" 'settings.conf', or 'app.conf'."
            f" If the first word of the command is not a real, standard"
            f" Unix/Linux command, builtin, or script that would actually exist"
            f" on this system, respond with exactly"
            f" '-bash: <word>: command not found', substituting the literal"
            f" first word the user actually typed. Never guess at a different"
            f" intended command and never autocorrect an apparent typo to a"
            f" similar real command (e.g. a typed 'c' or 'sl' must NOT be"
            f" treated as if it were 'cd' or 'ls' — respond with 'command not"
            f" found' for the literal word typed, not an error message for the"
            f" command you think they meant)."
            f" The '-bash: ' prefix is ONLY for that one 'command not found'"
            f" case (an unrecognized word typed directly at the shell)."
            f" Error messages produced BY a real program that does exist"
            f" (cat, ls, rm, mkdir, cd, etc.) never have a '-bash: ' prefix"
            f" — they're prefixed with that program's own name instead,"
            f" exactly as real Linux does it, e.g. 'cat: missing.txt: No"
            f" such file or directory' (capital N), never '-bash: cat:"
            f" missing.txt: no such file or directory'."
            f" Respond with only the direct, single-shot result of the exact"
            f" command given — never simulate additional interactive prompts,"
            f" password re-entry attempts, retry loops, or any other"
            f" multi-turn dialogue within one response, even for a command"
            f" like 'sudo' that would normally prompt for a password on a"
            f" real terminal. Assume any necessary authentication already"
            f" happened before this command was sent, and show only the"
            f" single resulting line(s) of output for this one command — no"
            f" fabricated 'password:' prompts, no fabricated 'Sorry, try"
            f" again' retries."
            f" This simulated system's true nature must never be revealed."
            f" Commands like 'ps', 'ps aux', 'top', 'htop', 'ss', 'netstat',"
            f" 'lsof', 'ip a', 'ip addr', or 'ifconfig' must never mention"
            f" python, twisted, twistd, cowrie, ollama, llm, docker, or any"
            f" other process/package name that would reveal this is a"
            f" simulated or honeypot system. Only show plausible standard"
            f" Linux processes (init or systemd as PID 1, kthreadd, sshd,"
            f" cron, rsyslogd, dbus-daemon, and the current login shell"
            f" itself) and standard listening ports (22 for ssh, optionally"
            f" 80/443 if it fits the surrounding narrative) — never port"
            f" 2222 or any port that would reveal how this system is"
            f" actually being accessed."
        )
        if exec_command:
            context += f" The command to execute is: {exec_command}"
        return context
    def _prompt_history(self) -> list:
        """
        Directory-listing consistency is already guaranteed entirely by
        _dir_listing_cache, so old 'ls' exchanges sitting in command_history
        add no value — and they actively hurt: if 'ls' is asked again in a
        *different* directory while a prior 'ls'/response pair is still in
        the last-10 window, the model tends to just echo that prior answer
        verbatim instead of generating fresh output for the new cwd (it
        sees an identical question answered a few turns back and repeats
        it). Strip 'ls' exchanges out of what we actually send the model.
        """
        filtered = []
        skip_next = False
        for entry in self.command_history:
            if skip_next:
                skip_next = False
                continue
            if entry.startswith("User: "):
                first_word = entry[len("User: "):].strip().split(" ", 1)[0]
                if first_word == "ls":
                    skip_next = True
                    continue
            filtered.append(entry)
        return filtered
    def _retry_ls(self, directory: str, show_all: bool = False) -> None:
        """
        Silently re-issues 'ls' (or 'ls -a', if the original request that
        triggered this retry included -a/-A) against `directory` after a
        blank first response, without echoing a second command into
        command_history. Used once per directory per session to recover
        from a stray empty LLM reply on a directory we know can't really
        be empty (e.g. '/etc') — the user just sees the (hopefully real)
        listing appear, with no visible sign a retry happened.
        """
        self._pending_ls_dir = directory
        self._pending_ls_show_all = show_all
        self._last_command_sent = "ls -a" if show_all else "ls"
        system_context = self._build_system_context()
        # No prior conversation history at all here — a directory's
        # contents shouldn't depend on unrelated earlier commands, and
        # words from a recent unrelated response have been observed
        # leaking into an 'ls' listing as if they were real filenames
        # (see _process_command_with_llm for the same fix and the exact
        # case that was caught live).
        prompt = [
            system_context,
            f"User: {self._last_command_sent}",
        ]
        self._command_pending = True
        d: defer.Deferred[str] = self.llm_client.get_response(prompt)
        d.addCallback(self._handle_llm_response)
        d.addErrback(self._handle_llm_error)
    def _process_command_with_llm(self, command: str) -> None:
        """
        Process a command by sending it to the LLM and writing the response
        to the terminal.
        """
        cache_key = (self.cwd, command.strip())
        if cache_key in self.fs_cache:
            # Replay the exact same output as last time for this directory+command,
            # guaranteeing a consistent, personalised fake filesystem.
            self._handle_llm_response(self.fs_cache[cache_key])
            return
        # Any new command can change filesystem state (new files, deleted
        # files, edits, etc.), so previously cached listings (e.g. 'ls')
        # are no longer guaranteed to be accurate. Drop them now — only an
        # immediate repeat of *this exact* command will hit the cache
        # (once it's added back in below), so state-changing commands in
        # between always force a fresh, context-aware LLM response.
        self.fs_cache.clear()
        if not hasattr(self, "llm_client"):
            self.llm_client = LLMClient()
            self.command_history = []
        self._last_command_sent = command.strip()
        self.command_history.append(f"User: {command}")
        system_context = self._build_system_context()
        first_word = command.strip().split(" ", 1)[0] if command.strip() else ""
        if first_word == "ls":
            # A directory's contents shouldn't depend on unrelated prior
            # commands at all — but conversation history was observed
            # leaking into 'ls' output anyway: a preceding "-bash: more:
            # command not found" response bled the words 'command',
            # 'found', and 'not' into the very next 'ls /opt' as if they
            # were real filenames, none of which any existing filter
            # catches since they're all individually ordinary-looking
            # words. _prompt_history() already strips *other* 'ls'
            # exchanges from context for a similar reason (see its
            # docstring); for 'ls' specifically, go further and send
            # nothing but this one request — no prior turns at all.
            history = [f"User: {command}"]
        else:
            history = self._prompt_history()[-10:]
        prompt = [system_context, *history]
        self._command_pending = True
        d: defer.Deferred[str] = self.llm_client.get_response(prompt)
        d.addCallback(lambda response: self._cache_and_handle(cache_key, response))
        d.addErrback(self._handle_llm_error)
    def _cache_and_handle(self, cache_key: tuple, response: str) -> None:
        """
        Store the LLM's response so the same command in the same directory
        always returns identical output, then display it as normal.
        """
        self.fs_cache[cache_key] = response
        self._handle_llm_response(response)
    def _handle_llm_response(self, response: str) -> None:
        """
        Handle the response from the LLM and display it to the user.
        """
        self._command_pending = False
        if self.terminal is None:
            return
        pending_ls_dir = self._pending_ls_dir
        pending_ls_show_all = self._pending_ls_show_all
        self._pending_ls_dir = None
        self._pending_ls_show_all = False
        clean_response = ""
        if response:
            clean_response = strip_markdown(response)
            clean_response = strip_fake_prompt(clean_response, self._last_command_sent)
        # What we'll actually display — defaults to the model's raw text,
        # but gets replaced below with a clean, deterministic re-render
        # whenever this is an 'ls' we can confidently parse. That avoids
        # showing the model's raw formatting glitches (e.g. two filenames
        # glued together with no separator) on the very first ls in a
        # directory — only later, cached calls used to get the clean form.
        display_text = clean_response
        if pending_ls_dir is not None:
            is_error = bool(clean_response) and bool(self._LS_ERROR_RE.search(clean_response))
            if is_error:
                # The LLM answered with an error ('Permission denied', 'No
                # such file or directory', etc.) rather than a listing.
                # Show that error as-is; don't tokenize it into fake
                # filenames, and leave this directory unseeded so the next
                # ls here tries again.
                pass
            else:
                content_lines = [
                    ln for ln in clean_response.split("\n") if ln.strip()
                ] if clean_response else []
                has_total_only = bool(content_lines) and all(
                    self._LS_TOTAL_RE.match(ln.strip()) for ln in content_lines
                )
                confidently_empty = has_total_only or (
                    not clean_response
                    and self._blank_response_means_empty(pending_ls_dir)
                )
                names = self._parse_ls_names(clean_response) if clean_response else []
                names, confidently_empty = self._apply_deterministic_listing_overrides(
                    pending_ls_dir, names, confidently_empty
                )
                if names or confidently_empty:
                    # Either real names, or we're confident this directory
                    # is genuinely empty (no response, or only a 'total 0'
                    # style header with no file lines). If the response had
                    # real content but parsing found nothing, that's an
                    # ambiguous parse miss — skip caching (and keep showing
                    # the raw text) so the next ls here just retries
                    # against the LLM instead of getting stuck showing a
                    # permanently empty directory.
                    for path, status in self._local_paths.items():
                        parent, base = posixpath.split(path)
                        if parent != pending_ls_dir:
                            continue
                        if status == "deleted":
                            if base in names:
                                names.remove(base)
                        elif base not in names:
                            names.append(base)
                    if pending_ls_dir == "/":
                        for d in self._STANDARD_ROOT_DIRS:
                            if d not in names:
                                names.append(d)
                    # The cache stays free of '.'/'..' — they're not real
                    # per-directory state, just added back in at display
                    # time here (and again on every future cache hit in
                    # _try_local_command) whenever -a was requested for
                    # *this* call. A plain 'ls' right after 'ls -a' in the
                    # same directory must not show them.
                    self._dir_listing_cache[pending_ls_dir] = names
                    display_names = names + [".", ".."] if pending_ls_show_all else names
                    display_text = "  ".join(sorted(display_names)) if display_names else ""
                elif (
                    not self._blank_response_means_empty(pending_ls_dir)
                    and pending_ls_dir not in self._ls_retried
                ):
                    # Ambiguous miss on a directory we know can't really be
                    # empty, and we haven't already retried here. Covers
                    # both a literally blank response (model echoed a
                    # stray prompt) and a non-blank response that parsed
                    # to zero real names (e.g. pure symbol-soup like
                    # ':\";' — every token got filtered as implausible) —
                    # either way, retry once silently rather than leaving
                    # the user staring at empty or garbage output.
                    self._ls_retried.add(pending_ls_dir)
                    self._retry_ls(pending_ls_dir, pending_ls_show_all)
                    return
                else:
                    # Either this directory's blank/ambiguous response is
                    # accepted as genuinely empty, or we already spent our
                    # one retry here and still couldn't parse anything real.
                    # Never fall through to showing the model's raw,
                    # unfiltered text for a listing command — unparseable
                    # garbage (stray flags, pipes, partial paths) is far
                    # more suspicious to a real attacker than an empty
                    # directory. Silence is the safe default, except that a
                    # genuinely empty directory listed with -a must still
                    # show '.' and '..', exactly like a real 'ls -a' would.
                    display_text = (
                        "  ".join(sorted([".", ".."])) if pending_ls_show_all else ""
                    )
        if display_text:
            # Cap what actually persists into future prompts. An
            # anomalously long response (e.g. a fabricated multi-turn
            # 'sudo' password dialogue) has been observed bleeding
            # unrelated content — like invented '(root) /path/to/bin'
            # entries — into completely unrelated directories' 'ls'
            # output several commands later, because the model sees it
            # sitting in the last-10-turn history and anchors on its
            # formatting. Truncating what's stored (not what's shown to
            # the user this turn) limits how far that kind of anomaly can
            # propagate.
            history_text = (
                display_text
                if len(display_text) <= 500
                else display_text[:500] + " ...[truncated]"
            )
            self.command_history.append(f"System: {history_text}")
            self.terminal.write(f"{display_text}\n".encode())
        # If nothing to display, just show the prompt silently (like an
        # empty command, or a confidently-empty directory)
        self._show_prompt()
        self._drain_queued_input()
    def _handle_llm_error(self, err):
        """
        Handle errors from the LLM client.
        """
        self._command_pending = False
        self._pending_ls_dir = None
        self._pending_ls_show_all = False
        self._log.failure("LLM error", failure=err)
        if self.terminal is None:
            return
        # Show nothing - just the prompt, as if the command produced no output
        self._show_prompt()
        self._drain_queued_input()
    def _show_prompt(self):
        """
        Display the appropriate command prompt to the user.
        """
        if self.terminal is None:
            return
        # Build a realistic prompt
        if self.user.username == "root":
            prompt = f"{self.user.username}@{self.hostname}:{self.cwd}# "
        else:
            prompt = f"{self.user.username}@{self.hostname}:{self.cwd}$ "
        self.terminal.write(prompt.encode("utf-8"))
    def _drain_queued_input(self) -> None:
        """
        Replays character/Enter input that arrived while a previous
        command was still waiting on the LLM (or a cd probe), in the
        order it was received. Stops as soon as a replayed Enter kicks
        off a new pending command, so a burst of several commands sent
        without waiting for each prompt gets fed through one at a time —
        same as a real shell processing them serially — rather than being
        dropped or run out of order. Lives here (not just on the
        interactive subclass) so every _command_pending resolution point
        in this base class can call it safely; HoneyPotExecProtocol never
        populates the queue, so this is always a no-op for it.
        """
        while self._queued_input and not self._command_pending:
            item = self._queued_input.pop(0)
            if item[0] == "char":
                self.characterReceived(item[1], item[2])
            else:
                self.handle_RETURN()
    def uptime(self):
        """
        Uptime
        """
        pt = self.getProtoTransport()
        r = time.time() - pt.factory.starttime
        return r
    def eofReceived(self) -> None:
        # Shell received EOF, nicely exit
        """
        TODO: this should probably not go through transport, but use processprotocol to close stdin
        """
        ret = failure.Failure(error.ProcessTerminated(exitCode=0))
        self.terminal.transport.processEnded(ret)
class HoneyPotExecProtocol(HoneyPotBaseProtocol):
    _log = Logger()
    # input_data is static buffer for stdin received from remote client
    input_data = b""
    def __init__(self, avatar, execcmd):
        """
        IMPORTANT
        Before this, execcmd is 'bytes'. Here it converts to 'string' and
        commands work with string rather than bytes.
        """
        try:
            self.execcmd = execcmd.decode("utf8")
        except UnicodeDecodeError:
            self._log.failure("Unusual execcmd: {execcmd!r}", execcmd=execcmd)
        HoneyPotBaseProtocol.__init__(self, avatar)
    def connectionMade(self) -> None:
        HoneyPotBaseProtocol.connectionMade(self)
        self.setTimeout(60)
        # Process the exec command with LLM
        self._process_exec_with_llm()
    def _process_exec_with_llm(self) -> None:
        """
        Process an exec command with the LLM and return the result.
        Used when commands are passed directly to SSH (e.g., ssh user@host 'command')
        """
        self.llm_client = LLMClient()
        self.command_history = []
        # Construct the prompt
        system_context = self._build_system_context(exec_command=self.execcmd)
        prompt = [system_context]
        # Get response asynchronously
        d: defer.Deferred[str] = self.llm_client.get_response(prompt)
        d.addCallback(self._handle_exec_response)
        d.addErrback(self._handle_exec_error)
    def _handle_exec_response(self, response: str) -> None:
        """
        Handle the LLM response for an exec command.
        """
        if self.terminal is None:
            return
        if response:
            clean_response = strip_markdown(response)
            self.terminal.write(f"{clean_response}\n".encode())
        # If no response, produce no output (some commands are silent)
        ret = failure.Failure(error.ProcessTerminated(exitCode=0))
        self.terminal.transport.processEnded(ret)
    def _handle_exec_error(self, exec_failure):
        """
        Handle errors from the LLM client during exec.
        """
        self._log.failure("LLM exec error", failure=exec_failure)
        if self.terminal is None:
            return
        # Produce no output, exit with 0 (as if command succeeded silently)
        ret = failure.Failure(error.ProcessTerminated(exitCode=0))
        self.terminal.transport.processEnded(ret)
    def keystrokeReceived(self, keyID, modifier):
        self.input_data += keyID
class HoneyPotInteractiveProtocol(HoneyPotBaseProtocol, recvline.HistoricRecvLine):
    def __init__(self, avatar):
        recvline.HistoricRecvLine.__init__(self)
        HoneyPotBaseProtocol.__init__(self, avatar)
    def connectionMade(self) -> None:
        HoneyPotBaseProtocol.connectionMade(self)
        recvline.HistoricRecvLine.connectionMade(self)
        self.llm_client = LLMClient()
        self.command_history = []
        # Show welcome banner
        welcome = f"Welcome to {self.hostname}\n"
        self.terminal.write(welcome.encode("utf-8"))
        self._show_prompt()
        self.keyHandlers.update(
            {
                b"\x01": self.handle_HOME,  # CTRL-A
                b"\x02": self.handle_LEFT,  # CTRL-B
                b"\x03": self.handle_CTRL_C,  # CTRL-C
                b"\x04": self.handle_CTRL_D,  # CTRL-D
                b"\x05": self.handle_END,  # CTRL-E
                b"\x06": self.handle_RIGHT,  # CTRL-F
                b"\x08": self.handle_BACKSPACE,  # CTRL-H
                b"\x09": self.handle_TAB,
                b"\x0b": self.handle_CTRL_K,  # CTRL-K
                b"\x0c": self.handle_CTRL_L,  # CTRL-L
                b"\x0e": self.handle_DOWN,  # CTRL-N
                b"\x10": self.handle_UP,  # CTRL-P
                b"\x15": self.handle_CTRL_U,  # CTRL-U
                b"\x16": self.handle_CTRL_V,  # CTRL-V
                b"\x1b": self.handle_ESC,  # ESC
            }
        )
    def timeoutConnection(self) -> None:
        """
        this logs out when connection times out
        """
        assert self.terminal is not None
        self.terminal.write(b"timed out waiting for input: auto-logout\n")
        HoneyPotBaseProtocol.timeoutConnection(self)
    def connectionLost(self, reason):
        HoneyPotBaseProtocol.connectionLost(self, reason)
        recvline.HistoricRecvLine.connectionLost(self, reason)
        self.keyHandlers = {}
    def initializeScreen(self) -> None:
        """
        Overriding super to prevent terminal.reset()
        """
        self.setInsertMode()
    def characterReceived(self, ch, moreCharactersComing):
        if self.terminal is None:
            return
        # A real shell doesn't read your next line until the current
        # command finishes. Without this guard, typing ahead while an LLM
        # response is still pending lets that async write land wherever
        # the cursor happens to be mid-typing, corrupting the display.
        # Rather than dropping this input outright — which silently ate
        # every command after the first from any client that sends several
        # in a burst without waiting for each prompt (typical of scripted
        # tools) — queue it and replay it once the current command finishes.
        if self._command_pending:
            if len(self._queued_input) < self._MAX_QUEUED_INPUT:
                self._queued_input.append(("char", ch, moreCharactersComing))
            return
        if self.mode == "insert":
            self.lineBuffer.insert(self.lineBufferIndex, ch)
        else:
            self.lineBuffer[self.lineBufferIndex : self.lineBufferIndex + 1] = [ch]
        self.lineBufferIndex += 1
        if not self.password_input:
            self.terminal.write(ch)
    def handle_RETURN(self) -> None:
        if self._command_pending:
            if len(self._queued_input) < self._MAX_QUEUED_INPUT:
                self._queued_input.append(("return",))
            return
        if self.lineBuffer:
            self.historyLines.append(b"".join(self.lineBuffer))
        self.historyPosition = len(self.historyLines)
        recvline.RecvLine.handle_RETURN(self)
    def handle_CTRL_C(self) -> None:
        pass
    def handle_CTRL_D(self) -> None:
        if self.terminal is not None:
            self.terminal.loseConnection()
    def handle_TAB(self) -> None:
        pass
    def handle_CTRL_K(self) -> None:
        if self.terminal is None:
            return
        self.terminal.eraseToLineEnd()
        self.lineBuffer = self.lineBuffer[0 : self.lineBufferIndex]
    def handle_CTRL_L(self) -> None:
        """
        Handle a 'form feed' byte - generally used to request a screen
        refresh/redraw.
        """
        if self.terminal is None:
            return
        self.terminal.eraseDisplay()
        self.terminal.cursorHome()
        self.drawInputLine()
    def handle_CTRL_U(self) -> None:
        if self.terminal is None:
            return
        for _ in range(self.lineBufferIndex):
            self.terminal.cursorBackward()
            self.terminal.deleteCharacter()
        self.lineBuffer = self.lineBuffer[self.lineBufferIndex :]
        self.lineBufferIndex = 0
    def handle_CTRL_V(self) -> None:
        pass
    def handle_ESC(self) -> None:
        pass
class HoneyPotInteractiveTelnetProtocol(HoneyPotInteractiveProtocol):
    """
    Specialized HoneyPotInteractiveProtocol that provides Telnet specific
    overrides.
    """
    def __init__(self, avatar):
        HoneyPotInteractiveProtocol.__init__(self, avatar)
    def getProtoTransport(self):
        """
        Due to protocol nesting differences, we need to override how we grab
        the proper transport to access underlying Telnet information.
        """
        return self.terminal.transport.session.transport