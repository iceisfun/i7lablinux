# TUI: full-screen console UI and the `labtui` library

> **Superseded by docs/PLAN.md (authoritative) on:** PLAN.md C2 (TUI is a thread in i7labd, no `i7lab-tui` binary), section 12 P5 (v0.1 pages: Overview, PCIe, Storage read-only, Network, Log, About; Actions reboot/poweroff/shell), section 6 (write dialogs type the full serial; v0.2), `tui.dump` and `i7labd::events` (section 4.4). Read PLAN.md first; where this note disagrees, PLAN.md wins.


Status: design (R4). Crate `labtui` (library, std + libc FFI only, no terminfo, no curses). The
console binary `i7lab-tui` (started by `i7lab-init` on tty1, and on the serial console if one is
configured) uses `labtui` plus `labprobe` data.

## Assumptions

- Console is the Linux virtual console on a framebuffer (`fbcon`) or an ANSI terminal on a serial
  line. Both understand a practical xterm/VT100 subset. We target: CSI cursor movement, SGR
  colours (16 colour, 256 colour and truecolor probed), alternate screen (`ESC[?1049h`), cursor
  hide (`ESC[?25l`), clear, line wrap off (`ESC[?7l`).
- The Linux console does not support truecolor or alt screen reliably. Detect: `TERM=linux`
  -> 16 colours, no alt screen (we clear and restore), box drawing via the console's
  unicode font (UTF-8 mode set with `ESC%G`); fallback ASCII frames (`+-|`) when the font lacks
  glyphs or when running on a serial port (`i7lab.ascii=1` or `ttyS*`).
- Framebuffer console font: the kernel built-in font (we compile with `FONT_TER16x32` and
  `FONT_SUPPORT`, and `CONFIG_FONT_AUTOSELECT` off) selected at boot with `fbcon=font:TER16x32` on
  displays wider than 2560 px, so a 4K console shows a readable ~240x67 grid instead of tiny
  text. Console size comes from the kernel, not from us. We only read it.
- Keyboard through the tty line discipline in raw mode (no `/dev/input` in the TUI; escape
  sequences for arrow keys come from the kernel keymap).
- Single process, single thread for rendering, one extra thread for data refresh. No mouse in v0.x.

## Terminal control (libc FFI)

```rust
// labtui::term
pub struct RawTerm { fd: RawFd, saved: libc::termios, alt: bool }
impl RawTerm {
    pub fn enter(fd: RawFd) -> io::Result<RawTerm>;   // tcgetattr, cfmakeraw-like, VMIN=0 VTIME=1
    pub fn size(&self) -> (u16 /*cols*/, u16 /*rows*/);// ioctl(TIOCGWINSZ), fallback 80x25 or $COLUMNS/$LINES
    pub fn restore(&mut self);                         // also run from Drop and from a panic hook
}
```

- Raw mode: clear `ICANON|ECHO|ISIG|IEXTEN`, `IXON|ICRNL|BRKINT|INPCK|ISTRIP`, `OPOST`; set `CS8`;
  `VMIN=0, VTIME=1` (100 ms read timeout) so the loop can also tick. `ISIG` is cleared
  so Ctrl-C arrives as a key, but we still map Ctrl-C to "quit dialog" to avoid trapping the operator.
- Restore on: normal exit, panic (panic hook), SIGTERM/SIGHUP, and `execve` of a shell (`F10`
  drops to `i7labsh` with the terminal restored, re-enters when the shell exits).
- Resize: `SIGWINCH` handler (sigaction via libc, async-signal-safe: it only sets an `AtomicBool`).
  The loop polls the flag, calls `TIOCGWINSZ`, re-lays-out and forces a full redraw. On a serial
  console there is no SIGWINCH; `r` or F5 does a manual size query through the cursor trick (move the
  cursor to 999,999, `ESC[6n`, parse the reply) and `Ctrl-L` forces a redraw.
- Output is built into one `Vec<u8>` per frame and written with a single `write(2)` (avoids tearing
  and slow tty flush on the framebuffer).

## Layout

Minimum 80x25. Below that: a single centred message "terminal too small (need 80x25)".

```
 i7lablinux 0.3  host:rack3-m720q  up 00:12:44  ip 192.0.2.141  mac 3c:ec:ef:..     <- header (row 0)
 [Overview] PCIe  Storage  Network  USB  Sensors  Log  Actions                      <- tab bar (row 1)
 +- Left pane --------------------+ +- Detail pane --------------------------------+
 | list / tree                     | | selected item details                         |
 +---------------------------------+ +-----------------------------------------------+
 F1 Help  F2 Probe  F5 Refresh  F10 Shell  Tab next pane  q Quit  attention: 2         <- status/key bar (last row)
```

Responsive rules, evaluated each frame from `(cols, rows)`:

| class        | cols x rows        | layout |
|--------------|--------------------|--------|
| compact      | 80..119 x 25..39   | one pane at a time, list view; Enter drills in, ESC goes back; tab bar abbreviates to 3-letter labels if needed |
| standard     | 120..199 x 30..59  | list + detail side by side (35/65 split) |
| wide (4K)    | >= 200 x >= 50     | list + detail + third "live" column (graphs: temperatures, throughput sparklines) ; bigger tables show more columns (BARs, AER counters) |

On a 4K framebuffer with the 16x32 font the grid is about 240x67 so the wide layout is the one used
there. The layout code never assumes pixel sizes, only cells.

## Keys

- Left/Right: previous/next tab (when the tab bar has focus) or collapse/expand in a tree.
- Tab / Shift-Tab (`ESC[Z`): cycle focus between tab bar, list pane, detail pane.
- Up/Down, PgUp/PgDn, Home/End: move selection / scroll.
- Enter: activate (drill in, run action selected in Actions, open confirmation).
- ESC: close dialog / go back / return focus to the tab bar. A lone ESC is told apart from an escape
  sequence by waiting 50 ms (VTIME) for the next byte.
- `q`: quit dialog ("leave TUI? shell stays available"); Ctrl-C identical.
- F1 help overlay (key list for the current page), F2 probe now, F3 filter, F4 sort,
  F5 redraw and refresh, F6..F8 jump to Log/Actions/Overview (aliases), F9 toggle ASCII/unicode
  frames, F10 shell, F12 about + version + build id. On consoles where F-keys misbehave, the same
  actions have letter keys (`?` help, `r` refresh, `/` filter, `s` shell).
- Numbers 1..8 jump to a tab.
- Key decoding (`labtui::input`) is a pure state machine `fn feed(&mut self, byte) -> Option<Key>`
  handling CSI `ESC[A..D`, `ESC[1;5C` (modifiers), `ESC[15~` (F5), `ESCOP`..`ESCOS` (F1-F4 on xterm),
  `ESC[[A` (Linux console F1-F5), UTF-8 multi-byte chars. Unit-tested with byte vectors.

## Pages

1. **Overview**: system identity (product, serial, BIOS, boot mode, secure boot), CPU model/cores/
   freq/temp, memory used/total and DIMM summary, uptime, load, IP addresses and link state per NIC,
   disks (count, SMART verdicts), "attention" list (AER errors, SMART warn, degraded PCIe link, high
   temperature, kernel log tags), and a small activity pane (last 5 audit entries: who did what).
2. **PCIe**: tree of bridges/devices (indented, expandable). Row: bdf, vendor name, device name,
   class, driver, link `x4 Gen3` (red when degraded). Detail pane: ids, BARs, IOMMU group, AER counters,
   ASPM, power state, capability list.
3. **Storage**: table of disks (name, type, size, model, serial, SMART, state: in-use/mounted/boot
   media). Detail: partition table, filesystem signatures, SMART attributes, test results. Sub-action
   keys on the page: `t` read test, `w` write test (opens confirmation with the safety gate reasons
   shown in red if refused), live progress bar and latency histogram when a test runs.
4. **Network**: NIC list with link/speed/MAC/IP/rx-tx rates; detail: ethtool stats, LLDP neighbour,
   WoL state, DHCP offers seen. `d` runs DHCP discover, `p` ping dialog.
5. **USB**: tree of buses/hubs/devices, speed, driver, power.
6. **Sensors**: temperatures with sparkline history, fans, voltages, power, battery; thresholds colour the value
   (green/yellow/red).
7. **Log**: scrollable kernel + lab log with level colours, search (`/`), follow mode (`f`), tag filter.
8. **Actions**: menu: reboot, power off, boot next (list from UEFI), kexec, rescan PCI, set WoL, set time, run stress, wipe,
   open shell, show key fingerprint, enrol keys. Every Class D action shows a confirmation dialog
   (summary text from labprobe + typed token or `y` + Enter for non-disk actions, retype the last 4
   characters of the device serial for disk actions). The dialog also names the action source: local
   console always passes the "operator is physically present" rule but still confirms.

Colours (semantic, mapped by `Theme`): frame, title, tab-active, tab-inactive, ok, warn, bad,
dim, selection (reverse video), accent. Default theme is dark. A monochrome theme (bold/reverse only)
is used when `TERM=dumb` or `i7lab.mono=1`.

## Renderer API (`labtui`)

Immediate-mode, cell buffer, diff-based output. No widget tree retained between frames except the
double buffer; application state lives in the caller.

```rust
pub struct Cell { pub ch: char, pub fg: Color, pub bg: Color, pub attr: Attr } // Attr: BOLD|DIM|REVERSE|UNDERLINE
pub enum Color { Default, Ansi(u8 /*0..15*/), Idx(u8), Rgb(u8,u8,u8) }          // degraded to 16 colours per ColorMode

pub struct Buffer { w: u16, h: u16, cells: Vec<Cell> }
impl Buffer {
    pub fn new(w: u16, h: u16) -> Self;
    pub fn resize(&mut self, w: u16, h: u16);
    pub fn set(&mut self, x: u16, y: u16, cell: Cell);
    pub fn put_str(&mut self, x: u16, y: u16, s: &str, style: Style) -> u16;   // returns columns written; clips; wide char aware
    pub fn fill(&mut self, r: Rect, ch: char, style: Style);
}

pub struct Rect { pub x: u16, pub y: u16, pub w: u16, pub h: u16 }
impl Rect { pub fn split_h(&self, left: u16) -> (Rect, Rect); pub fn split_v(&self, top: u16) -> (Rect, Rect);
            pub fn inset(&self, n: u16) -> Rect; pub fn centered(&self, w: u16, h: u16) -> Rect; }

pub struct Style { pub fg: Color, pub bg: Color, pub attr: Attr }

// widgets are plain functions drawing into a Buffer region and returning layout facts
pub fn frame(buf: &mut Buffer, r: Rect, title: &str, style: Style, set: BorderSet /*Unicode|Ascii|Double*/);
pub fn tabs(buf: &mut Buffer, r: Rect, labels: &[&str], active: usize, theme: &Theme);
pub fn list(buf: &mut Buffer, r: Rect, state: &mut ListState, rows: &[Row], theme: &Theme);
pub fn table(buf: &mut Buffer, r: Rect, state: &mut TableState, cols: &[Col], rows: &[Vec<Span>], theme: &Theme);
pub fn tree(buf: &mut Buffer, r: Rect, state: &mut TreeState, nodes: &[TreeNode], theme: &Theme);
pub fn text(buf: &mut Buffer, r: Rect, lines: &[Line], scroll: usize);          // Line = Vec<Span{text, Style}>
pub fn gauge(buf: &mut Buffer, r: Rect, ratio: f32, label: &str, theme: &Theme);
pub fn sparkline(buf: &mut Buffer, r: Rect, samples: &[f32], theme: &Theme);    // uses ▁▂▃▄▅▆▇█ or ASCII " .:-=+*#"
pub fn dialog(buf: &mut Buffer, screen: Rect, d: &Dialog, theme: &Theme);       // modal: title, body, buttons

pub struct Screen { /* front + back Buffer, ColorMode, term capabilities */ }
impl Screen {
    pub fn new(term: &RawTerm, caps: Caps) -> Self;
    pub fn buffer(&mut self) -> &mut Buffer;           // draw here
    pub fn present(&mut self) -> io::Result<()>;       // diff back vs front, emit minimal CSI, swap
    pub fn invalidate(&mut self);                      // force full repaint (after resize, Ctrl-L)
}

pub enum Event { Key(Key), Resize(u16, u16), Tick }
pub struct EventLoop { /* poll(2) on tty fd, timer, SIGWINCH flag, self-pipe for data refresh */ }
impl EventLoop { pub fn next(&mut self, timeout: Duration) -> Event; }
```

Design decisions:

- Diff output: per row, find changed spans, emit `CSI y;x H` then SGR changes only when attr/colour
  differs from the cursor's current state, then chars. Cost per frame is small on the 4K grid.
- Wide characters: a small `wcwidth` table (East Asian wide, combining) ships in `labtui::width`;
  the lab only expects ASCII + box drawing, but device names and USB strings can contain anything.
  Non-printable bytes (control chars, invalid UTF-8) are replaced with `?` before reaching the
  terminal, so a hostile USB product string cannot inject escape sequences into the operator
  console. This is mandatory: all strings from probes pass through `labtui::sanitize`.
- Text measurement and truncation are in cells, with an ellipsis marker.
- All drawing functions are pure over the buffer, so a `Buffer` can be rendered to a string for
  golden-file tests (`Buffer::to_text()` plus an ANSI dump). Tests: layout classes at 80x25, 132x43,
  240x67; key decoder vectors; diff output on known changes; sanitize against escape injection.
- No global state; the app owns `AppState { page, focus, selections, data: Arc<Snapshot>, dialog }`
  and a `fn draw(&AppState, &mut Buffer)` function; the data thread produces `Snapshot`s and wakes the
  loop via a self-pipe. Probes never run on the render thread.

## Remote console parity

The same `labtui` render path can target a network client: `i7labctl tui --ether <mac>` (and
`--http`) streams the already-composed frame as ANSI bytes over the authenticated channel, and sends
key events back, so a remote operator sees the identical screen. The remote client uses its own
terminal size and the host re-lays-out on a `Resize` event from the client. (v0.5)

## Unsupported / future

Mouse, scrollback, IME input, non-US layouts, images, truecolor on the VT console, and sixel are out of scope.
