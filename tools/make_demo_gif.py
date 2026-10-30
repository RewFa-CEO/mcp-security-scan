#!/usr/bin/env python3
"""Render a crisp demo GIF of mcpsec using Pillow + ffmpeg (no vhs needed)."""
import os, subprocess, tempfile, shutil
from PIL import Image, ImageDraw, ImageFont

SCALE = 2
CW, CH, PADX, PADY = 10, 18, 22, 12            # per-char + padding
LINES = 22
TITLE = "mcpsec"

# font
F = "/Library/Fonts/Menlo.ttc"
if not os.path.exists(F):
    F = "/System/Library/Fonts/Menlo.ttc"
try:
    font = ImageFont.truetype(F, 15 * SCALE // 2 * 2, index=0)
except Exception:
    font = ImageFont.load_default()

BG      = (24, 24, 28)
BAR     = (40, 40, 48)
TITLEC  = (150, 150, 160)
FG      = (225, 225, 225)
PROMPT  = (110, 200, 110)
DIM     = (130, 130, 140)
HIGH    = (235, 95, 88)
MED     = (238, 180, 80)
OK      = (90, 205, 110)
WHITE   = (240, 240, 240)

# (text, color) lines for each command's output (real mcpsec output, trimmed)
BATCH = [
 ("## MCP batch scan — examples", WHITE),
 ("", None),
 ("**3 config(s), 9 finding(s):**", WHITE),
 ("- examples/mcp.clean.json      -> clean", OK),
 ("- examples/mcp.remote.json     -> 1 high, 1 medium", HIGH),
 ("- examples/mcp.sample.json     -> 5 high, 2 medium", HIGH),
 ("", None),
 ("## top offenders (all files)", WHITE),
 ("- [HIGH] ssrf-to-internal — local-dash: url points to internal/loopback host", HIGH),
 ("- [HIGH] secret-in-config — shell-tools: OpenAI-style API key in config", HIGH),
 ("- [HIGH] prompt-injection — run_shell description contains directive text", HIGH),
 ("- [MEDIUM] exfil-surface — fetch accepts attacker-controlled url param", MED),
]
PLAIN = [
 ("# MCP security scan — examples/mcp.sample.json", WHITE),
 ("", None),
 ("**7 finding(s):** 5 high, 2 medium", WHITE),
 ("", None),
 ("## [HIGH] secret-in-config — shell-tools/-", HIGH),
 ("- Evidence: OpenAI-style API key detected near: ...sk-abcd1234a***", DIM),
 ("- Fix: move the credential out of config; rotate it (treat it as leaked).", DIM),
 ("## [HIGH] prompt-injection-signal — shell-tools/run_shell", HIGH),
 ("- Fix: treat tool descriptions as UNTRUSTED input.", DIM),
 ("## [MEDIUM] exfil-surface — shell-tools/fetch", MED),
 ("- Fix: allowlist permitted hosts.", DIM),
 ("(exit 1: high findings present — CI-ready)", DIM),
]

COMMANDS = [
 ("python3 -m mcpsec examples --batch", BATCH),
 ("python3 -m mcpsec examples/mcp.sample.json", PLAIN),
]

W = 1350
H = PADY * 2 + (LINES + 1) * CH + 26  # +title bar

def new_img():
    return Image.new("RGB", (W, H), BG)

def draw_title(d):
    d.rectangle([0, 0, W, 24], fill=BAR)
    for i in range(3):
        d.ellipse([10 + i * 16, 8, 20 + i * 16, 18], fill=(120, 120, 130))
    d.text((W // 2 - 90, 4), TITLE, fill=TITLEC, font=font)

def render(cmd_so_far, out_lines):
    img = new_img()
    d = ImageDraw.Draw(img)
    draw_title(d)
    top = 30
    x, y = PADX, top
    d.text((x, y), "❯", fill=PROMPT, font=font)
    d.text((x + 20, y), cmd_so_far, fill=FG, font=font)
    oy = y + CH
    for text, color in out_lines:
        if color is None:
            color = FG
        d.text((PADX, oy), text, fill=color, font=font)
        oy += CH
    return img

frames = []
def add(n, f):
    for _ in range(n):
        frames.append(f)

# 1) start blank
blank = render("", [])
add(20, blank)

for idx, (cmd, outs) in enumerate(COMMANDS):
    # type the command
    for i in range(1, len(cmd) + 1):
        f = render(cmd[:i], [])
        add(2, f)
    add(6, render(cmd, []))                    # pause, nothing yet
    # reveal output line by line
    for k in range(len(outs) + 1):
        shown = outs[:k]
        f = render(cmd, shown)
        add(5, f)
    add(30, render(cmd, outs))                  # hold result
    if idx == 0:
        # screen "scrolls": clear to start next command (new window)
        add(14, render("", []))

# end beat: a scoped "clean" pass
add(14, render("", []))
SC_CMD = "python3 -m mcpsec etoro --scope scope.txt"
SC_OUT = [("## scope-targeted fastpass: scope.txt -> www.etoro.com ...", WHITE),
          ("", None),
          ("(no hit on the in-scope routes — normal for a hardened target)", DIM)]
for i in range(1, len(SC_CMD) + 1):
    add(1, render(SC_CMD[:i], []))
add(6, render(SC_CMD, []))
for k in range(len(SC_OUT) + 1):
    add(5, render(SC_CMD, SC_OUT[:k]))
add(30, render(SC_CMD, SC_OUT))

# --- encode ---
with tempfile.TemporaryDirectory() as td:
    for i, f in enumerate(frames):
        f.save(os.path.join(td, f"f{i:04d}.png"))
    gif = "docs/demo.gif"
    os.makedirs("docs", exist_ok=True)
    pal = os.path.join(td, "pal.png")
    subprocess.run(["ffmpeg", "-y", "-framerate", "20", "-i", os.path.join(td, "f%04d.png"),
                    "-vf", f"scale={W}:{H}:flags=lanczos,palettegen", pal],
                   check=True, capture_output=True)
    subprocess.run(["ffmpeg", "-y", "-framerate", "20", "-i", os.path.join(td, "f%04d.png"),
                    "-i", pal, "-lavfi", f"scale={W}:{H}:flags=lanczos[x];[x][1:v]paletteuse",
                    "-loop", "0", gif], check=True, capture_output=True)
print(f"GIF: {os.path.abspath(gif)}  ({len(frames)} frames)")
