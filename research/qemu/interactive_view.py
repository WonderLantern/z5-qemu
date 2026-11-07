# SPDX-License-Identifier: GPL-2.0-or-later
"""Z5 模拟器交互查看页（`boot_probe.py --interactive-port`）。

只在 127.0.0.1 上提供：最新 LCD 画面（PNG）、状态 JSON、按键队列。按键由探针主线程经原厂 AO 入口
`0x1059AE16` 发送（与 Q4 相同），本模块不接触 GDB 连接。画面为模拟器扫描输出，`camera_verified: false`。
"""
import json
import queue
import struct
import threading
import zlib
from http.server import BaseHTTPRequestHandler, ThreadingHTTPServer
from urllib.parse import parse_qs, urlparse


def ppm_to_png(data):
    """QEMU screendump PPM ("P6\\n<w> <h>\\n255\\n" + RGB) to PNG bytes."""
    magic, size, maxval, pixels = data.split(b'\n', 3)
    width, height = map(int, size.split())
    if magic != b'P6' or maxval != b'255' or len(pixels) < width * height * 3:
        raise ValueError('unexpected screendump format')
    pixels = pixels[:width * height * 3]

    def chunk(kind, payload):
        return struct.pack('>I', len(payload)) + kind + payload + struct.pack('>I', zlib.crc32(kind + payload))
    rows = b''.join(b'\0' + pixels[y * width * 3:(y + 1) * width * 3] for y in range(height))
    return (b'\x89PNG\r\n\x1a\n' + chunk(b'IHDR', struct.pack('>2I5B', width, height, 8, 2, 0, 0, 0)) +
            chunk(b'IDAT', zlib.compress(rows, 1)) + chunk(b'IEND', b''))


PAGE = '''<!doctype html><html lang="zh-CN"><head><meta charset="utf-8">
<meta name="viewport" content="width=device-width,initial-scale=1"><title>Z5 模拟器</title>
<style>
:root{--bg:#16181c;--panel:#22252b;--key:#30343c;--keyhi:#3d4450;--text:#e8e8e8;--muted:#9aa0aa;--accent:#f2c200}
body{margin:0;background:var(--bg);color:var(--text);font:14px system-ui,sans-serif;display:flex;justify-content:center}
main{padding:16px;max-width:1100px;width:100%;box-sizing:border-box}
h1{font-size:16px;margin:0 0 4px}.note{color:var(--muted);margin:0 0 12px}
.row{display:flex;gap:20px;flex-wrap:wrap;align-items:flex-start}
.screen{background:#000;border:6px solid #000;border-radius:6px;line-height:0}
.screen img{width:720px;max-width:calc(100vw - 60px);height:auto;image-rendering:auto}
.pad{background:var(--panel);border-radius:10px;padding:14px;display:grid;gap:8px;min-width:230px}
.grid{display:grid;grid-template-columns:repeat(3,64px);grid-template-rows:repeat(3,48px);gap:6px;justify-content:center}
button{background:var(--key);color:var(--text);border:0;border-radius:8px;font:600 14px system-ui;cursor:pointer}
button:hover{background:var(--keyhi)}button:active{background:var(--accent);color:#000}
.side{display:grid;grid-template-columns:1fr 1fr;gap:6px}.side button{height:40px}
.stop{background:#5a2626}.stop:hover{background:#7a3030}
.status{color:var(--muted);font-size:12px;white-space:pre-line}
kbd{background:var(--key);border-radius:4px;padding:0 4px}
</style></head><body><main>
<h1>Z5 模拟器（C 1.50，原厂固件）</h1>
<p class="note">画面是模拟器 LCD 扫描输出；取景底图为主机合成的参考图，不是固件取景。按键经原厂 AO 入口发送。</p>
<div class="row">
<div class="screen"><img id="lcd" alt="LCD" src="frame.png"></div>
<div class="pad">
<div class="side"><button data-k="menu">MENU</button><button data-k="i">i</button>
<button data-k="disp">DISP</button><button data-k="help">帮助 ?</button>
<button data-k="play">播放 ▶</button><button data-k="delete">删除 🗑</button>
<button data-k="zoom_in">放大 ＋</button><button data-k="zoom_out">缩小 −</button></div>
<div class="grid"><span></span><button data-k="up">▲</button><span></span>
<button data-k="left">◀</button><button data-k="ok">OK</button><button data-k="right">▶</button>
<span></span><button data-k="down">▼</button><span></span></div>
<div class="status" id="status">连接中…</div>
<div class="status">键盘：方向键、<kbd>Enter</kbd>=OK、<kbd>M</kbd>=MENU、<kbd>I</kbd>=i、<kbd>D</kbd>=DISP、<kbd>H</kbd>=帮助、<kbd>P</kbd>=播放、<kbd>Del</kbd>=删除、<kbd>+</kbd>/<kbd>-</kbd>=放大/缩小</div>
<button class="stop" id="stop" style="height:36px">结束会话</button>
</div></div></main>
<script>
const keymap={ArrowUp:'up',ArrowDown:'down',ArrowLeft:'left',ArrowRight:'right',Enter:'ok',m:'menu',M:'menu',i:'i',I:'i',p:'play',P:'play',Delete:'delete',d:'disp',D:'disp','+':'zoom_in','=':'zoom_in','-':'zoom_out',h:'help',H:'help'};
function send(k){fetch('key?name='+k,{method:'POST'}).catch(()=>{});}
document.querySelectorAll('button[data-k]').forEach(b=>b.onclick=()=>send(b.dataset.k));
addEventListener('keydown',e=>{const k=keymap[e.key];if(k){e.preventDefault();send(k);}});
document.getElementById('stop').onclick=()=>{if(confirm('结束模拟器会话？'))fetch('stop',{method:'POST'});};
const img=document.getElementById('lcd');let frame=-1;
async function tick(){try{const s=await (await fetch('status.json',{cache:'no-store'})).json();
document.getElementById('status').textContent=(s.running?'运行中':'已结束')+' · 客体时间 '+(s.guest_ms/1000).toFixed(1)+' s · 已按键 '+s.presses+(s.pending?' · 排队 '+s.pending:'')+(s.message?'\\n'+s.message:'');
if(s.frame!==frame){frame=s.frame;img.src='frame.png?f='+frame;}}catch(e){document.getElementById('status').textContent='连接已断开';}
setTimeout(tick,250);}
tick();
</script></body></html>'''


class Session:
    def __init__(self, port, keys):
        self.keys = set(keys)
        self.queue = queue.Queue()
        self.lock = threading.Lock()
        self.png, self.frame, self.guest_ms, self.presses = b'', 0, 0, 0
        self.stopped = False
        self.message = ''
        session = self

        class Handler(BaseHTTPRequestHandler):
            def log_message(self, *args):
                pass

            def send(self, code, body, kind):
                self.send_response(code)
                self.send_header('Content-Type', kind)
                self.send_header('Cache-Control', 'no-store')
                self.send_header('Content-Length', str(len(body)))
                self.end_headers()
                self.wfile.write(body)

            def do_GET(self):
                path = urlparse(self.path).path
                if path == '/':
                    self.send(200, PAGE.encode('utf-8'), 'text/html; charset=utf-8')
                elif path == '/frame.png':
                    with session.lock:
                        png = session.png
                    self.send(200 if png else 503, png or b'no frame yet', 'image/png' if png else 'text/plain')
                elif path == '/status.json':
                    with session.lock:
                        body = dict(running=not session.stopped, frame=session.frame, guest_ms=session.guest_ms,
                                    presses=session.presses, pending=session.queue.qsize(), message=session.message)
                    self.send(200, json.dumps(body).encode(), 'application/json')
                else:
                    self.send(404, b'not found', 'text/plain')

            def do_POST(self):
                url = urlparse(self.path)
                if url.path == '/key':
                    name = parse_qs(url.query).get('name', [''])[0]
                    if name not in session.keys or session.queue.qsize() >= 16:
                        self.send(400, b'rejected', 'text/plain')
                        return
                    session.queue.put(name)
                    self.send(202, b'queued', 'text/plain')
                elif url.path == '/stop':
                    session.stopped = True
                    self.send(202, b'stopping', 'text/plain')
                else:
                    self.send(404, b'not found', 'text/plain')

        self.server = ThreadingHTTPServer(('127.0.0.1', port), Handler)
        self.thread = threading.Thread(target=self.server.serve_forever, daemon=True)

    def start(self):
        self.thread.start()

    def next_key(self):
        try:
            return self.queue.get_nowait()
        except queue.Empty:
            return None

    def publish(self, png, guest_ms, presses, message=''):
        with self.lock:
            self.png, self.guest_ms, self.presses, self.message = png, guest_ms, presses, message
            self.frame += 1

    def close(self, message='会话已结束'):
        with self.lock:
            self.message = message
        self.stopped = True
        self.server.shutdown()
        self.server.server_close()
