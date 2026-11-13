#!/usr/bin/env python3
# usage: tuicap.py SOCK "step,step,..." ; steps: wait:S | key:NAME | text:... | dump:LABEL
import socket, sys, time, select
sys.path.insert(0, '/tmp/i7ll-pyte'); import pyte
KEYS={'tab':'\t','stab':'\x1b[Z','right':'\x1b[C','left':'\x1b[D','down':'\x1b[B','up':'\x1b[A','enter':'\r','esc':'\x1b','redraw':'\x0c','f5':'\x1b[15~','f10':'\x1b[21~','f12':'\x1b[24~','pgdn':'\x1b[6~'}
s=socket.socket(socket.AF_UNIX); s.connect(sys.argv[1]); s.setblocking(False)
scr=pyte.Screen(80,25); st=pyte.ByteStream(scr)
def pump(sec):
    end=time.time()+sec
    while time.time()<end:
        r,_,_=select.select([s],[],[],0.1)
        if r:
            try: d=s.recv(65536)
            except BlockingIOError: continue
            if not d: return
            st.feed(d)
for step in sys.argv[2].split(','):
    k,_,v=step.partition(':')
    if k=='wait': pump(float(v))
    elif k=='key': s.send(KEYS[v].encode()); pump(0.8)
    elif k=='text': s.send(v.encode()); pump(0.5)
    elif k=='dump':
        print('=== %s ==='%v); print('\n'.join(l.rstrip() for l in scr.display).rstrip()); print()
