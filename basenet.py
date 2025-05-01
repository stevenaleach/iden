#!/usr/bin/env python3
#
#    IDEN basenet.py 0.1.1
#
#    Copyright (C) 2025 Steven A. Leach
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    See <https://www.gnu.org/licenses/> for details.
#
# Unified basenet.py script (localhost and public server modes)
# Copyright (C) 2025 Steven A. Leach

from   fastapi import FastAPI, Request
from   fastapi.responses import PlainTextResponse, HTMLResponse
from   hashlib import sha256
import uvicorn, sys, socket, yaml, markdown, re, time, os, struct
from concurrent.futures import ThreadPoolExecutor
from nacl.signing import SigningKey, VerifyKey
from nacl.exceptions import BadSignatureError
from fastapi.responses import RedirectResponse
# --- Config ---

IS_PUBLIC_SERVER = False # Set to True when deploying behind nginx
MAX_EXPANSIONS_PER_PASS = 16  # Limit number of expansions per document pass
HTTP_HOST = "127.0.0.1"
HTTP_PORT = 8008
BASE_NET_PORT = 4040
SIGNAL_PORT = 4004
if not IS_PUBLIC_SERVER:
    REWRITE_LINK_PREFIX = "http://127.0.0.1:8008/" 
else:
    REWRITE_LINK_PREFIX = "https://example.net/"
NODE_DIR = os.path.expanduser("~/.iden")
PRIV = os.path.join(NODE_DIR, "private_key.bin")
PUB  = os.path.join(NODE_DIR, "public_key.bin")
NODES_TXT = os.path.join(NODE_DIR, "nodes.txt")
PREVIEW_DIR = os.path.expanduser("~/drafts")
HOMEPAGE_FILE = "README.md"
MAX_SIGPROX_THREADS = 32

#------------------------------------------------------------------------------
# Global "iden" and "state" utility functions
#------------------------------------------------------------------------------
def crypt_state(state,password):
    ''' Encrypt (or decrypt) a state by xor of password hash. '''
    from hashlib import sha256
    if type(state) == str:
        state = unpack_state(state)
    p = sha256( password.encode(encoding='utf-8') ).digest()
    s = state[:-4]; x = bytes(a ^ b for (a,b) in zip(s, p))
    return(x+state[-4:])

def pack_state(state):
    ''' Return string represtentation for a state. '''
    from leb128 import i as varint
    import base58
    if type(state) == str:
        return(state)
    return((b'z'+base58.b58encode(bytes(varint.encode(0)+state))).decode())

def unpack_state(s):
    ''' Return a binary state given a string representation. '''
    import base58
    if type(s) == bytes:
        return(s)
    s = s[1:]; s = base58.b58decode(s)
    assert s[0] == 0
    s = s[1:]
    return(s)

def state_idx(state):
    ''' Returns integer state index for a state. '''
    if type(state) == str:
        state = unpack_state(state)
    return(int.from_bytes(state[-4:],'little',signed=False))

def step(state, start=False):
    ''' Advance a state one generation step.'''
    from hashlib import sha256
    a = sha256(state).digest(); b = int.from_bytes(state[-4:],'little')
    return(a+(b-1).to_bytes(4,'little',signed=False))

def print_state(state):
    ''' Prints out a hex state as a grid to be hand copied onto paper. '''
    if type(state) == str:
        state = unpack_state(state)
    print(pack_state(state),'\n')
    s=state.hex();codes=[];i=0
    while len(s):
        if i > 3:
            print('\n'+'-----+------+------+------'); i=0
        if i:
            print('| ',end='')
        print(s[:4].upper(), end=' ');s = s[4:]; i+=1
    print('\n')

def get_url(host, iden_str, idx = None,pub=True,home=False):
    s = host+"/iden://"+iden_str
    if idx:
        s+="."+str(idx)
    else:
        if home:
            s+=".0"
    if pub:
        s+="/pub"
    return(s)

#------------------------------------------------------------------------------
# Pad Manager functions
#------------------------------------------------------------------------------
class PadMan:
    SOCKET_PATH = os.path.expanduser("~/.iden/padman")

    @staticmethod
    def _send(opcode: bytes) -> bytes:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(PadMan.SOCKET_PATH)
                client.sendall(opcode)
                return client.recv(65536)
        except Exception as e:
            print(f"PadMan error ({opcode}):", e)
            return b""

    @staticmethod
    def idx() -> int:
        """Returns the current index as an integer."""
        raw = PadMan._send(b'ix')
        if raw:
            return int.from_bytes(raw[:4], 'little')
        return -1

    @staticmethod
    def iden_bin() -> bytes:
        """Returns the next state as a string."""
        raw = PadMan._send(b'id').decode().strip()
        return unpack_state(raw)

    @staticmethod
    def iden_str():
        """Returns the pad's iden as a string."""
        raw = PadMan._send(b'id').decode().strip()
        return(raw)


    @staticmethod
    def state_bin() -> bytes:
        """Returns the next state from padman as bytes."""
        return PadMan._send(b'st')

    @staticmethod
    def state_str():
        """Returns the next state from padman as a string."""
        return(pack_state(PadMan.state_bin()))

    @staticmethod
    def url(idx = 0,host="http://127.0.0.1:8008",pub=True, home=False):
        s = host+"/iden://"+PadMan.iden_str()
        if idx:
            s+="."+str(idx)
        else:
            if home:
                s+=".0"
        if pub:
            s+="/pub"
        print(s)
        return(s)

    @staticmethod
    def shutdown():
        """Sends a shutdown signal to the padman service."""
        PadMan._send(b'qu')

#------------------------------------------------------------------------------
# BaseNet helper functions
#------------------------------------------------------------------------------
class BaseNet:
    HOST = "127.0.0.1"
    PORT = BASE_NET_PORT 
    @staticmethod
    def _send_tcp(data: bytes, host: str = None, port: int = None) -> bytes:
        host = host or BaseNet.HOST
        port = port or BaseNet.PORT
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((host, port))
                s.sendall(data)
                response = []
                chunk = s.recv(4096)
                while chunk:
                    response.append(chunk)
                    chunk = s.recv(4096)
                return b"".join(response)
        except Exception as e:
            print("BaseNet TCP error:", e)
            return b""

    @staticmethod
    def deliver(blob: bytes, host: str = None, port: int = None) -> bytes:
        """Send a preassembled 'offer + length + payload' blob to the specified
        basenet node."""
        return(BaseNet._send_tcp(blob, 
                                 host or BaseNet.HOST, port or BaseNet.PORT))

    @staticmethod
    def get(uri: str, host: str = None, port: int = None) -> bytes:
        host = host or BaseNet.HOST
        port = port or BaseNet.PORT
        if not uri.startswith("iden://"):
            raise ValueError("URI must start with iden://")
        return BaseNet._send_tcp(b"id" + uri.encode(), host, port)

    @staticmethod
    def get_from(iden_str: str, idx: int, host: str = None, 
                 port: int = None) -> tuple[int, bytes] | None:
        """
        Attempts to retrieve a basenet frame for the given iden string and
        index. Walks backwards from idx to 0 if not found. Returns (idx, data)
        on success, None if not found.
        """
        host = host or BaseNet.HOST
        port = port or BaseNet.PORT

        for i in range(idx+1, -1, -1):
            uri = f"iden://{iden_str}.{i}"
            response = BaseNet._send_tcp(b"id" + uri.encode(), host, port)
            if response and not response.startswith(b"!"):
                return (i, response)
        return None

#------------------------------------------------------------------------------
# Iden Signaling Layer functions
#------------------------------------------------------------------------------
class IdenSignal:
    HOST = "127.0.0.1"
    PORT = SIGNAL_PORT
    @staticmethod
    def send_msg(data: bytes, host: str = HOST, port: int = PORT) -> bytes:
        """Send a raw message to the IdenSignal TCP interface."""
        host = host or IdenSignal.HOST
        port = port or IdenSignal.PORT
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((host, port))
                s.sendall(data)
                response = []
                while True:
                    chunk = s.recv(4096)
                    if not chunk:
                        break
                    response.append(chunk)
                return b"".join(response)
        except Exception as e:
            print("IdenSignal TCP error:", e)
            return b""

    @staticmethod
    def report(host: str = HOST, port: int = PORT) -> bytes:
        """Send a 'report' (re) message using iden and state from PadMan."""
        host = host or IdenSignal.HOST
        port = port or IdenSignal.PORT
        iden = PadMan.iden_bin()
        state = PadMan.state_bin()
        msg = b"re" + iden + state
        return IdenSignal.send_msg(msg, host, port)

    @staticmethod
    def dedicate(host: str = HOST, port: int = PORT) -> bytes:
        """Send a 'dedicate' (de) message using iden and state from PadMan."""
        host = host or IdenSignal.HOST
        port = port or IdenSignal.PORT
        iden = PadMan.iden_bin()
        state = PadMan.state_bin()
        msg = b"de" + iden + state
        return IdenSignal.send_msg(msg, host, port)

    @staticmethod
    def msg_count_t(t: float, host: str = HOST, port: int = PORT) -> int:
        """Send a 'ct' (count) message for the past `t` seconds. Returns number
        of messages seen."""
        host = host or IdenSignal.HOST
        port = port or IdenSignal.PORT
        payload = b"ct" + struct.pack("<d", t) # <= little-endian, d = float64
        response = IdenSignal.send_msg(payload, host, port)
        if len(response) >= 4:
            return int.from_bytes(response[:4], "little")
        return -1

    @staticmethod
    def get_messages(t: float, host: str = HOST, 
                     port: int = PORT):
        """Send a 'gt' (get_t) to get message for the past `t` seconds."""
        host = host or IdenSignal.HOST
        port = port or IdenSignal.PORT
        payload = b"gt" + struct.pack("<d", t)  # <= little-endian, d = float64
        response = IdenSignal.send_msg(payload, host=host, port=port)
        if len(response) < 70:
            return((0,None))
        size = int.from_bytes(response[:4],"little")
        return(size,response[4:])

    @staticmethod
    def idx(iden: bytes, host = "127.0.0.1", port = 4004) -> int:
        host = host or IdenSignal.HOST
        port = port or IdenSignal.PORT
        response = IdenSignal.send_msg(b'ix'+iden, host=host, port=port)
        if len(response) < 4:
            return(None)
        return( int.from_bytes(response[:4],"little") )

    @staticmethod
    def state(iden: bytes, host = "127.0.0.1", port = 4004) -> int:
        host = host or IdenSignal.HOST
        port = port or IdenSignal.PORT
        response = IdenSignal.send_msg(b'st'+iden, host=host, port=port)
        if len(response) < 4:
            return(None)
        return(response)

    @staticmethod
    def signal(iden:bytes, idx:int, host="127.0.0.1", port =4004) -> bytes:
        host = host or IdenSignal.HOST
        port = port or IdenSignal.PORT
        return(IdenSignal.send_msg(b'si'+iden+idx.to_bytes(4,'little'),
                                   host=host,port=port ))

    @staticmethod
    def version(host = None, port = None) -> str:
        host = host or IdenSignal.HOST
        port = port or IdenSignal.PORT
        return(IdenSignal.send_msg(b've', host=host, port=port))

#------------------------------------------------------------------------------
# BaseNet Frame Class
#------------------------------------------------------------------------------
class Frame:
    def __init__(self,
                 content: dict = None,
                 BASENET_PORT  = 4040,
                 SIGNAL_PORT   = 4004,
                 HOST          = "127.0.0.1"):
        self.body = content or {}

    def add_file(self, path: str, data: str):
        parts = path.strip("/").split("/")
        node = self.body.setdefault('files', {})
        for part in parts[:-1]:
            node = node.setdefault(part, {})
        node[parts[-1]] = data

    def author(self, name: str):
        self.body['author'] = name

    def geoloc(self, lat: float, lon: float):
        self.body['geoloc'] = {'lat':lat,'lon':lon}

    def lang(self, lang: str):
        self.body['lang'] = lang

    def title(self, title: str):
        self.body['title'] = title

    def link_file(self, path: str, uri: str, hash: str = None):
        link = {'link': uri}
        if hash is not None:
            link['hash'] = hash
        self.add_file(path, link)

    def time(self, timestamp: float = None):
        import time
        self.body['time'] = timestamp or time.time()

    def to_bytes(self):
        YAM = yaml.dump(self.body).encode()
        if len(YAM) <= (2**16 - 11):  # 65525 bytes max payload size
            return YAM
        else:
            print("Frame size exceeds 64KB limit.")
            return None

    def app(self, appstr: str):
        current_apps = set(
                filter(None, 
                       (s.strip() for s in self.body.get("app", 
                                                         "").split(","))))
        current_apps.add(appstr.strip())
        self.body["app"] = ",".join(sorted(current_apps))

    def pub(self,text: str, appkey = "peerpub"):
        self.body["text.md"] = text
        self.app(appkey)

    def backlink(self, host: str = "127.0.0.1", port: int = 4040):
        """
        Add a backlink to the previous frame (if any).

        Returns
        -------
        bool
            True if a backlink was added, False otherwise.
        """

        iden_str = PadMan.iden_str()
        current_idx = PadMan.idx()

        if current_idx <= 0:
            print("No previous frame to link to (idx = 0).")
            return(False)

        result = BaseNet.get_from(iden_str, current_idx - 1, host, port)

        if result is None:
            print("No previous frame found.")
            return(False)

        prev_idx, prev_data = result
        prev_hash = sha256(prev_data).hexdigest()

        self.body['prev_frame'] = {
            'idx': prev_idx,
            'hash': prev_hash
        }
        print(f"Added backlink to idx {prev_idx}, hash {prev_hash}")
        return(True)


    def backpub(self, host: str = "127.0.0.1", 
                port: int = 4040, appkey="peerpub"):
        """
        Search backward from the current idx until a frame with 'peerpub' in
        its app field is found. If found, add a text.md file linking to that
        frame and record its idx in 'lastpub'.
        """
        iden_str = PadMan.iden_str()
        current_idx = PadMan.idx()
        for i in range(current_idx + 1, -1, -1):  # start at current_idx - 1
            uri = f"iden://{iden_str}.{i}"
            data = BaseNet.get(uri, host=host, port=port)
            if not data or data.startswith(b"!"):
                continue

            try:
                parts = data.decode().split("---\n", 1)
                if len(parts) != 2:
                    raise ValueError(
                            "Expected YAML header followed by '---'")
                parsed = yaml.safe_load(parts[1])
                if not isinstance(parsed, dict):
                    print(f"Bad YAML at idx {i}: {type(parsed)}")
                    continue
            except Exception as e:
                print(f"Failed to parse YAML content at idx {i}: {e}")
                continue

            app_str = parsed.get("app", "")
            if appkey in [s.strip() for s in app_str.split(",")]:
                uri = f"iden://{iden_str}.{i}/pub"
                self.body["text.md"] = f"Prev. Pub: [ {uri} ]( {uri} )"
                print("\nMD = ", self.body["text.md"])
                self.body['lastpub'] = i
                print(f"Found previous peerpub at idx {i} → {uri}")
                return

        print("No previous peerpub post found.")

    def banner(self, text=""):
        a = '<div class="banner">\n<div class="banner-left"><a href="'
        b = '">[Home]</a></div>\n<div class="banner-center">'
        c = '</div>\n<div class="banner-right"><a href="'
        d = '">[Previous]</a></div>\n'
        e = '</div>\n'

        iden = PadMan.iden_str()
        self.home_uri = f"iden://{iden}.0/pub"
        self.ban = a + self.home_uri + b + text + c

        if "lastpub" in self.body:
            self.back_uri = f"iden://{iden}.{self.body['lastpub']}/pub"
            self.ban += self.back_uri
        else:
            self.ban += "#"

        self.ban += d + e

    def header(self,text=""):
        self.banner(text)
        if "text.md" in self.body:
            self.body["text.md"] = self.ban+"\n\n"+self.body["text.md"]+"\n\n"

    def footer(self,text=""):
        self.banner(text)
        if "text.md" in self.body:
            self.body["text.md"] = self.body["text.md"]+"\n\n"+self.ban+"\n"

#------------------------------------------------------------------------------
# BaseNet Publisher Function
#------------------------------------------------------------------------------
def Publish(body,
            page: int = 1,
            r: bytes = bytes([0] * 32),
            host: str = "127.0.0.1",
            signal_port: int = SIGNAL_PORT,
            basenet_port: int = BASE_NET_PORT,
            send = False,
            sleep=0.0):

    import time

    def Hash(b):
        return sha256(b).digest()

    def Mix(state, signal):
        assert isinstance(signal, bytes) and len(signal) == 64
        return Hash(state + signal)

    def offer_msg(iden, n, key):
        assert len(iden) == 32 and len(key) == 32
        return b'of' + iden + n.to_bytes(4, 'little') + key

    def tcp_send(data, port):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((host, port))
                s.sendall(data)
                buff = []
                response = s.recv(1380)
                while response:
                    buff.append(response)
                    response = s.recv(1380)
            return b''.join(buff)
        except Exception as e:
            print("Error:", e)
            return b""

    def unix_send(socket_path: str, data: bytes) -> bytes:
        try:
            with socket.socket(socket.AF_UNIX, socket.SOCK_STREAM) as client:
                client.connect(socket_path)
                client.sendall(data)
                return client.recv(65536)
        except Exception as e:
            print(f"Error with unix socket at {socket_path}: {e}")
            return b''

    padman = os.path.expanduser('~/.iden/padman')
    iden = unpack_state(unix_send(padman, b'id').decode())
    if not len(iden):
        print("The Pad Manager Isn't Responding.")
        return()
    state = unix_send(padman, b'st')
    if not len(state):
        print("Unable To Retrieve State From Pad Manager.")
        return()
    idx = state_idx(state)
    print("Using idx",idx)
    if hasattr(body, 'to_bytes'):
        body = body.to_bytes()

    if len(body) > (2**16 - 11):
        print("Frame size exceeds 64KB limit.")
        return(None)

    header = yaml.dump({'_': page}).encode()
    full_payload = header + b"---\n" + body

    datahash = Hash(full_payload)
    signal = datahash + r
    mix = Mix(state, signal)

    cl = b'cl' + iden + mix + idx.to_bytes(4, 'little')
    pr = b'pr' + iden + state + signal

    if send:
        print("Sending claim...")
        print(tcp_send(cl, signal_port))
        time.sleep(sleep)

        print("Sending proof...")
        print(tcp_send(pr, signal_port))

    offer = offer_msg(iden, idx, datahash)
    length = len(full_payload).to_bytes(2, 'little')
    combined = offer + length + full_payload
    if send:
        BaseNet.deliver(combined,host=host, port=basenet_port)
    return({'CLAIM':cl, 'PROOF':pr, 'PAYLOAD': combined})


# --- App Init ---

app = FastAPI()

# --- TCP  ---

def tcp_send(data, host="127.0.0.1", port=BASE_NET_PORT):
    try:
        with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
            s.connect((host, port))
            s.sendall(data)
            buff = []
            response = s.recv(1380)
            while response:
                buff.append(response)
                response = s.recv(1380)
        return b"".join(buff)
    except Exception as e:
        print("Error:", e)
        return b""

# --- Markdown Rendering ---

def rewrite_iden_links(md_text: str, prefix: str = REWRITE_LINK_PREFIX) -> str:
    i, length = 0, len(md_text)
    output = ""
    while i < length:
        # Handle escaped "\iden://"
        if md_text[i:i+8] == r'\iden://':
            output += 'iden://'
            i += 8
            continue

        # Handle unescaped "iden://
        if md_text[i:i+7] == 'iden://':
            if i == 0 or md_text[i-1] in ' \t\n([{"\'':  
                output += prefix + 'iden://'
                i += 7
                continue
            else:
                # Part of another URL or word, skip adding prefix
                output += 'iden://'
                i += 7
                continue

        # Add current character as-is
        output += md_text[i]
        i += 1

    return output


def expand_blockquote_iden_blocks(md_text: str) -> str:
    pattern = re.compile(r"(?<!\\)\|\|\|\s*(iden://[^\s|]+(?:\.[0-9]+)?(?:/[^\s|]+)*)\s*\|\|\|", 
                         re.IGNORECASE)
    count = 0
    def expand(match):
        nonlocal count
        if count >= MAX_EXPANSIONS_PER_PASS:
            return "> [[expansion limit reached]]"
        count += 1
        full_uri = match.group(1).strip()
        trimmed = full_uri[len("iden://"):]
        parts = trimmed.split("/")
        base_uri = "iden://" + parts[0]
        subkeys = [p.strip() for p in parts[1:] if p.strip()]
        try:
            response = tcp_send(base_uri.encode())
            text = response.decode("utf-8")
            yml = yaml.safe_load_all(text)
            next(yml)
            content = next(yml)
            for key in subkeys:
                if isinstance(content, dict) and key in content:
                    content = content[key]
                else:
                    break
            if isinstance(content, str):
                return "\n".join(["> " + line for line in content.splitlines()])
            else:
                return "> " + repr(content)
        except:
            return "> [[error expanding block]]"
    return pattern.sub(expand, md_text)

def expand_inline_iden_blocks(md_text: str) -> str:
    pattern = re.compile(r"(?<!\\):::\s*(iden://[^\s:]+(?:\.[0-9]+)?(?:/[^\s:]+)*)\s*:::", 
                         re.IGNORECASE)
    count = 0
    def expand(match):
        nonlocal count
        if count >= MAX_EXPANSIONS_PER_PASS:
            return "[[expansion limit reached]]"
        count += 1
        full_uri = match.group(1).strip()
        trimmed = full_uri[len("iden://"):]
        parts = trimmed.split("/")
        base_uri = "iden://" + parts[0]
        subkeys = [p.strip() for p in parts[1:] if p.strip()]
        try:
            response = tcp_send(base_uri.encode())
            text = response.decode("utf-8")
            yml = yaml.safe_load_all(text)
            next(yml)
            content = next(yml)
            for key in subkeys:
                if isinstance(content, dict) and key in content:
                    content = content[key]
                else:
                    break
            return content if isinstance(content, str) else repr(content)
        except:
            return "[[error expanding block]]"
    return pattern.sub(expand, md_text)

def extract_meta(md_text: str) -> tuple[str, str]:
    """Extract a title and extended paragraph preview from markdown."""
    title = "PeerPub Document"
    lines = md_text.strip().splitlines()

    # Title: first heading
    for line in lines:
        if line.startswith("#"):
            title = line.lstrip("#").strip()
            break

    # Description: collect valid paragraph lines
    desc_lines = []
    char_count = 0
    collecting = False
    breaks = 0

    for line in lines:
        line = line.strip()

        # Ignore junk
        if (
            not line
            or line.startswith("#")
            or line.startswith("```")
            or line.startswith(":::")
            or line.startswith("<")
            or line.startswith("|||")
            or (line.startswith("*") and line.endswith("*"))
            or (line.startswith("**") and line.endswith("**"))
            or line.startswith("@")
            or line == "[TOC]"
        ):
            if collecting:
                breaks += 1
                if breaks >= 2:
                    break
            continue

        if len(line) < 20:
            continue

        desc_lines.append(line)
        char_count += len(line)
        collecting = True
        breaks = 0  # reset if a good line follows

        if char_count >= 300:
            break

    description = " ".join(desc_lines).strip()
    if len(description) > 300:
        description = description[:297].rstrip() + "..."

    return title, description



#def render_markdown_as_html(md_text: str, title: str = None) -> HTMLResponse:
def render_markdown_as_html(
        md_text: str, title: str = None, meta: dict = None) -> HTMLResponse:
    expanded_md = expand_inline_iden_blocks(md_text)
    expanded_md = expand_blockquote_iden_blocks(expanded_md)
    rewritten_md = rewrite_iden_links(expanded_md)

    #extracted_title, description = extract_meta(md_text)
    #if not title:
    #    title = extracted_title
    extracted_title, description = extract_meta(md_text)

    if not title:
        if meta and "title" in meta and isinstance(meta["title"], str):
            title = meta["title"]
        else:
            title = extracted_title



    html_body = markdown.markdown(
        rewritten_md,
        extensions=["fenced_code", "tables", "toc", "footnotes","def_list"]
    )

    full_html = f"""
<!DOCTYPE html>
<html>
<head>
<title>{title}</title>
<meta property="og:title" content="{title}">
<meta property="og:description" content="{description}">
<meta name="twitter:card" content="summary">
<meta name="twitter:title" content="{title}">
<meta name="twitter:description" content="{description}">
<style>
dl {{
    background: #f0f0f0;
    border-left: 4px solid #ccc;
    padding: 0.75em 1em;
    margin: 2em 2em;
    font-size: 0.95em;
    border-radius: 3px;
}}

dt {{
    font-weight: bold;
    margin-top: 0.6em;
    margin-bottom: 0.2em;
    font-size: .80em;
    color: #222;
}}

dd {{
    margin-left: 1em;
    margin-bottom: 1.5em;
    font-size: 0.75em;
    color: #333;
}}

.banner {{
    display: flex;
    justify-content: space-between;
    align-items: center;
    background-color: #777;
    color: #fff;
    padding: 0.75em 1em;
    border-radius: 1px;
    margin: 0.75em 0;
    font-weight: bold;
    font-size: 0.8em;
}}

.banner a {{
    color: #fff;
    text-decoration: none;
    margin: 0 0.5em;
}}

.banner a:hover {{
    text-decoration: underline;
}}

.banner-center {{
    flex: 1;
    text-align: center;
}}


/* Responsive stacking for narrow screens */
@media (max-width: 600px) {{
    .banner {{
        flex-direction: column;
        text-align: center;
    }}

    .banner a {{
        display: block;
        margin: 0.25em 0;
    }}
}}

.toc {{
    background: #e0e0e0;
    border: 1px solid #ccc;
    padding: 1em;
    margin: 2em 0;
    border-radius: 4px;
    font-size: 0.95em;
}}

.toc ul {{
    list-style: none;
    padding-left: 1em;
}}

.toc li {{
    margin-bottom: 0.4em;
}}

.toc a {{
    text-decoration: none;
    color: #102040;
}}

.toc a:hover {{
    text-decoration: underline;
}}


body {{
    font-family: sans-serif;
    max-width: 800px;
    margin: 2em auto;
    background: #f9f9f9 !important;
    color: #111;
    padding: 1em;
}}

pre {{
    border: 1px solid #555;
    background: #e0e0e0;
    margin: 2em;
    padding: 1em;
    overflow-x: auto;
    font-size: 1.10em;
}}

code {{
    background: #e0e0e0;
    padding: 2px 4px;
    border-radius: 2px;
    font-size: 1.10em;
}}

blockquote {{
    border-left: 3px solid #808080;
    border-right: 3px solid #808080;
    border-top: 3px solid #808080;
    border-bottom: 3px solid #808080;
    background: #ffffff; !important;
    margin: 2.00em 2.00em;
    padding: 0.5em 0.5em;
    border-radius: 2px;
    color: #333;
    font-size: 0.95em;
    }}
table {{
    border-collapse: collapse;
    width: 100%;
    margin: 1em 0;
    background: #fff;
    font-size: 0.95em;
}}

th, td {{
    border: 1px solid #ccc;
    padding: 0.6em;
    text-align: left;
}}

th {{
    background-color: #ddd;
    color: #111;
    font-weight: bold;
    text-transform: uppercase;
    letter-spacing: 0.03em;
}}

tr:nth-child(even) {{
        background-color: #f9f9f9;
    }}
</style>

<!-- MathJax Support -->
<script>
window.MathJax = {{
tex: {{
    inlineMath: [['$', '$'], ['\\\\(', '\\\\)']],
    displayMath: [['$$', '$$'], ['\\\\[', '\\\\]']]
}},
svg: {{ fontCache: 'global' }}
}};
</script>
<script src="https://cdn.jsdelivr.net/npm/mathjax@3/es5/tex-svg.js" async></script>
</head>
<body>{html_body}</body>
</html>
    """
    return HTMLResponse(full_html)

# --- HTTP Handler ---

@app.get("/{path:path}")
async def handle_request(path: str, request: Request):
    path = path.strip()
    # Redirect empty path to preview homepage if configured
    if not path and HOMEPAGE_FILE:
        return RedirectResponse(url=f"/preview/{HOMEPAGE_FILE}")

    if path.startswith("preview/"):
        filename = path[len("preview/"):].strip()
        if not re.fullmatch(r"[A-Za-z0-9._-]+", filename):
            return PlainTextResponse("Invalid filename", status_code=400)
        try:
            full_path = os.path.join(PREVIEW_DIR, filename)
            with open(full_path, "r", encoding="utf-8") as f:
                md_text = f.read()
            return render_markdown_as_html(
                    md_text, title=f"Preview: {filename}")
        except Exception as e:
            return PlainTextResponse(
                    f"Error reading preview file: {e}", status_code=400)

    if not path.startswith("iden://"):
        return PlainTextResponse("Invalid request format", status_code=400)
    trimmed = path[len("iden://"):]
    parts = trimmed.split("/")
    uri_part = "iden://" + parts.pop(0)
    subkeys = [part.strip() for part in parts if part.strip()]
    response = tcp_send(uri_part.encode())
    if subkeys:
        try:
            yml = yaml.safe_load_all(response)
            next(yml)
            yml = next(yml)
            if subkeys[0] == 'pub' and 'pub' not in yml:
                if 'text.md' in yml:
                    return render_markdown_as_html(yml["text.md"], meta=yml)
            for key in subkeys:
                if isinstance(yml, dict) and key in yml:
                    yml = yml[key]
                else:
                    break  # Key not found or yml not a dict — exit early

            # Clean return depending on type
            if isinstance(yml, str):
                return PlainTextResponse(yml)
            elif isinstance(yml, (int, float)):
                return PlainTextResponse(str(yml))
            else:
                return PlainTextResponse(yaml.dump(yml, 
                                                   default_flow_style=False))

        except Exception as e:
            return PlainTextResponse(f"[Error parsing content: {e}]")
    return PlainTextResponse(response)

def display_page(url, height=600):
    """
    Display a web-page from a full HTTP/HTTPS URL, sandboxed in Jupyter.
    """
    from IPython.display import display, HTML
    import html
    iframe_html = f"""
    <iframe src="{html.escape(url)}"
            style="width: 100%; height: {height}px; border: none;"
            loading="lazy"
            sandbox="allow-scripts allow-same-origin allow-popups">
    </iframe>
    """
    display(HTML(iframe_html))

#------------------------------------------------------------------------------
# SigProx Wrappers
#------------------------------------------------------------------------------
class SigProx:

    @staticmethod
    def send(msg: bytes, node:bytes = None ,host="127.0.0.1", 
             port=8044) -> bytes:
        # Load keys from ~/.iden
        base = os.path.expanduser("~/.iden")
        with open(os.path.join(base, "private_key.bin"), "rb") as f:
            sk = SigningKey(f.read())
        pk = sk.verify_key
        my_id = pk.encode()

        # Client to Node.
        # 1. [0][ID 32][CHALLENGE 64]
        #
        challenge1 = os.urandom(64)
        s = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        s.connect((host, port))
        s.sendall(b"\x00" + my_id + challenge1)

        # Node to Client.
        # 2. [ID 32][SIG 64(CHALLENGE)][CHALLENGE 64]
        #
        server_id = s.recv(32)
        if node:
            if not server_id == node:
                print("Node ID Does Not Match.")
                s.close()
                return(None)
        sig1 = s.recv(64)
        challenge2 = s.recv(64)
        try:
            VerifyKey(server_id).verify(challenge1, sig1)
        except BadSignatureError:
            s.close()
            print("Bad server signature in handshake")
            return(None)
        # # Client to Node.
        # 3. [SIG 64(CHALLENGE+MESSAGE)][length 3 byte le][MSG]
        #
        signed = sk.sign(challenge2 + msg)
        length = len(msg).to_bytes(3, "little")
        s.sendall(signed.signature + length + msg)

        # Node to Client
        # 4. [SIG 64(T+MSG_HASH+RESPONSE)][T][MSG_HASH][RESPONSE]
        #
        sig2 = s.recv(64)
        t_raw = s.recv(8)
        t = struct.unpack("<d", t_raw)[0]
        hash_msg = s.recv(32)
        response = b""
        while True:
            chunk = s.recv(4096)
            if not chunk:
                break
            response += chunk

        blob = t_raw + hash_msg + response
        try:
            VerifyKey(server_id).verify(blob, sig2)
        except BadSignatureError:
            print("Bad signature on response")
            return(None)
        if sha256(msg).digest() != hash_msg:
            print("Hash mismatch")
            return(None)
        s.close()
        return({"response":response,"node_id": server_id,
                "t":t,"sig":sig2,"msg_hash":hash_msg})

    @staticmethod
    def report(host="127.0.0.1",port=8044,node=None):
        iden = PadMan.iden_bin()
        state = PadMan.state_bin()
        msg = b"re" + iden + state
        response = SigProx.send(msg,host=host,port=port,node=node)
        if response:
            i = response["response"][:1]
            return(int.from_bytes(i,"little"),response)
        return(None)

    @staticmethod
    def msg_count(t: float, host: str = "127.0.0.1", 
                  port: int = 8044, node=None) -> int:
        """Send a 'ct' (count) message for the past `t` seconds. 
        Returns number of messages seen."""
        payload = b"ct" + struct.pack("<d", t) # <= little-endian, d = float64
        response = SigProx.send(payload, host=host, port=port,node=node)
        if response:
            i = response["response"]
            i = int.from_bytes(i, "little")
            return(i,response)
        return(None)

    @staticmethod
    def get_messages(t: float, host: str = "127.0.0.1", 
                     port: int = 8044,node=None):
        """Send a 'gt' (get_t) to get message for the past `t` seconds."""
        payload = b"gt" + struct.pack("<d", t) # <= little-endian, d = float64
        RESPONSE = SigProx.send(payload, host=host, port=port,node=node)
        if RESPONSE:
            response = RESPONSE["response"]
            if not response:
                return(None)
            if len(response) < 70:
                return(None)
            size = int.from_bytes(response[:4],"little")
            return(size,response[4:],RESPONSE)
        return(None)

    @staticmethod
    def idx(iden: bytes, host = "127.0.0.1", port = 8044, node = None) -> int:
        RESPONSE = SigProx.send(b'ix'+iden, host=host, port=port, node=node)
        if RESPONSE:
            response = RESPONSE["response"]
            if not response:
                return(None)
            if len(response) < 4:
                return(None)
            return( int.from_bytes(response[:4],"little"),RESPONSE )
        return(None)

    @staticmethod
    def state(iden: bytes, host = "127.0.0.1", port = 8044, node=None) -> int:
        RESPONSE = SigProx.send(b'st'+iden, host=host, port=port,node=node)
        if RESPONSE:
            response = RESPONSE["response"]
            if len(response) < 32:
                return(None)
            return(response, RESPONSE)
        return(None)

    @staticmethod
    def signal(iden:bytes, idx:int, host="127.0.0.1", 
               port =8044, node=None) -> bytes:
        RESPONSE = SigProx.send(b'si'+iden+idx.to_bytes(4,'little'),
                                host=host,port=port,node=node)
        if RESPONSE:
            response = RESPONSE["response"]
            if len(response) < 64:
                return(None)
            return(response,RESPONSE)
        return(None)

    @staticmethod
    def version(host = "127.0.0.1", port = 8044,node=None) -> str:
        RESPONSE = SigProx.send(b've', host=host, port=port,node=node)
        if RESPONSE:
            return(RESPONSE["response"],RESPONSE)
        return(None)

    @staticmethod
    def get(uri: str, host: str = "127.0.0.1", 
            port: int = 8044, node=None) -> bytes:
        if not uri.startswith("iden://"):
            print("URI must start with iden://")
            return(None)
        RESPONSE = SigProx.send(b"id" + uri.encode(), 
                                host=host, port=port,node=node)
        if RESPONSE:
            response = RESPONSE["response"]
            return(response, RESPONSE)
        return(None)

    @staticmethod
    def get_from(iden_str: str, idx: int, host: str = "127.0.0.1", 
                 port: int = 8044, node=None) -> tuple[int, bytes] | None:
        """
        Attempts to retrieve a basenet frame for the given iden string and
        index. Walks backwards from idx to 0 if not found. Returns (idx, data)
        on success, None if not found. """
        for i in range(idx+1, -1, -1):
            uri = f"iden://{iden_str}.{i}"
            RESPONSE = SigProx.send(b"id" + uri.encode(), host=host, 
                                    port=port,node=node)
            if RESPONSE:
                response = RESPONSE["response"]
                if response and not response.startswith(b"!"):
                    return (i, response, RESPONSE)
            else:
                return(None)
        return(None)

# --- Entrypoint ---

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1].lower() == "sigprox":
        # --- Load Keys ---
        with open(PRIV, "rb") as f:
            sk = SigningKey(f.read())
        vk = sk.verify_key

        # --- Allowlist (optional) ---
        ALLOWED = set()
        if os.path.exists(NODES_TXT):
            with open(NODES_TXT) as f:
                for line in f:
                    parts = line.strip().split()
                    if parts:
                        try:
                            ALLOWED.add(bytes.fromhex(parts[0][:64]))
                        except ValueError:
                            pass

        # --- Service Dispatch ---
        def proxy_forward(msg: bytes) -> bytes:
            if msg.startswith(
                    (b"cl", b"pr", b"re", b"si", 
                     b"ix", b"st", b"ct", b"gt", b"de", b"ve")):
                port = SIGNAL_PORT
            elif msg.startswith((b"id",b"of")):
                print("basenet")
                port = BASE_NET_PORT
            else:
                return b"!invalid"
            try:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.connect(("127.0.0.1", port))
                    s.sendall(msg)
                    out = b""
                    while True:
                        chunk = s.recv(4096)
                        if not chunk:
                            break
                        out += chunk
                    return out
            except Exception as e:
                return f"!error: {e}".encode()

        # --- Threaded Handler ---
        def proxy_handle_client(conn, addr):
            with conn:
                conn.settimeout(10)  # <-- set timeout to 10 seconds
                try:
                    # Client to Node.
                    # 1. [0][ID 32][CHALLENGE 64]
                    #
                    version = conn.recv(1)
                    if version != b'\x00':
                        return
                    client_id = conn.recv(32)
                    challenge1 = conn.recv(64)
                    if len(client_id) != 32 or len(challenge1) != 64:
                        return
                    if ALLOWED and client_id not in ALLOWED:
                        return
                    challenge2 = os.urandom(64)
                    sig1 = sk.sign(challenge1).signature
                    # 2. Node to Client.
                    # [ID 32][SIG 64(CHALLENGE)][CHALLENGE 64]
                    #
                    conn.sendall(vk.encode() + sig1 + challenge2)
                    # 3. # Client to Node.
                    # [SIG 64(CHALLENGE+MESSAGE)][length 3 byte le][MSG]
                    #
                    sig2 = conn.recv(64)
                    length_bytes = conn.recv(3)
                    length = int.from_bytes(length_bytes, "little")
                    msg = b""
                    while len(msg) < length:
                        chunk = conn.recv(length - len(msg))
                        if not chunk:
                            return
                        msg += chunk

                    # Verify
                    try:
                        VerifyKey(client_id).verify(challenge2 + msg, sig2)
                    except BadSignatureError:
                        return

                    # Forward
                    #print("msg",msg)
                    # Throttle if applicable
                    if msg[:2] in [b"cl", b"pr", b"re", b"de"] and len(msg) >= 70:
                        ip_str = addr[0]
                        try:
                            ip_bytes = socket.inet_aton(ip_str)
                            iden = msg[2:34]
                            throttle_msg = b"??" + ip_bytes + iden
                            with socket.socket(
                                    socket.AF_UNIX, socket.SOCK_STREAM) as s:
                                s.connect(os.path.expanduser(
                                    "~/.iden/throttle"))
                                s.sendall(throttle_msg)
                                delay = s.recv(8)
                                delay_secs = struct.unpack("<d", delay)[0]
                                if delay_secs > 0:
                                    print(f"SigProx Throttling {ip_str} {delay_secs:.3f} sec")
                                    time.sleep(delay_secs)
                        except Exception as e:
                            print(f"[SigProx] Throttle error for {ip_str}: {e}")

                    payload = proxy_forward(msg)
                    now = struct.pack("<d", time.time())
                    h = sha256(msg).digest()
                    blob = now + h + payload
                    sig = sk.sign(blob).signature
                    # 4. Node to Client
                    # [SIG 64(T+MSG_HASH+RESPONSE)][T][MSG_HASH][RESPONSE]
                    #
                    conn.sendall(sig + blob)
                except Exception as e:
                    print("Error:", e)

        # --- Server Loop ---
        def proxy_serve():
            HOST = "0.0.0.0"
            PORT = 8044
            MAX_WORKERS = MAX_SIGPROX_THREADS
            with ThreadPoolExecutor(max_workers=MAX_WORKERS) as pool:
                with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                    s.setsockopt(socket.SOL_SOCKET, socket.SO_REUSEADDR, 1)
                    s.bind((HOST, PORT))
                    s.listen()
                    print(f"[sigprox] Listening on {HOST}:{PORT}")
                    while True:
                        conn, addr = s.accept()
                        pool.submit(proxy_handle_client, conn, addr)
        print("Signing Proxy Started")
        proxy_serve()

    else:
        print(f"Starting basenet web service on http://{HTTP_HOST}:{HTTP_PORT}")
        uvicorn.run(app, host=HTTP_HOST, port=HTTP_PORT)

