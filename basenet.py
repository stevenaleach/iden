#!/usr/bin/python3
#
#    IDEN 0.1.0,
#    basenet.py
#
#    Copyright (C) 2025 Steven A. Leach
#
#    This program is free software: you can redistribute it and/or modify
#    it under the terms of the GNU General Public License as published by
#    the Free Software Foundation, either version 3 of the License, or
#    (at your option) any later version.
#
#    See <https://www.gnu.org/licenses/> for details.

from fastapi import FastAPI, Request
from fastapi.responses import PlainTextResponse, HTMLResponse
import uvicorn, sys, socket, yaml, markdown, re
import time
import os
from hashlib import sha256

basenet_ip = "127.0.0.1"
basenet_port = 4040
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


class Frame:
    def __init__(self, content: dict = None):
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
        return yaml.dump(self.body).encode()


def Publish(body,
            page: int = 1,
            r: bytes = bytes([0] * 32),
            host: str = "127.0.0.1",
            signal_port: int = 4004,
            basenet_port: int = 4040):

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
            print(f"Error communicating with unix socket at {socket_path}: {e}")
            return b''

    def tcp_deliver(offer, data):
        try:
            with socket.socket(socket.AF_INET, socket.SOCK_STREAM) as s:
                s.connect((host, basenet_port))
                s.sendall(offer)
                resp = s.recv(2)
                print("Response from basenet:", resp)
                if resp == b"ok":
                    length = len(data).to_bytes(2, 'little')
                    s.sendall(length + data)
                    print("Payload sent.")
                else:
                    print("Did not receive OK. Aborting.")
        except Exception as e:
            print("Delivery error:", e)

    padman = os.path.expanduser('~/.iden/padman')
    iden = unpack_state(unix_send(padman, b'id').decode())
    state = unix_send(padman, b'st')
    idx = state_idx(state)

    if hasattr(body, 'to_bytes'):
        body = body.to_bytes()

    header = yaml.dump({'_': page}).encode()
    full_payload = header + b"---\n" + body

    datahash = Hash(full_payload)
    signal = datahash + r
    mix = Mix(state, signal)

    cl = b'cl' + iden + mix + idx.to_bytes(4, 'little')
    pr = b'pr' + iden + state + signal

    print("Sending claim...")
    print(tcp_send(cl, signal_port))
    time.sleep(0.01)

    print("Sending proof...")
    print(tcp_send(pr, signal_port))

    offer = offer_msg(iden, idx, datahash)
    tcp_deliver(offer, full_payload)

    return offer, full_payload


def tcp_send(data, host=basenet_ip, port=basenet_port):
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

app = FastAPI()

def rewrite_iden_links(md_text: str, prefix: str = "127.0.0.1:4040/") -> str:
    def replacer(match):
        full = match.group(0)
        if full.startswith("\\iden://"):
            return "iden://" + full[7:]  # remove escape
        return prefix + full
    pattern = re.compile(r'(\\)?iden://[^\s)>\]"\']+')
    return pattern.sub(replacer, md_text)


@app.get("/{path:path}")
async def handle_request(path: str, request: Request):
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
            next(yml)  # skip header
            yml = next(yml)

            if subkeys[0] == 'pub' and 'pub' not in yml:
                if 'text.md' in yml:
                    return render_markdown_as_html(yml['text.md'], title="PeerPub Document")

            for key in subkeys:
                if isinstance(yml, dict) and key in yml:
                    yml = yml[key]
                    if not isinstance(yml, dict):
                        return PlainTextResponse(yaml.dump(yml))

            return PlainTextResponse(yaml.dump(yml))
        except Exception as e:
            return PlainTextResponse(f"[Error parsing content: {e}]")

    return PlainTextResponse(response)

def expand_inline_iden_blocks(md_text: str) -> str:
    pattern = re.compile(r"(?<!\\):::\s*(iden://[^\s:]+(?:\.[0-9]+)?(?:/[^\s:]+)*)\s*:::", re.IGNORECASE)

    def expand(match):
        full_uri = match.group(1).strip()
        print("Expanding inline block:", full_uri)

        # Split base URI and subpath
        trimmed = full_uri[len("iden://"):]
        parts = trimmed.split("/")
        base_uri = "iden://" + parts[0]
        subkeys = [p.strip() for p in parts[1:] if p.strip()]

        try:
            response = tcp_send(base_uri.encode())

            try:
                text = response.decode("utf-8")
            except:
                return "[[binary content]]"

            try:
                yml = yaml.safe_load_all(text)
                next(yml)  # Skip header
                content = next(yml)

                for key in subkeys:
                    if isinstance(content, dict) and key in content:
                        content = content[key]
                    else:
                        break

                return content if isinstance(content, str) else repr(content)

            except:
                return text  # Couldn't parse as YAML — return as-is

        except:
            return ""  # No errors returned, just nothing

    return pattern.sub(expand, md_text)

def render_markdown_as_html(md_text: str, title: str = "PeerPub Document") -> HTMLResponse:
    expanded_md = expand_inline_iden_blocks(md_text)
    rewritten_md = rewrite_iden_links(expanded_md)
    #html_body = markdown.markdown(rewritten_md)
    html_body = markdown.markdown(rewritten_md, extensions=['fenced_code', 'codehilite'])

    full_html = f"""
    <!DOCTYPE html>
    <html>
    <head>
        <title>{title}</title>
        <style>
            body {{
                font-family: sans-serif;
                max-width: 800px;
                margin: 2em auto;
                padding: 1em;
                background-color: #f9f9f9;
                color: #333;
            }}
            h1, h2, h3 {{
                color: #444;
                border-bottom: 1px solid #ccc;
                padding-bottom: 0.3em;
            }}
            a {{
                color: #007acc;
                text-decoration: none;
            }}
            a:hover {{
                text-decoration: underline;
            }}
            code {{
                background-color: #eee;
                padding: 2px 4px;
                border-radius: 3px;
                font-family: monospace;
            }}
            pre {{
                background-color: #eee;
                padding: 1em;
                overflow-x: auto;
            }}
        </style>
    </head>
    <body>
        {html_body}
    </body>
    </html>
    """
    return HTMLResponse(full_html)

if __name__ == "__main__":
    if len(sys.argv) > 1 and sys.argv[1].lower() == "publish":
        print("Publishing:", sys.argv[2:])
    else:
        print("Starting basenet web service on http://0.0.0.0:8008")
        uvicorn.run(app, host="0.0.0.0", port=8008)
