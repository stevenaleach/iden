**Note For GitHub**: *The "\\"'s escaping any "iden://" in this text are there for peerpub rendering and should be ignored when reading on GitHub.*  This paper is formated for "peerpub" rendering and lives live on the test node [here:](https://idens.net/iden://z1HRUsTNcYMkN5WPm9s1YjGaLUVs58RVRHPjBrV1kYwdAJ.642/pub) <--- [that's](https://idens.net) an open node, there to be tested and poked at and played with, published to and read from.
# <center>IDEN</center>
*Steven A. Leach*   

```
@z1HRUsTNcYMkN5WPm9s1YjGaLUVs58RVRHPjBrV1kYwdAJ
```

[TOC] 

### 1. Introduction

IDEN is a lightweight decentralized identity and publishing platform.

It provides a small, efficient foundation for building distributed, coordinated systems around self-generated identities. An `iden` serves as a portable, public address—readable by anyone, writable only by its owner.

At its core is an indexed feed of `signals` tied to a sequence of `states`, each with a unique `idx`. A state is a self-authenticating token that anchors a message or action to a specific point in an identity’s timeline, forming a verifiable, ordered history of intent. Signals may represent actions or content, enabling flexible coordination and authenticated publication across domains.

**Principle of Operation:**

At the lowest level is a signaling protocol based on three types of messages:

**Reports** announce a new state for an iden. These messages are self-authenticating: a state is only accepted if it steps correctly to the known prior high state (or, if unknown, to the iden itself).

**Claims** promise a future state. They include a target idx, and a 32-byte hash of the to-be-revealed state plus a 64-byte arbitrary signal payload.

**Proofs** complete the claim. A proof reveals the promised state and signal, and the signal is only accepted if:

* The state is valid (i.e., steps to the previous state),

* The idx is higher than any state seen so far, and

* A matching claim was seen before any report or proof for that state.

This provides a robust mechanism for ownership verification and coordination, without needing a trusted third party or real-time consensus.

**Network Propagation:**  
  
No separation of claims and proofs is necessary to register signals to a single node. In an extended network, the publishing node can add a pause between claims and proofs to allow the claim to propagate across the network first. If the sender service is run, a node will send any new valid proofs or reports it receives to all connected peers and will send the most recent known correct report or proof on receiving an invalid or out-of-date report. The same is true for any new claim, and each new claim triggers the inclusion of the iden in reports and claims. Nodes, regardless of whether they run the sender service, can be polled periodically by peers for recent messages.  
  
Nodes are identified by 32 byte fields which, in this implementation, are Ed25519 public keys used for handshaking and for the secure signed proxy interface. Connecting nodes provide "advertisement strings" specifying services and the ports on which they operate. Peers may be queried with the maximum record count specified for most recently connected peers enabling peer discovery.

  
**Trust, Replay, and the Absence of Global Consensus:**

IDEN does not implement a global consensus protocol. Nodes do not participate in real-time agreement or state synchronization beyond what they individually observe and choose to trust. The system instead relies on *local confidence*: each node records and accepts claims, proofs, and payloads based on what it has seen, in order, according to a verifiable chain of identity-state continuity.

This offers strong integrity guarantees at the point of observation, but it does not prevent replay or substitution attacks outside that context. If an attacker can interpose themselves between a client and a node (e.g., via DNS spoofing, routing hijack, or physical MITM), they may be able to delay or forge messages and insert alternate content before the legitimate signal arrives. The system accepts whichever valid message arrives first as genuine.

**Secure Proxy:**

To mitigate this, a signing proxy service `sigprox` is provided that can wrap both signaling and basenet traffic. The proxy verifies inbound messages against their Ed25519 signatures, discards any unsigned or invalid data, and signs its responses so clients can confirm they came from a trusted source. Optionally, a nodes.txt file can be used to restrict access through the proxy to a list of approved node public keys. In such a configuration, the underlying TCP services should be bound to localhost only, with the proxy as the sole public-facing interface.

As long as both sender and receiver interact with the same node (or a trusted, well-connected set of nodes), communication should be safe. IDEN’s model is best understood as authenticated rendezvous, with configurable levels of openness and trust. This model prioritizes transparency & inspectability, for distributed publishing, messaging, or coordination across loosely connected nodes.


**Nodes, Services, & Implementation:**

IDEN, at core consists of the signal store & message processor.  This is a small background service the purpose of which is to enable fast authentication (of messages, commands, requests, etc.) received by other services.  
  
A single basic service is implemented, documented, and included here, `basenet`, which is a general-purpose open-ended structurable data-store and feed with indexed URI retrieval.  
  
A single basenet application, `peerpub` is also implemented, documented, and included here and is the native environment for this document (though it will also live on GitHub as README.md).
  
**Implementation Structure:**
  
The base system is a single multi-functional 'iden' binary written in Rust which provides a few command-line tools as well as all of the sub-services which comprise the system:  
 
 
| Subservice         | Role                         | Description                                                              |
|--------------------|------------------------------|-----------------------------
| `mproc`            | Message Processor            | Manages signalstore, handles claim, report, proof, and queries    |  
| `tcp_in`           | Public TCP service         | Accepts open TCP connections, handles peer handshaking.          |  
| `throttle`         | IP Throttling Service      | Provides IP based throttling to tcp_in, along with throttle bypass by single iden link dedication in coordination with tcp_in. |  
| `sender`           | Message Relaying             | Queues and relays outbound messages to connected peers                   |  
| `peerstat`         | Peer Cache                   | Tracks latest connected peers, supports peer discovery (advertisement string) information.                   |  
| `basenet`          | Storage Layer                | Indexed URI addressable data-store  |  
| `padman`           | Iden Pad Manager             | Tracks state idx, holds the decrypted pad in memory and provides states to user programs through the "~/.iden/padman" socket. |  


Additionally, `basenet.py` provides the user-facing Python library and tools — including the HTTP server, Markdown renderer, publishing helpers, and CLI entrypoints.

**Modularity:**

The entire system except for the higher-level Python library and tools, is implemented in the form of service roles that the iden binary will step into based on the first argument on the command-line. This includes the role 'run' (run REPL commands from a file) with which it can launch and shut down a collection of copies of itself all taking their parts and communicating through a well defined API.  
  
This is so that this code can stand as a *reference implementation* - it is simple and straight-forward, but any one of these components can be optimized and improved on and any improved versions can be implemented stand-alone and then simply substituted for the iden binary for the service in question. 

Further, the system should be considered connection agnostic — the tcp_in service is intentionally minimal, performing only the essential tasks: routing messages between the outside world and the mproc service, handling peer handshakes and advertisements, and exposing connected peer information. It can be easily replaced or extended by other connection services (e.g., hardened, IPv6-capable, or domain-specific) that provide equivalent functionality. Node IDs — whether Ed25519 public keys, hashes of pubkeys, or any other format — must be 32 bytes in length (for compatibility with the peerstat record format). The routing of peerstat and signaling messages currently handled by tcp_in simply needs to be made available.


### 2. Basenet

The `basenet` service is an example of how other services can build on the signaling layer. It stores content associated with a state (iden and idx) by embedding the iden, idx, and payload hash in a message header, then verifying the presence of the matching signal with a single query to the signaling service before accepting the payload. This mechanism can be used by any service wishing to coordinate actions or data with the identity-state layer, not just basenet.

Basenet is a simple service for storage and retrieval of UTF-8 encoded data frames, up to 64KB in size.  By default, these frames are assumed to contain YAML data, though this is not a requirement. When structured as YAML, they can be sub-addressed using internal dictionary paths.   
  
  `Peerpub` is a basenet application which can render and serve markdown source text with hyperlinking, with both silent and block-quoted non-recursive in-place expansion for document composition as well as data embedding.

**Data Frames:**

Basenet data-frames are limited to no more than sixty-four kilobytes in size and must be valid UTF-8 encoded data. They are required to begin with a dictionary which must contain at least the key '_' (a single underscore) with possible values '0' or '1', designating the frame type:

* `Type 0` frames replace previous type 0 records.
	
* `Type 1` frames append to the top of a feed of frames with at least 128 kb of history storage. Node administrators may allow a higher quota for an iden by writing a size in bytes to a file "pin.txt" in the iden's storage directory.
	
This header must end with a document divider '---', and may be followed by any valid UTF-8 encoded data.

'_' is the only required field. Any additional fields added to the header will not be available as paths for retrieval (see below) and will be ignored. This is where a cryptographic signature of the frame body might be placed or any other metadata that it is desirable to separate from the body.

**URI Retrieval:**

Content is referenced using the '\iden://' protocol specifier:

**The most recently added type 1 (feed) frame:**

	\iden://z1HRUsTNcYMkN5WPm9s1YjGaLUVs58RVRHPjBrV1kYwdAJ
	
**The current type 0 (pinned) frame:**

	\iden://z1HRUsTNcYMkN5WPm9s1YjGaLUVs58RVRHPjBrV1kYwdAJ.0
	
**The type 1 frame at idx = 1,000,000:**

	\iden://z1HRUsTNcYMkN5WPm9s1YjGaLUVs58RVRHPjBrV1kYwdAJ.1000000
	

**If Payload Is YAML:**  
*Sub-addressing of a dictionary:*

	\iden://z1HRUsTNcYMkN5WPm9s1YjGaLUVs58RVRHPjBrV1kYwdAJ.42/files/src/README.txt
	
*This should always fail gracefully, returning the structure as far down the parse path as it is able to reach.*

*Note:* Though not demonstrated by the library, it is possible to publish both a type 0 and type 1 frame simultaneously using a single state by placing both hashes in the signal field and delivering the type 0 frame before the type 1 (otherwise the second offer will be rejected by idx as a duplicate).  
  
Also, as mentioned though YAML is expected to be the primary means of encoding data in frame bodies, this isn't required. A body may be simply a plain-text document - or any UTF-8 data-blob that it might be useful to construct for any purpose.

**Default Disk Quota & Garbage Collection:**

The oldest frames in an iden's .N feed history will be dropped as necessary to keep the feed at or below the default 128KB storage quota. A higher (but no lower) limit can be granted to an iden with a value specifying a maximum file size in bytes written to `pin.txt` in that iden's storage directory.

### 3. Peerpub

Peerpub is a built-in application of basenet, providing tools for structured document composition and publication. It acts as both a renderer and a publishing tool, allowing users to create interlinked documents that can link to and be packaged with data.

It renders Markdown from text.md elements in basenet YAML frames into hyperlinked HTML pages with non-recursive in-line expansion of named URI text:

**Silent inline expansions:** `::: \iden://... :::`

*Content from other documents or fields is inserted into the output transparently.*

**Block-quoted inline expansions:** `||| \iden://... |||`

*The same, but rendered as Markdown blockquotes, useful for quoting or referencing other material.*

**Note:** Silent expansions are performed prior to a second pass for block-quoted expansions which means that text included in the first pass can include block-quotes which will expand in the second pass.

**Expansion Limits:** A configuration value `MAX_EXPANSIONS_PER_PASS` (default 16) in `basenet.py` limits expansions to prevent an excessive number of expansions of large frames. On a private node this could be set arbitrarily high with no worry.

If specified material is in the iden's "pinned"/"reference" frame (.0) then static documents can live-update on refresh as the renderer sources the latest updates to this frame. 

The same, in fact, is true for the top of feed, (no dot): If a document imports and expands named data from that URI, then it will auto-expand any named fields when they are populated in the currently retrievable top-of-feed frame by the iden (and the markdown expansion tag will be printed in the text when it does not resolve to data).

This allows for both fixed publication (permanently linkable .N posts) and mutable references (via named data in .0 or top-of-feed frames), and allows immutable .N documents to be re-rendered importing updated information at any time.

Both basenet YAML sub-resolution and basenet markdown rendering are currently provided by the Python script - though in the future both of these tasks are intended to be moved into the (next) Rust basenet sub-service. Rendering is currently through the Python Markdown library with "fenced_code", "tables", "toc", "footnotes", & "def_list" extensions enabled.  
  
**Document Rendering:**

The basenet web service renders peerpub markdown from text.md when requested via a /pub URI path if and only if no pub element exists in the YAML root. The presence of a pub element disables automatic rendering and instead causes its value to be returned directly. This allows a creator to override default behavior if desired.

If `text.md` exists and `pub` does not, then:

*	`\iden://<idenstring>/pub`   
	will render the peerpub document at the feed top.

*	`\iden://<idenstring>.N/pub`   
	will render a specific feed document.

*	`\iden://<idenstring>.0/pub`   
	renders the current .0 frame.

*Markdown: [^4.1] Python Markdown Library [^4.2]*

**Previewing Local Documents**

To support drafting workflows, the peerpub renderer provides previewing of local markdown files.  If a file exists in the configured preview directory (e.g., ~/drafts/), it can be viewed directly with:

```
http://127.0.0.1:8008/preview/<filename>
```
This loads the specified file as a "text.md", applying all standard rendering and URI expansion logic. All \iden://... references are resolved against the node’s basenet service.

**Note:** preview rendering only permits access to files in the configured preview directory. Subdirectories are not permitted.  
  
**Node Pages:** To support public-facing deployments, a node can specify a default homepage. If enabled via the config variable at the top of the script (e.g., HOMEPAGE_FILE = "about_this_node.md"), any request to the root URI (e.g., https://nodename.net/) will redirect to:

```
/preview/about_this_node.md
```

**Open Graph Data**

If a YAML title is present, it will override the first Markdown heading for Open Graph metadata and HTML rendering.

### 4. Installation & Setup

**Requirements**

This project is being developed and tested on **Debian 12**. You will need:


- A working installation of **Rust** (for building the core binary)
- A **Python 3** virtual environment with **pip**
- **Git** for cloning the repository
- **Zenity** For the pad manager (GUI used for password prompt on startup),  
  bypass with `--no-gui`.

**Zenity**  
    
```bash    
sudo apt install zenity  
```

**Python Dependencies**

```bash  
pip install fastapi uvicorn pynacl pyyaml markdown  
```

**Clone the repository and run the installation script:**

```bash  
git clone https://github.com/stevenaleach/iden
cd iden
./install.sh  
```

This will:

- Build a release version of the `iden` Rust binary,

- Copy `iden`, `basenet`, and `basenet.py` to `~/bin`, creating `~/bin` if necessary.

- Add `~/bin` to your shell path (`~/.bashrc`) if needed

**Initialize:**

```bash  
cd; iden init
```

**Generate a new iden:**

```bash  
iden generate <output_file>
```

This will generate an unencrypted text file with intermittent state checkpoints beginning at the generation seed and ending with the iden on the final line.  

**Store an encrypted checkpoint:**

```bash
iden store <input-pad> .iden/<name>.pad <idx>
```
The file must have the extension ".pad" and must be placed in the user's ~/.iden directory or in a directory .iden in the path where the pad manager will be launched. You will be prompted for a password and a file with an encrypted checkpoint pair (idx=n, n-1) will be created. Note that the pad manager is intentionally very simple and does not cache checkpoints in memory - so the higher the idx you chose to store the slower retrieval will be each time. A value between perhaps 10,000 and 1,000,000 might be a good choice.

**Launch the pad manager:**

```bash
iden padman <name> &

or:

iden padman <name> --no-gui
```

The pad manager tracks the current public state idx and provides new states to any client (user programs). You will be prompted for the encryption password on launch and the program will fail and exit unless the correct password is provided. Once the password is provided, the pad manager will listen to the local socket .iden/padman and will provide the iden, current idx, and states on demand to any user programs that needs them.

### 5. CLI Tools

##### 5.1 iden

The iden binary offers several commands, including some basic tools and service modes:

**Commands:**

*   `iden connect <host> [port]`  
	*	Connect to a remote peer at `<host>` on optional [port] (default 4004).

*   `iden generate <file>`        
	*	Generate a new IDEN pad, saving to `<file>`.

*	`iden init`                   
	*	Initialize the IDEN storage directory and configuration files.

*   `iden mproc <name>`           
	*	Run an mproc message processor on `.iden/<name>`.
	
*  	`iden basenet <name>`         
	*	Run a basenet message processor on `.iden/bn<name>`.

*	`iden basenet_in`            
    * 	Start the basenet TCP listener service.

*   `iden peerstat`               
	*	Start the peer statistics tracking service.

*	`iden run <startup_file>`     
	*	Execute commands from a file before entering the REPL.

*	`iden sender`                 
	*	Start the sender service.

*	`iden shard <N>`              
	*	Generate a new shard map with N shards.

*	`iden tcp_in`                 
	*	Start the TCP listener service.

*	`iden store <pad> <name> <idx>` 
	*	Store an encrypted checkpoint for padman    

*	`iden throttle`               
	*	Start the throttling service.

*	`iden version` | `ve`           
	*	Display the current version number.

*	`iden help | -h | --help`     
	*	Display this help message.


##### 5.2 basenet

The `basenet` script which will by default be installed in the user's `~/bin` directory can be used to launch basenet.py.  
  
If no command-line arguments are passed, this will launch the HTTP service.  

```
basenet
```

The sigprox service can be launched via:  

  
```
 basenet sigprox
```

---

### 6. Python Library


**Idens, States, Step(), & Mix() Detailed:**

Each state is a 36-byte value composed of a 32-byte hash and a 4-byte little-endian idx. An iden is a 32 byte value that is the hash of the state at idx=1, or the state at idx=0 with the idx bytes discarded.    
  
Both idens and states are encoded as base58 strings with a version prefix byte (0) and multibase code 'z' (base58btc) for display and interchange using the following functions:

**Python:**

```

import base58

def pack_state(state):
    ''' Return string representation for a state. '''
    return((b'z'+base58.b58encode(bytes([0])+state))).decode())

def unpack_state(s):
    ''' Return a binary state given a string representation. '''
    s = s[1:]; s = base58.b58decode(s)
    assert s[0] == 0
    return(s[1:])

```

*Example:*   

```
"z1HRUsTNcYMkN5WPm9s1YjGaLUVs58RVRHPjBrV1kYwdAJ"
```
The step function is the hash of the prior state with the decremented idx appended:

```   

from hashlib import sha256

def step(state, start=False):
    ''' Advance a state one generation step.'''
    a = sha256(state).digest() 
    b = int.from_bytes(state[-4:],'little')
    return(a+(b-1).to_bytes(4,'little',signed=False))

```


The Mix() function is used to construct the 32-byte value placed into a claim message. It combines the current state and a 64-byte signal.

```

def mix(state, signal):
    assert isinstance(signal, bytes) and len(signal) == 64
    return Hash(state + signal)
    
```

*multibase [^6.0]*

---

#### 6.1 Utility Functions

pack_state(state) → str
:    Returns a string-encoded state (or iden) from bin.  


unpack_state(s) → bytes
:    Returns a binary state (or iden) from a string representation.  


step(state) → bytes
:    Advances a state one step, from idx=N to idx=N-1.  


state_idx(state) → int
:    Returns the index value (idx) from a state passed in binary or string form.  


crypt_state(state, password) → bytes
:    XORs the first 32 bytes of a state with the SHA256 hash of a password to encrypt/decrypt.  


print_state(state) → None
:    Displays the binary state as a printable grid suitable for hand copying to paper.  

---

#### 6.2  PadMan

`PadMan` is a collection of static methods for interaction with the running padman service via its Unix socket. It provides iden and idx information and acquires states for publishing workflows.


PadMan.idx() → int
:    Returns the current (last provided, current public) idx or -1 if the top of the pad has been reached.


PadMan.iden_bin() → bytes
:    Returns the current iden in binary form.


PadMan.iden_str() → str
:    Returns the string form of the current iden managed by the running padman.


PadMan.state_bin() → bytes
:    Request the next state in binary form.


PadMan.state_str() → str
:    Request the next state in string form.


PadMan.shutdown() → None
:    Sends a shutdown signal to the padman service, terminating the listener.

---

#### 6.3 IdenSignal

`IdenSignal` provides TCP access to the signaling layer, allowing interaction with a running signalstore node for sending reports, retrieving message stats, or querying known state/index values.


IdenSignal.report(host="127.0.0.1", port=4004) → bytes
: 	Sends a 're' (report) message using the current iden and next state from PadMan. Announces the new state to the node.


IdenSignal.dedicate(host="127.0.0.1", port=4004) 
: 	Sends a 'de' (dedicate) message using iden and state from PadMan. Used to associate a public IP with this iden for bypassing rate limits.


IdenSignal.msg_count_t(t: float,host="127.0.0.1", port=4004) → int
: 	Sends a 'ct' (count) query for how many messages were received in the last t seconds. Returns an integer count.


IdenSignal.get_messages(t: float,host="127.0.0.1", port=4004) → tuple[int, bytes]
: 	Sends a 'gt' (get) query to retrieve all messages seen in the last t seconds. Returns a count and raw concatenated message payload.


IdenSignal.idx(iden: bytes,host="127.0.0.1", port=4004) → int | None
: 	Queries the latest known idx for a given iden. Returns an integer index or None if unknown.


IdenSignal.state(iden: bytes,host="127.0.0.1", port=4004) → bytes | None
: 	Retrieves the current highest known state for an iden. Returns raw 36-byte state or None.


IdenSignal.signal(iden: bytes, idx:int, host="127.0.0.1", port=4004) -> bytes | None
:	Retrieves signal N for idx if available.


IdenSignal.version(host="127.0.0.1",port=4004) → str
: Queries the node's version using the 've' opcode. Returns a UTF-8 string like "0.1.0".

---

#### 6.4 BaseNet  
`BaseNet` provides static helpers for interacting with a basenet TCP node using the public service port.


BaseNet.deliver(blob: bytes, host=None, port=None) → bytes
:	Sends a preassembled offer message (b"of" + iden + idx + hash + length + payload) to the basenet TCP service. Returns the raw response or b"" on error.


BaseNet.get(uri: str, host=None, port=None) → bytes
:	Sends an id (resolve) request for the given URI (must begin with \iden://). Returns raw UTF-8 bytes or an error response starting with b"!".


BaseNet.get_from(iden_str: str, idx: int, host=None, port=None) → tuple[int, bytes] | None
:	Attempts to retrieve the frame at the given iden and idx. If not found, walks backward toward index 0. Returns a tuple (found_idx, payload) or None if no frame is found.

---

#### 6.5 Frame Class

`Frame` is a class for constructing basenet YAML document body frames. It provides recommended methods for filling in metadata including peerpub documents and banners (header, footer) attachment.


Frame(content=None, BASENET_PORT=4040, SIGNAL_PORT=4004, HOST="127.0.0.1")
:	Create a new frame from an optional dictionary. Ports and host can be set for use for backlink search.


**Frame Methods:**

Frame.add_file(path, data)  
:	Attach a file or nested dictionary to the frame at the given path (e.g., "files/readme.txt" or "files/docs/intro.md").


Frame.link_file(path, uri, hash=None)  
:	Insert a file link instead of a literal, using {'link': uri}. Optional hash passed as an argument.


Frame.author(name)  
:	Set the author field. Arbitrary string.


Frame.geoloc(lat, lon)  
:	Set a geoloc field with latitude and longitude.


Frame.lang(code)  
:	Set a language string, e.g., "eng".


Frame.title(title)  
:	Set a document title.


Frame.time(timestamp=None)  
:	Set the time field to the current UNIX epoch time (or to a given float timestamp).


Frame.app(name)  
:	Add an app tag (e.g., "peerpub"). Tags are accumulated as a comma separated string.


Frame.pub(text,appkey="peerpub")  
:	Marks the frame with a post type (default "peerpub") in the app field and adds passed text as text.md.


Frame.backlink(host="127.0.0.1", port=4040)  
:	Look up the previous frame (using PadMan.iden_str() and PadMan.idx()) and store its idx and hash in prev_frame. Provides a walkable verifiable back-path for basenet frames.


Frame.backpub(appkey="peerpub", host="127.0.0.1", port=4040)  
:	Search backward from the current idx until a frame with the specified appkey (default 'peerpub') in its app field is found. If found, add a text.md file linking to that frame and record its idx in 'lastpub'.


Frame.to_bytes() → bytes  
:	Convert the frame to YAML and encode as UTF-8. Used before hashing or transmitting the frame.

---

#### 6.6 Publish Function

`Publish()` is the default publication pipeline (at least from within a Jupyter notebook) for submitting basenet frames. It handles building a full basenet frame with header, creates and sends a claim and proof and then payload to a single designated node, returns claim, proof, and payload for delivery to other nodes.


Publish(body,  
page=1,  
r=bytes([0] * 32),  
host="127.0.0.1",  
signal_port=4004,  
basenet_port=4040,
send = True,
sleep = 0.0)  
:	Publish a frame to basenet.    
  

**Arguments**:

* `body`: YAML string or Frame object. If a Frame is provided, it will be serialized with .to_bytes().

* `page`: Frame type (0 = reference, 1 = feed). Defaults to 1.

* `r`: A 32-byte random signal payload. Defaults to all zero bytes.

* `host`: Target host for both padman and TCP services. Defaults to "127.0.0.1".

* `signal_port`: Port for TCP signaling (claim/proof). Defaults to 4004.

* `basenet_port`: Port for basenet TCP submission. Defaults to 4040.

* `send`: If set to False, Publish() will build and return claim, proof, and payload messages but not dispatch them.

* `sleep`: An optional delay to allow a claim time to propagate before sending the proof.

**Behavior**:

* Retrieves iden and next available state from the running padman.

* Serializes the frame with a YAML type header (_ = 0|1) and divider.

* Computes a 32-byte hash of the payload.

* Assembles a 64-byte signal: SHA256(payload) + r.

* Constructs and sends:

  * `cl`: A claim (includes hash of state + signal and target index)

  * `pr`: A proof (reveals the state and signal)

  * `payload`: An offer header+payload blob to store the payload in basenet

* Returns a dictionary with raw messages: 'CLAIM', 'PROOF', 'PAYLOAD' for manual dispatch.
**Example:**

```python

f = Frame()
f.title("My Post")
f.backlink()
f.backpub()
f.pub("# Hello, world!")
Publish(f)

```
  
---

#### 6.7 sigprox_send()

sigprox_send(msg: bytes, node=False, host='127.0.0.1', port=8044) -> bytes  
:    Sends a signed message to a node's signing proxy, verifies signed response and returns a dictionary which includes the verified server response, time value t, the server’s signature over the t+msg_hash+response, and the SHA256 hash of the original message (keys: `response`, `node_id`, `t`, `sig`, `msg_hash`).  If an optional 32 byte node ID is passed and it does not match that of the handshaking node then the send will be aborted.

---

### 7. Usage Examples

As a starting example, below is some code that might be run from a Jupyter Notebook cell which would publish a new ".0" peerpub homepage:

**Example One:**

```  

import os,sys
bin_path = os.path.expanduser("~/bin")
if bin_path not in sys.path:
    sys.path.insert(0, bin_path)
import basenet as bn  

IdenSignal.dedicate()  # Optional: bypass throttling

frame = bn.Frame()

frame.backlink()
frame.time()
frame.backpub()
frame.pub(open("/home/user/drafts/README.md").read())

frame.header("Header Title Goes Here")
frame.footer("Some Footer Text.")

D = bn.Publish(frame, page=0, send=True, sleep=0.25)

claim = D["CLAIM"]
proof = D["PROOF"]
payload = D["PAYLOAD"]

```

**Walk-Through:**

1. **IdenSignal.dedicate():** Running this will bypass IP throttling for future messages from the client IP address for this iden's traffic.  More importantly, it is processed the same (outside of effecting throttling) as a report message. A node will not bother caching a claim for an iden if it doesn't have any signal-store record yet - so running this line will introduce the node to this iden and establish a record so that if we haven't published to it before the following will still work. Normally it won't be necessary, and if not used only the first signal (and associated content) will fail to register.

2. **Frame():** Creates a new basenet frame object. Internally, this sets up an empty dictionary to serve as the body root.

3. **backlink():** Finds the most recent retrievable basenet frame (of any kind) and stores its idx and SHA256 hash in the prev_frame field.  This builds a verifiable chain of frames, useful for reconstructing sequences across multiple nodes.

4. **time():** Inserts the current UNIX timestamp into the frame under the time field. This is optional but recommended.

5. **backpub():**  Searches backward from the current index for the latest frame with "peerpub" listed in its app field (the default key if none is specified). If found, a "lastpub" field with the linked frame’s index is added to the frame. This helps support thread-style document chains and browsing trails with headers and footers.

6. **pub(...):** Marks this frame as a peerpub document by adding "peerpub" to the app string. The body passed here is stored as text.md in the YAML frame.  

7. **header(text)** & **footer(text):**  Prepends and appends Markdown banners to text.md. These contain "home" (.0) links, "previous" links to the frame found by backpub(), and optional centered text strings.

8. **Publish():** Here, the frame is published to localhost as a ".0" frame (page=0), and we collect the claim, proof, and payload which could be delivered to another node. If a sender is running on localhost and we are connected to any peers, then the delay should provide time for the claim and proof to be sent requiring only the payload be delivered - or if it is not running then all three can be delivered "manually".

**Example Two, Publishing raw (non-YAML) payloads:**

The Publish() function accepts any UTF-8 bytes or .to_bytes()-capable object. While Frame() is a recommended interface for structured posts, you can also publish raw content directly — without YAML or metadata.
  

```

bn.Publish(b"test", host="idens.net")

```

This publishes a valid frame with no structured content — just a short blob. The resulting frame looks like:  
  
```

_: 1
---
test


```

This frame was published as a feed frame (.N) which is the default if not otherwise specified. When next `Frame.backpub()` is run, it will correctly issue complaints about malformed YAML in this record and pass over it. Otherwise this will function like any other frame.

**Example Three, Using Sigprox:**

```

# Step 1: Create a simple post
frame = bn.Frame()
frame.title("Secure Post")
frame.time()
frame.pub("# This post was published securely via sigprox.")

# Step 2: Prepare messages (but don't send them yet)
bundle = bn.Publish(frame, send=False)
claim = bundle["CLAIM"]
proof = bundle["PROOF"]
payload = bundle["PAYLOAD"]

# Step 3: Send each message via sigprox, verifying node identity
print("Sending CLAIM...")
resp1 = bn.sigprox_send(claim, host="idens.net", node=remote_id)
print("CLAIM response:", resp1['response'])

print("Sending PROOF...")
resp2 = bn.sigprox_send(proof, host="idens.net", node=remote_id)
print("PROOF response:", resp2['response'])

print("Sending PAYLOAD...")
resp3 = bn.sigprox_send(payload, host="idens.net", node=remote_id)
print("PAYLOAD response:", resp3['response'])

```

**Walk-Through:**

1. **Frame()** builds a simple basenet document, marked as a peerpub post.

2. **Publish(..., send=False)** constructs the messages we need but holds off on transmission.

3. **sigprox_send(...)** sends each message through the node’s signing proxy. The node= argument ensures we’re still talking to the same node we verified earlier — if the node were somehow replaced, the function would abort instead of sending to a stranger.


---

### 8. Node Configuration

#### 8.1 iden.cfg

Node configuration lives in .iden/iden.cfg and is parsed as simple key: value lines. There is no special comment character — anything following the value on the same line is ignored, so comments can be included freely. Order doesn't matter, and the file can include as few or as many settings as you like. Unknown keys are ignored.

**Example .iden/iden.cfg:**

```

basenet_port:         4040      
claim_cache_limit:    512       Per-iden limit for claim-cache size.  
claim_cache_time:     900       Claim retention time in seconds.  
claim_cache_total:    10000000  Per-shard limit for claim-cache size.  
message_cache_size:   60000     Per shard max message cache size.  
message_cache_time:   1800      Retention time for messages in seconds.  
mproc_step_limit:     50000  
peercache_size:       500  
pubnet_port:          8008  
sender_thread_limit:  128  
signal_cache_size:    4096  Filesize limit for ss.bin  
ss_split_chars:       2 /nnnn/... chars per division.  
ss_split_count:       1 /nnnn/nnnn/aaaaaaaaaaaaaaaaaaaa.../ N divisions.  
tcp_in_port:          4004  Primary signaling port  
thread_limit_in:      8  
throttle_delta:       2.0  <-- An overly safe extreme default.  
throttle_forget:      900  Time hosts/dedications will be remembered for.  
tcp_bind_addr:        127.0.0.1  

```

*None of the values above are tuned or optimized - they're just values that happened to have been used during development and haven't needed to be adjusted.*

The `ss_split_chars` and `ss_split_count` variables exist primarily for older file-systems & possible limits on the number of files per directory - for modern systems this can be left to personal preference and the default (2,1) is probably a good choice. Note that the longer the throttling delay (throttle_delta), the more concurrent TCP threads you’ll need (thread_limit_in) to avoid excessive queuing.

If `tcp_bind_addr` is not specified, signaling and basenet will bind to the public TCP address (0.0.0.0).

#### 8.2 Sharding

Even when only a single shard is used (the initial default configuration), a shard map (`0 0000 ffff`) is present. The .iden/shard.map file determines how messages are routed across sub-services by the first four hex digits of the iden address. 

**Example shard map, .iden/shard.map**

```

0 0000 3fff  
1 4000 7fff  
2 8000 bfff  
3 c000 ffff  

```

#### 8.3 Startup & Shutdown

The iden run command takes a file for input, passing '!' lines to the shell
and all others to the internal REPL:

**REPL Commands:**

* `basenet_in start <name>`:
    * Start the basenet service on the given socket name.

* `basenet_in stop <name>`:
    * Stop the basenet service on the given socket name.

* `connect <host> [port]`:
    * Establish a connection to a remote peer.

* `exit | quit | q`:
    * Exit the REPL.

* `listener start`:
    * Start the TCP listener service.

* `listener stop`:
    * Stop the TCP listener service.

* `mproc start <name>`:
    * Start an mproc instance listening on the specified socket.

* `mproc stop <name>`:
    * Shut down a running mproc instance.

* `peerstat start`:
    * Start the peerstat service.

* `peerstat stop`:
    * Stop the peerstat service.

* `sender start`:
    * Start the sender service.

* `sender stop`:
    * Stop the sender service.

* `shard <iden>`:
    * Determine which shard an iden belongs to.

* `start_mprocs`:
    * Start all mproc instances defined in .iden/shard.map.

* `stop_mprocs`:
    * Stop all mproc instances defined in .iden/shard.map.

* `throttle start`:
    * Start the throttling service.

* `throttle stop`:
    * Stop the throttling service.

* `padman stop`:
    * Shut down the padman service.

* `start_basenets`:
    * Start all basenet instances defined in .iden/shard.map.

* `stop_basenets`:
    * Stop all basenet instances defined in .iden/shard.map.

    

**Example start script**

```

!echo default startup script.  
throttle start  
start_mprocs  
start_basenets  
listener start  
peerstat start  
basenet_in start  
sender start  
#!iden padman foo &  
quit  

```

**Example stop script**

```

!echo default shutdown script.  
sender stop  
stop_mprocs  
stop_basenets  
listener stop  
peerstat stop  
basenet_in stop  
padman stop  
throttle stop  
quit  

```

---

### 9. Public (TCP) APIs

---

#### 9.1 Signaling Layer TCP

**Advertisement String:** `Ed25519_IPv4_TCP_0.1.0` 

**Default Port:** `4004`

**Shutdown Socket:** `.iden/tcp_in`  
*Listens for 'qu' shutdown command*

Handles peer handshaking, link dedication, routing messages to mproc shards.

---

**`pe` — Peers**

| Field          | Length     | Description |
|----------------|------------|-------------|
| `pe`           | 2 bytes    | Opcode      |
| `count`        | 2 bytes    | Desired record count (little-endian)  |

*Response:*

| Field                 | Description  |
|----------------------|---------------|
| `record_count`       | Number of records returned (u16_le)    |
| `records`            | `[32-byte ID] + [UTF-8 info string]`   |

---

**`hi` — Handshake**

| Field         | Length     | Description   |
|---------------|------------|-------------|
| `hi`          | 2 bytes    | Opcode     |
| `challenge`   | 64 bytes   | Random challenge  |

**Response:**

| Field         | Description   |
|---------------|----------------|
| `pubkey`      | 32-byte Ed25519 pubkey  |
| `signature`   | 64-byte Ed25519 signature   |
| `challenge`   | Response challenge (64 bytes)  |

**Peer follow-up:**

| Field                  | Description |
|------------------------|-----------|
| `pubkey`               | 32-byte Ed25519 pubkey |
| `signature`            | 64-byte signature of response challenge |
| `advertisement-string` | UTF-8 string (null-terminated) |

---

**`ct`** — Message Count in Last `t` Seconds

| Field    | Length     | Description |
|----------|------------|---------|
| `ct`     | 2 bytes    | Opcode  |
| `t`      | 8 bytes    | Seconds as float64 (little-endian) |

**Response:** `count` (4 bytes, u32_le)

---

**`gt`** — Get Messages in Last `t` Seconds

| Field    | Length     | Description |
|----------|------------|-----------|
| `gt`     | 2 bytes    | Opcode |
| `t`      | 8 bytes    | Seconds as float64 (little-endian) |

**Response:**

| Field            | Description  |
|------------------|--------------|
| `total_length`   | 4 bytes (u32_le) |
| `payload`        | Concatenated messages |

---

**`de`** — Dedicate Link

| Field       | Length     | Description |
|-------------|------------|------------|
| `de`        | 2 bytes    | Opcode   |
| `iden`      | 32 bytes   | Target identity |
| `state`     | 36 bytes   | State |

**Response:** *(none - should properly return the response code from 're')*

---

**`ix`** — Index Lookup

| Field    | Length     | Description  |
|----------|------------|------------|
| `ix`     | 2 bytes    | Opcode  |
| `iden`   | 32 bytes   | Iden   |

**Response:**  
`idx` (u32_le) if found, else single byte `0`

---

**`st`** — State Lookup

| Field    | Length     | Description   |
|----------|------------|-----------|
| `st`     | 2 bytes    | Opcode   |
| `iden`   | 32 bytes   | Identity  |


**Response:**  
36-byte state or single byte `0` if not found

---

**`si`** — Signal Lookup

| Field    | Length     | Description |
|----------|------------|---|
| `si`     | 2 bytes    | Opcode  |
| `iden`   | 32 bytes   | Identity  |
| `idx`    | 4 bytes    | Idx, Little Endian  |

**Response:**  
64-byte signal or single byte `0` if not found

---

**`re`** — Report State

| Field    | Length     | Description  |
|----------|------------|-----|
| `re`     | 2 bytes    | Opcode   |
| `iden`   | 32 bytes   | Identity    |
| `state`  | 36 bytes   | Reported new state  |

**Response:**  
Status byte:  
`0 = OK`, `1 = Bad size`, `2 = Too low`, `3 = Too far`, `4 = False`

---

**`cl`** — Claim

| Field    | Length     | Description  |
|----------|------------|----|
| `cl`     | 2 bytes    | Opcode |
| `iden`   | 32 bytes   | Identity  |
| `mix`    | 32 bytes   | Hash(state + signal)  |
| `idx`    | 4 bytes    | Intended state index  |

**Response:** None

---

**`pr`** — Proof

| Field      | Length     | Description  |
|------------|------------|----|
| `pr`       | 2 bytes    | Opcode  |
| `iden`     | 32 bytes   | Identity  |
| `state`    | 36 bytes   | Matching state  |
| `signal`   | 64 bytes   | Signal  |
**Response:**  
Same status codes as `re`

---

**`ve`** — Version

| Field    | Length     | Description |
|----------|------------|-------------|
| `ve`     | 2 bytes    | Opcode |

**Response:** UTF-8 encoded version string

---

#### 9.2 basenet TCP

**Advertisement String:** `basenet_0.1.0`

**Default Port** `4040`

**Shutdown Socket:** `.iden/basenet_tcp`  
*Listens for 'qu' shutdown command*

Exposes local basenet `of` and `id`, routed by shard.

See local basenet below for opcode details.

---

#### 9.3 sigprox TCP

Signing proxy wrapping both basenet and signaling services.  
Signatures are Ed25519, hashes are SHA256.

**A:  Client to Node:**  

|Field        |	Length    |     Description   |
|-------------|-----------|--------------------|
|  `0`        |  1 byte   |  Version prefix    |
| `node ID`   | 32 bytes  | Ed25519 public key |
| `challenge` | 64 bytes  | Random challenge   |
 
**B: Node to Client:**

|Field        |	Length  |  Description |
|-------------|-----------|---------------|
| `node ID`   | 32 bytes  | Ed25519 public key  |
| `signature` | 64 bytes  | Signature of challenge A |
| `challenge` | 64 bytes  | Random challenge  |


**C: Client to Node:**

|Field        |	Length  |     Description  |
|-------------|-----------|-----|
| `signature` | 64 bytes | Signature of challenge+message  |
| `length`    | 3 bytes  | Message length, 3 byte little-endian |
| `message`   | variable | Basenet or iden signaling message    |

**D: Node to Client:**

|Field        |	Length  |     Description |
|-------------|-----------|----------------|
| `signature` | 64 bytes | Signature of t + message hash + response  |
| `t`         | 8 bytes  | 64 bit floating point little-endian epoch time |
| `hash`      | 32 bytes | Sha256 hash of client's message  |
| `response`  | variable | Wrapped service's response to client message  |



### 10. Local (Unix Socket) APIs

---

#### 10.1 basenet (sharded)

**Sharded service listening on to socket path:** `.iden/bn<shard_number>`

**`of`** — Offer

|Field  |	Length	|   Description   |
--------|-----------|----------|
|`of`     |2 bytes	          |Opcode    |
|`iden`	|32 bytes	      |Identity to store payload under  |
|`idx`	    |4 bytes	          |state idx  |
|`hashkey`	|32 bytes	      |SHA256 hash of the payload |
|`length	`|2 bytes	          |Payload length (u16_le) |
|`payload`	|variable	      |UTF-8 encoded frame (with YAML header)|

**Response**:
None. The message is silently accepted or rejected based on internal checks. Duplicate entries are skipped.

---
  
**`ck`** —  Check

| Field | Length | Description |
|---|---|---|
| `ck` | 2 bytes | Opcode  |
| `iden` | 32 bytes | Identity to check |
| `idx` | 4 bytes | State idx to check for existing entry |

**Response**: "YE" / "NO"

---

**`id`** — "\iden://" URI retrieval

| Field | Length | Description |
|---|---|---|
| `"\iden://"` | 7 bytes | URI prefix |
| `uri` | variable | URI string to resolve |

**Response**: Payload / "!Not Found"

---

**`qu`** — Quit

| Field | Length | Description |
|---|---|---|
| `qu` | 2 bytes | Opcode |

**Response**: Service terminates.

---

#### 10.2 mproc (sharded)

**Sharded service listening on to socket path:** `.iden/<shard_number>`

**`ct`** — Message Count in Last `t` Seconds

| Field    | Length     | Description |
|----------|------------|--------|
| `ct`     | 2 bytes    | Opcode  |
| `t`      | 8 bytes    | Seconds as float64 (little-endian) |

**Response:** `count` (4 bytes, u32_le)

---

**`gt`** — Get Messages in Last `t` Seconds

| Field    | Length     | Description  |
|----------|------------|---------|
| `gt`     | 2 bytes    | Opcode  |
| `t`      | 8 bytes    | Seconds as float64 (little-endian) |

**Response:**

| Field            | Description  |
|------------------|--------------|
| `total_length`   | 4 bytes (u32_le) |
| `payload`        | Concatenated messages   |

---

**`ix`** — Index Lookup

| Field    | Length     | Description   |
|----------|------------|------|
| `ix`     | 2 bytes    | Opcode  |
| `iden`   | 32 bytes   | Identity  |

**Response:**  
`idx` (u32_le) if found, else single byte `0`

---

**`st`** — State Lookup

| Field    | Length     | Description   |
|----------|------------|------------|
| `st`     | 2 bytes    | Opcode  |
| `iden`   | 32 bytes   | Identity  |

**Response:**  
36-byte state or single byte `0` if not found

---

**`si`** — Signal Lookup

| Field    | Length     | Description  |
|----------|------------|---------------|
| `si`     | 2 bytes    | Opcode    |
| `iden`   | 32 bytes   | Identity  |
| `idx`    | 4 bytes    | Idx, Little Endian  |

**Response:**  
64-byte signal or single byte `0` if not found

---

**`re`** — Report State

| Field    | Length     | Description  |
|----------|------------|------------|
| `re`     | 2 bytes    | Opcode |
| `iden`   | 32 bytes   | Identity  |
| `state`  | 36 bytes   | Reported new state  |

**Response:**  
Status byte:  
`0 = OK`, `1 = Bad size`, `2 = Too low`, `3 = Too far`, `4 = False`

---

**`cl`** — Claim

| Field    | Length     | Description  |
|----------|------------|---------|
| `cl`     | 2 bytes    | Opcode |
| `iden`   | 32 bytes   | Identity  |
| `mix`    | 32 bytes   | Hash(state + signal)  |
| `idx`    | 4 bytes    | Intended state index  |

**Response:** None

---

**`pr`** — Proof

| Field      | Length     | Description |
|------------|------------|-----------|
| `pr`       | 2 bytes    | Opcode  |
| `iden`     | 32 bytes   | Iden  |
| `state`    | 36 bytes   | State   |
| `signal`   | 64 bytes   | Signal   |
**Response:**  
Same status codes as `re`

---

**`ve`** — Version

| Field    | Length     | Description  |
|----------|------------|--------------|
| `ve`     | 2 bytes    | Opcode  |

**Response:** UTF-8 encoded version string

---

**`qu`** — Quit

| Field | Length | Description |
|---|---|---|
| `qu` | 2 bytes | Opcode |

**Response**: Service terminates.

---

#### 10.3 throttle

**Socket Path:** `.iden/throttle`

Purpose:

Rate-limits incoming requests by IP. Tracks last seen time and optional iden "dedicated". 
(Only applied for `cl`,`pr`, and `re`).

**`??`** — Throttle Check

|Field	|Length	 |      Description|
|-------|--------|-----|
`??`	    |2 bytes |	Opcode
`ip`	    |4 bytes |	IPv4 address
`iden` | 32 bytes | Iden requesting access

**Response**:

|Field	|Length	|Description   |
|-------|-------|-----------------------|
|delay	|8 bytes|	Seconds to sleep (f64_le)|

---

**`de`** — Dedicate IP to Iden

|Field	|Length	|Description    |
|-------|-------|----------------|
|`de`	    |2 bytes|	Opcode    |
|`ip`	    |4 bytes	| IPv4 address  |
|`iden`	|32 bytes|	Iden to assign this IP to (for future bypass) |

**Response:**

|Field	|Length	|Description  |
|-------|-------|---------------------|
|delay	|8 bytes|	Seconds to wait (f64_le) |

**`qu`** — Quit
**`qu`** — Quit

| Field | Length | Description |
|---|---|---|
| `qu` | 2 bytes | Opcode |

**Response**: Service terminates.

---


#### 10.4 peerstat

**`ad`** — Add/Advertise Peer

|Field	|Length	|Description|
|-------|---------|---------------|
|`ad`	    |2 bytes  |	Opcode  |
|`peer_id`	|32 bytes |	Identity of the peer |
|`info`	|variable |	UTF-8 label (null-terminated optional)  |

**Response:** None

Adds a peer to the local cache. 

---

**`gn`** — Get N Peers

|Field	|Length	  |Description |
|-------|---------|------------|
|`gn`	    |2 bytes  |	Opcode |
|`count`	|2 bytes	  | Number of peers requested (u16 little endian)|

**Response:**

|Field	|Description   |
|-------|--------------|
|`record_count`|	u16_le — number of peers returned |
|`records` |Each record is [32-byte iden] + [UTF-8 string, null-terminated]|



**`qu`** — Quit

| Field | Length | Description |
|---|---|---|
| `qu` | 2 bytes | Opcode |

**Response**: Service terminates.

---

#### 10.5 padman

**Socket Path:** .iden/padman

Role: State issuer — manages encrypted checkpointed pad and issues states to local client software.

**`ix`** — Get Current Index

|Field	|Length	|Description|
--------|-------|-----------|
|`ix`	|2 bytes|	Opcode |

**Response:**

idx as 4 bytes (u32_le)

---

**`id`** — Get Managed Iden

|Field	|Length	|Description|
|-------|-------|------------|
|`id`   | 2 bytes|	Opcode  |

**Response:**

iden string

---

**`st`** — Get next state

|Field	|Length	|Description|
|-------|-------|-----------|
|`st`	|2 bytes|	Opcode  |

**Response:**

36-byte state. Also increments idx in .iden/<name>.idx
 
---
 
**`qu`** — Quit

| Field | Length | Description |
|---|---|---|
| `qu` | 2 bytes | Opcode |

**Response**: Service terminates.

---

### 11. Socket & Port Summary

|Service | TCP Port	|  Unix Socket Path	| Notes | 
|--------|--------|----------|------|  
|`tcp_in`	 |	4004|	`.iden/tcp_in`| Public signaling ingress | 
|`sender`	 |	None|	`.iden/sender`| Relays outbound messages |
|`mproc`	 |None |`.iden/<shard_number>`| Signal processor, one per shard | 
|`basenet_in`	|4040	|`.iden/basenet_tcp`| Public basenet ingress (TCP) |
|`basenet`|	None| `.iden/bn<shard_number>`| Data store & retrieval engine | 
|`peerstat`|	None| `.iden/peerstat`| Tracks peers + service advertisements |
|`padman`|	None| `.iden/padman`| Pad/state manager for publishing | 
|`throttle`|	None| `.iden/throttle` | Rate-limiter for TCP clients | 
|`sigprox` | 8044	 | None	 | Signing proxy, wraps TCP services | 
|`basenet.py` | 8008 | None | HTTP + peerpub/preview rendering | 

[^4.1]: [markdown](https://daringfireball.net/projects/markdown/syntax)
[^4.2]: [python markdown](https://python-markdown.github.io/)
[^6.0]: [multibase](https://github.com/multiformats/multibase)
