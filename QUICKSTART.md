# Quick Start:


### Python Setup:

```bash
python3 -m venv .venv
source .venv/bin/activate
pip3 install fastapi uvicorn pynacl pyyaml markdown
```


### Install Rust:

```bash

curl --proto '=https' --tlsv1.2 -sSf https://sh.rustup.rs | sh
source ~/.cargo/env
```

###  Install Zenity:  
*(used by padman for password prompt; run with `--no-gui` if not in a desktop environment)*

```bash

sudo apt install zenity
```


### Build & Install:

```bash

git clone https://github.com/stevenaleach/iden
cd iden
./install.sh  # Builds all components and installs the binaries locally
```


### Generate & Store an Iden:

```bash

cd
iden init  # Sets up the .iden directory and configuration files
iden generate newpad.txt  # Creates a new identity
iden store newpad.txt .iden/test.pad 500000  # Stores an encrypted checkpoint

```


### Launch Pad Manager:

```bash

iden padman test & # Launches the pad manager, serving .iden/test.pad
```



### Next:
Import basenet in a Jupyter notebook and test writing and reading from the test node, idens.net:  
  

```python

# In Jupyter, import basenet from ~/bin
import os, sys
bin_path = os.path.expanduser("~/bin")
if bin_path not in sys.path:
    sys.path.insert(0, bin_path)
import basenet as bn
```
