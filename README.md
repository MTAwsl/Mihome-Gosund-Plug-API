# Mihome-Gosund-Plug-API

This repository contains basic library file to implement controls(on/off) of Mihome Gosund Plugs.

## Usage

First install required dependencies using 

```
pip install -r requirements.txt
```

Copy gosund_plug.py and miio.py to your working directory.

Import GosundPlug class and you are ready to go :)

Example:

```python
from gosund_plug import GosundPlug

usage = GosundPlug("YOUR IP ADDRESS", "YOUR TOKEN'S HERE")
example = GosundPlug("192.168.1.233", "ffffffffffffffffffffffffffffffff")

print(example.status()) # Returns a boolean which value is True when it's on and False when it's off

example.on() # Switch on
example.off() # Switch off
```

## Credits

Miio protocal: https://github.com/OpenMiHome/mihome-binary-protocol

Gosund Plug control: https://github.com/rytilahti/python-miio/blob/miot_basics/miio/gosund_plug.py
