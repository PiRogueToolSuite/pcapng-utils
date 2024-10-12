<div align="center">
<img width="60px" src="https://pts-project.org/android-chrome-512x512.png">
<h1>PCAPNG to HAR Converter</h1>
<p>
Python-based tool for converting PCAPNG files to HAR files.
</p>
<p>
License: GPLv3 and MIT
</p>
<p>
<a href="https://pts-project.org">Website</a> | 
<a href="https://discord.gg/qGX73GYNdp">Support</a>
</p>
</div>

## Overview

This project is a Python-based tool for converting PCAPNG files to HAR files.
It supports both HTTP/1.1 and HTTP/2 protocols.

## Requirements

- Python 3.11+
- `tshark` (part of the Wireshark suite; **requires version >= 4.0**)

## Installation

1. Install Python 3.11 or higher.
2. Install `tshark` from the Wireshark suite.
3. Clone this repository:
```sh
git clone <repository_url>
cd <repository_directory>
```
4. Install the required Python packages:
```sh
pip install -r requirements.txt
```

## Usage

Prior to using this converter, please have a look at [documentation on how to convert .pcap to .pcapng](./pcapng_utils/tshark/wrapper.py#L54)

### Shell

Run `./pcapng_to_har.py [-h]` in your shell (with your Python virtual environment activated)

### Python

```python
from pcapng_to_har import pcapng_to_har, Tshark
def pcapng_to_har(
    input_file: Path | str,
    output_file: Path | str | None = None,
    *,
    tshark: Tshark | None = None,
    socket_operations_file: Path | str | None = None,
    cryptography_operations_file: Path | str | None = None,
    overwrite: bool = False,
    **json_dump_kws: Any,
) -> None:
```

## Licensing
This work is licensed under multiple licences:

* All the code in this repository is licensed under the GPLv3 license.
  * Copyright: 2024   U+039b <hello@pts-project.org>  
  * Copyright: 2024   Defensive Lab Agency <contact@defensive-lab.agency>
* The files containing a SPDX header are licensed under the MIT license.
  * Copyright: 2024   Pôle d'Expertise de la Régulation Numérique - PEReN <contact@peren.gouv.fr>
