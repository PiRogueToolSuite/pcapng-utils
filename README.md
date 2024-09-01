# PCAPNG to HAR Converter

## Overview

This project is a Python-based tool for converting PCAPNG files to HAR files. It supports both HTTP/1.1 and HTTP/2 protocols.

## Requirements

- Python 3.6+
- `tshark` (part of the Wireshark suite)

## Installation

1. Install Python 3.6 or higher.
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
```python
from pathlib import Path

from pcapng_utils.tshark.traffic import NetworkTrafficDump
from pcapng_utils.tshark.wrapper import Tshark

tshark_path = '/Applications/Wireshark.app/Contents/MacOS/tshark'
input_file = Path('input.pcapng')
# Load the traffic from the PCAPNG file
tshark_wrapper = Tshark(pcapng_file=input_file, tshark_path=tshark_path)
tshark_wrapper.load_traffic()
# Parse the traffic
traffic = NetworkTrafficDump(tshark_wrapper.traffic)
traffic.parse_traffic()
# Save the HAR file
traffic.save_har(Path('output.har'))
```