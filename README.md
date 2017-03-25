ssSniff
------
ShadowSocks(SS) traffic sniffer

### Aim
Proof of concept of detecting SS traffic. Could be used for the improvement of SS. Or, for the censorship against SS. Either way, it is better to expose the vulnerabilities in advance and take the initiative.

### Usage
```
# install libpcap first, then
pip install -r requirements.txt
sudo ./sssniff.py
```
Finally, browse the web via your SS proxy. When the script detects more than 15 suspicious connections to/from one source, it will flag it to be a ShadowSocks server and print to the terminal.

### Method
ShadowSocks is famous for its randomness feature; however, the first packet of a connection is usually not expected to be random. Even in a TLS session, we expect to see some plaintext sections in the handshake stage. Therefore, one can detect ShadowSocks traffic by simply looking at the first few packets and calculating their entropy (as a measure of randomness). Together with some minor adjustments, this method suffices to detect the current ShadowSocks protocol at a high accuracy.

### TODO
* Develop a more general method to detect proxy traffic.
* Test for false-positive results.

### Credits
* [scapy](http://www.secdev.org/projects/scapy/) for packet sniffing/manipulation
* [dpkt](https://github.com/kbandla/dpkt) for packet parsing/creation
