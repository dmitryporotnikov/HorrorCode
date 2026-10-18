# HorrorCode

[![License: GPL-3.0](https://img.shields.io/github/license/dmitryporotnikov/HorrorCode)](LICENSE)
[![Windows](https://img.shields.io/badge/targets-Windows-0078D6?logo=windows)](CustomIOFilterDriver)
[![On purpose](https://img.shields.io/badge/quality-horrifying-red)](#)

Code I've written over the years for demos and for teaching new engineers how things break. Every project here is broken on purpose: a driver that stalls I/O, a DNS server that lies, a driver that bugchecks the machine.

Use it on a VM you can throw away.

| Project | What it does |
|---|---|
| [CustomIOFilterDriver](CustomIOFilterDriver) | A Windows filter driver that adds latency to I/O. Good for showing what a bad minifilter does to a machine. |
| [DPCBugcheckDriver](DPCBugcheckDriver) | A driver that takes the kernel down with a bugcheck. |
| [High-DPC-Simulator](High-DPC-Simulator) | A driver that fires timer DPCs every millisecond, which is a quick way to make a system feel terrible. |
| [Defunctdns](Defunctdns) | A dual-stack DNS server that answers A records over IPv4 and NXDOMAIN over IPv6. |
| [Non-RFC-Compliant-Cookie](Non-RFC-Compliant-Cookie) | A small web server that sets cookies with literal backslashes, for testing how proxies and middleware cope with RFC 6265 violations. |

Each directory has its own README, build steps and warnings. The driver projects need the Windows Driver Kit and a test machine, not your daily driver.

## License

GPL-3.0. See [LICENSE](LICENSE).
