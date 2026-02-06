+++
title = "Fawkes"
chapter = true
weight = 100
+++

## Summary

Fawkes is a Golang-based Mythic C2 agent with cross-platform support (Windows, Linux, macOS). It features multiple process injection techniques, in-memory code execution, token manipulation, and binary inflation for evasion.

### Highlighted Agent Features

- Cross-platform agent (Windows, Linux, macOS)
- Multiple process injection techniques (PoolParty, Opus, Threadless, APC, Vanilla)
- In-memory .NET assembly and BOF/COFF execution
- Token manipulation (make, steal, rev2self)
- Memory read/write for runtime patching (AMSI/ETW bypass)
- Binary inflation at build time for entropy/size manipulation
- Garble obfuscation support
- Shellcode output via sRDI

## Author

- [@galoryber](https://github.com/galoryber)

## Table of Contents

{{% children %}}
