# Run Pair on an original Jetson Nano

This ARM64 build targets the Ubuntu 18.04 / JetPack 4 userspace generation. Pair
has been user-confirmed on a physical Jetson Nano, although the exact JetPack
version was not recorded. The v0.2 discovery and phrase-pairing flow still needs
a fresh Jetson hardware check.

No installation or administrator password is required:

```sh
cd ~/Downloads
tar -xzf pair-linux-arm64-jetpack4.tar.gz
chmod +x pair
./pair
```

Run Pair from the graphical desktop. Choose **Connect**, select the nearby
Windows host, and compare the six-word phrase on both screens. If discovery is
blocked, enter the Windows laptop's LAN IPv4 address and port `47321` manually.

For missing-library errors, compare `ldd ./pair` with
`LINKED-LIBRARIES.txt`. See [connection help](docs/TROUBLESHOOTING.md).
