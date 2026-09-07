# Run pair on an original Jetson Nano

This ARM64 build is produced in an Ubuntu 18.04 container for the JetPack 4
userspace generation. It has not yet been run on physical Jetson hardware.

No installation or administrator password is required. From the Jetson's
graphical desktop, download `pair-linux-arm64-jetpack4.tar.gz`, then open a
terminal and run:

```sh
cd ~/Downloads
tar -xzf pair-linux-arm64-jetpack4.tar.gz
chmod +x pair
./pair
```

If the browser saved the file elsewhere, change `~/Downloads` accordingly. The
window requires the Jetson's graphical X11 desktop. It will not open from a
headless console without a display session.

Choose **Connect**, enter the Windows laptop's local IPv4 address, leave port
`47321`, paste the pairing code shown by the Windows host, and click **Connect**.

If the program reports a missing shared library, compare it with
`LINKED-LIBRARIES.txt` and open an issue with the exact error plus:

```sh
cat /etc/nv_tegra_release
lsb_release -ds
ldd ./pair
```
