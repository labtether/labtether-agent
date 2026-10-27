# Remote desktop input on Linux (X11)

To control an X11 desktop over WebRTC from the hub, the machine needs a few
extra tools.

X11 control requires `xdotool` and `xmodmap` in addition to the desktop capture
stack. Install `x11-xserver-utils` on Debian/Ubuntu, `xorg-xmodmap` on Arch, or
`xmodmap` on Fedora, openSUSE and Alpine. Missing or failed keymap tools leave
X11 WebRTC control unavailable.

The agent reads the current X11 keymap for each new key press. Repeats, release
and disconnect cleanup use the physical key number saved for that press.
This keeps a layout change from redirecting cleanup and lets controllers share
held keys without releasing each other's holds. Keys absent from the server
keymap fail explicitly; the agent does not change the keymap or add implicit
modifier presses. A bounded internal XTEST helper sends keys without changing
the active XKB layout group. A custom `LABTETHER_EXEC_ALLOWED_BINARIES` list
must permit `labtether-x11-input` as well as `xdotool` and `xmodmap`; the default
policy already allows all three.
