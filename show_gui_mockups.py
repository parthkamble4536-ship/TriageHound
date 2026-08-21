import sys
import platform

if len(sys.argv) < 2:
    print("Usage: python show_gui_mockups.py [mac|linux]")
    sys.exit(1)

os_target = sys.argv[1].lower()

if os_target == "mac":
    platform.system = lambda: "Darwin"
    print("Spoofing macOS (v2.0) environment...")
elif os_target == "linux":
    platform.system = lambda: "Linux"
    print("Spoofing Linux (v3.0) environment...")
else:
    print("Invalid target. Use 'mac' or 'linux'")
    sys.exit(1)

import gui
gui.main()
