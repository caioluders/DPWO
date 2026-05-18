#!/usr/bin/env python3
"""Build standalone binaries for DPWO using PyInstaller."""
import os
import subprocess
import sys

SCRIPT_DIR = os.path.dirname(os.path.abspath(__file__))

# PyInstaller data separator differs per platform
SEP = ";" if sys.platform == "win32" else ":"


def build_gui():
    print("Building DPWO GUI binary...")
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--windowed",
        "--name", "dpwo-gui",
        f"--add-data=plugins{SEP}plugins",
        os.path.join(SCRIPT_DIR, "gui.py"),
    ]
    subprocess.run(cmd, check=True, cwd=SCRIPT_DIR)
    print("GUI binary built: dist/dpwo-gui")


def build_cli():
    print("Building DPWO CLI binary...")
    cmd = [
        sys.executable, "-m", "PyInstaller",
        "--onefile",
        "--console",
        "--name", "dpwo",
        f"--add-data=plugins{SEP}plugins",
        os.path.join(SCRIPT_DIR, "dpwo.py"),
    ]
    subprocess.run(cmd, check=True, cwd=SCRIPT_DIR)
    print("CLI binary built: dist/dpwo")


def main():
    if len(sys.argv) < 2:
        print("Usage: python build.py [gui|cli|all]")
        sys.exit(1)

    target = sys.argv[1].lower()

    if target == "gui":
        build_gui()
    elif target == "cli":
        build_cli()
    elif target == "all":
        build_cli()
        build_gui()
    else:
        print(f"Unknown target: {target}")
        print("Usage: python build.py [gui|cli|all]")
        sys.exit(1)


if __name__ == "__main__":
    main()
