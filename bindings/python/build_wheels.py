#!/usr/bin/env python3
"""
Build platform-specific wheels for sensor.

This script builds wheels with bundled native libraries for each platform.
Run this on each target platform or use CI/CD to build all wheels.
"""

import os
import platform
import shutil
import subprocess
import sys
from pathlib import Path

PLATFORM_TAGS = {
    ("linux", "amd64"): "manylinux_2_17_x86_64",
    ("linux", "arm64"): "manylinux_2_17_aarch64",
    ("darwin", "amd64"): "macosx_10_9_x86_64",
    ("darwin", "arm64"): "macosx_11_0_arm64",
    ("windows", "amd64"): "win_amd64",
    ("windows", "arm64"): "win_arm64",
}

LIB_EXTENSIONS = {
    "linux": ".so",
    "darwin": ".dylib",
    "windows": ".dll",
}

def get_current_platform():
    """Detect current platform."""
    system = platform.system().lower()
    machine = platform.machine().lower()

    if system == "darwin":
        os_name = "darwin"
    elif system == "windows":
        os_name = "windows"
    else:
        os_name = "linux"

    if machine in ("x86_64", "amd64"):
        arch = "amd64"
    elif machine in ("aarch64", "arm64"):
        arch = "arm64"
    else:
        arch = "amd64"

    return os_name, arch

def build_native_library(os_name, arch):
    """Build the native library for the specified platform."""
    script_dir = Path(__file__).parent
    clib_dir = script_dir.parent / "clib"

    print(f"Building native library for {os_name}/{arch}...")

    env = os.environ.copy()
    env["TARGET_OS"] = os_name
    env["TARGET_ARCH"] = arch

    result = subprocess.run(
        ["bash", "build.sh", "native"],
        cwd=clib_dir,
        env=env,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print(f"Build failed: {result.stderr}")
        sys.exit(1)

    print(result.stdout)

    ext = LIB_EXTENSIONS[os_name]
    lib_name = f"libsensor-{os_name}-{arch}{ext}"
    lib_path = clib_dir / "dist" / lib_name

    if not lib_path.exists():
        print(f"Library not found: {lib_path}")
        sys.exit(1)

    return lib_path

def copy_library_to_package(lib_path, os_name, arch):
    """Copy the native library to the package directory."""
    script_dir = Path(__file__).parent
    lib_dir = script_dir / "sensor" / "lib"
    lib_dir.mkdir(parents=True, exist_ok=True)

    for f in lib_dir.glob("libsensor-*"):
        f.unlink()

    dest = lib_dir / lib_path.name
    shutil.copy2(lib_path, dest)
    print(f"Copied {lib_path.name} to {lib_dir}")

    return dest

def build_wheel(os_name, arch):
    """Build a platform-specific wheel."""
    script_dir = Path(__file__).parent

    plat_tag = PLATFORM_TAGS.get((os_name, arch))
    if not plat_tag:
        print(f"Unknown platform: {os_name}/{arch}")
        sys.exit(1)

    print(f"Building wheel for {plat_tag}...")

    for d in ["build", "dist", "sensor.egg-info"]:
        p = script_dir / d
        if p.exists():
            shutil.rmtree(p)

    result = subprocess.run(
        [
            sys.executable, "-m", "pip", "wheel",
            "--no-deps",
            "--wheel-dir", "dist",
            ".",
        ],
        cwd=script_dir,
        capture_output=True,
        text=True,
    )

    if result.returncode != 0:
        print(f"Wheel build failed: {result.stderr}")
        sys.exit(1)

    dist_dir = script_dir / "dist"
    wheels = list(dist_dir.glob("sensor-*.whl"))

    if not wheels:
        print("No wheel found!")
        sys.exit(1)

    old_wheel = wheels[0]

    parts = old_wheel.stem.split("-")
    parts[-1] = plat_tag
    new_name = "-".join(parts) + ".whl"
    new_wheel = dist_dir / new_name

    old_wheel.rename(new_wheel)
    print(f"Created: {new_wheel}")

    return new_wheel

def main():
    """Main entry point."""
    import argparse

    parser = argparse.ArgumentParser(description="Build sensor wheels")
    parser.add_argument(
        "--platform",
        choices=["linux-amd64", "linux-arm64", "darwin-amd64", "darwin-arm64",
                 "windows-amd64", "windows-arm64", "native"],
        default="native",
        help="Target platform (default: native)",
    )
    parser.add_argument(
        "--skip-build",
        action="store_true",
        help="Skip building native library (use existing)",
    )

    args = parser.parse_args()

    if args.platform == "native":
        os_name, arch = get_current_platform()
    else:
        os_name, arch = args.platform.split("-")

    print(f"=== Building sensor wheel for {os_name}/{arch} ===")
    print()

    if not args.skip_build:
        lib_path = build_native_library(os_name, arch)
    else:
        script_dir = Path(__file__).parent
        clib_dir = script_dir.parent / "clib"
        ext = LIB_EXTENSIONS[os_name]
        lib_path = clib_dir / "dist" / f"libsensor-{os_name}-{arch}{ext}"
        if not lib_path.exists():
            print(f"Library not found: {lib_path}")
            print("Run without --skip-build first")
            sys.exit(1)

    copy_library_to_package(lib_path, os_name, arch)
    wheel_path = build_wheel(os_name, arch)

    print()
    print("=== Build complete! ===")
    print(f"Wheel: {wheel_path}")
    print()
    print("To install:")
    print(f"  pip install {wheel_path}")
    print()
    print("To upload to PyPI:")
    print(f"  twine upload {wheel_path}")

if __name__ == "__main__":
    main()
