#!/usr/bin/env python3
"""
============================================================================
SHARED SCAN UTILITIES - Common code for all Python modules
============================================================================
Provides:
1. ScanConfig dataclass
2. run_command() helper
3. Signal/interrupt handling
4. Console fallback
============================================================================
"""

import os
import signal
import subprocess
from dataclasses import dataclass, field
from pathlib import Path
from threading import Event
from typing import Dict, List, Optional, Tuple

# ============================================================================
# CONSOLE SETUP (Rich with fallback)
# ============================================================================
try:
    from rich.console import Console
    from rich.progress import Progress, SpinnerColumn, TextColumn
    console = Console()
except ImportError:
    class Console:
        def print(self, *args, **kwargs):
            print(*args)
        def log(self, *args, **kwargs):
            print(*args)
    console = Console()
    Progress = None
    SpinnerColumn = None
    TextColumn = None


# ============================================================================
# INTERRUPT HANDLING
# ============================================================================
_interrupted = Event()


def signal_handler(signum, frame):
    """Handle SIGINT (Ctrl-C) gracefully."""
    _interrupted.set()
    console.print("\n[yellow]════════════════════════════════════════════════════════════[/yellow]")
    console.print("[yellow]  INTERRUPT RECEIVED - Stopping current operations[/yellow]")
    console.print("[cyan]  • Current scans will be terminated[/cyan]")
    console.print("[cyan]  • Results so far will be saved[/cyan]")
    console.print("[green]  • Pipeline will continue to next module[/green]")
    console.print("[yellow]════════════════════════════════════════════════════════════[/yellow]\n")


def is_interrupted() -> bool:
    """Check if interrupt was requested."""
    return _interrupted.is_set()


def reset_interrupt():
    """Reset interrupt flag (for testing)."""
    _interrupted.clear()


def install_signal_handler():
    """Install the graceful SIGINT handler."""
    signal.signal(signal.SIGINT, signal_handler)


# Install by default when imported
install_signal_handler()


# ============================================================================
# DATA CLASSES
# ============================================================================
@dataclass
class ScanConfig:
    """Unified configuration for all scanning modules."""
    output_dir: str
    config_file: str = ""
    fast_mode: bool = False
    stealth_mode: bool = False
    threads: int = 25
    rate_limit: int = 150
    allow_destructive: bool = False
    nuclei_severity: str = "critical,high,medium"
    blind_xss_callback: str = ""
    timeout: int = 300
    max_targets: int = 100


# ============================================================================
# COMMAND EXECUTION
# ============================================================================
def run_command(cmd: List[str], output_file: Optional[str] = None,
                timeout: int = 3600) -> Tuple[bool, str, int]:
    """
    Run a command and capture output.

    Args:
        cmd: Command as list of arguments
        output_file: Optional file path to save output
        timeout: Max execution time in seconds

    Returns:
        Tuple of (success, output, return_code)
    """
    try:
        cmd_preview = ' '.join(cmd[:5]) + ('...' if len(cmd) > 5 else '')
        console.log(f"[cyan]Running:[/cyan] {cmd_preview}")

        result = subprocess.run(
            cmd,
            capture_output=True,
            text=True,
            timeout=timeout
        )

        output = result.stdout + result.stderr

        # Log warnings for non-zero exit codes
        if result.returncode != 0 and result.stderr:
            error_preview = result.stderr[:200].strip()
            if error_preview:
                console.log(f"[yellow]Warning: {error_preview}[/yellow]")

        if output_file:
            with open(output_file, 'w') as f:
                f.write(output)
            if result.returncode == 0:
                console.log(f"[green]Output saved: {output_file}[/green]")

        return result.returncode == 0, output, result.returncode

    except subprocess.TimeoutExpired:
        console.log(f"[yellow]Command timed out after {timeout}s[/yellow]")
        return False, "Timeout", -1
    except FileNotFoundError as e:
        console.log(f"[red]Command not found: {cmd[0]}[/red]")
        return False, str(e), -2
    except Exception as e:
        console.log(f"[red]Command failed: {e}[/red]")
        return False, str(e), -3
