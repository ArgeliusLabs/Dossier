"""Entry point for standalone (PyInstaller) builds. Not needed when installed with pip."""
from dossier.cli import main

if __name__ == "__main__":
    raise SystemExit(main())
