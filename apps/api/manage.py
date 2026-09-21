#!/usr/bin/env python
"""AfricaWatch — Django management utility."""
import os, sys
def main():
    os.environ.setdefault("DJANGO_SETTINGS_MODULE","africanwatch.settings.dev")
    try: from django.core.management import execute_from_command_line
    except ImportError as exc: raise ImportError("Django introuvable.") from exc
    execute_from_command_line(sys.argv)
if __name__ == "__main__": main()
