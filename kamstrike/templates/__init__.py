"""YAML vulnerability templates and the engine that runs them.

Templates are data: a few HTTP requests plus the matchers that decide whether the response
proves the issue. KAMSTRIKE executes them itself, so there is nothing to install and nothing
to keep in sync.
"""

from .engine import INTRUSIVE_TAG, Match, Template, TemplateError, load_dir, load_file, parse
from .loader import TemplateConfig, catalogue, library_dir, load, run, select

__all__ = [
    "INTRUSIVE_TAG", "Match", "Template", "TemplateConfig", "TemplateError", "catalogue",
    "library_dir", "load", "load_dir", "load_file", "parse", "run", "select",
]
