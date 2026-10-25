"""Active verification checks.

Every check is non-destructive by default: it reads, it never writes device state, and it
never degrades service. Checks that must change something to prove the weakness are marked
``intrusive`` in the knowledge base and only run when the operator passes ``--exploit``.
"""

from .base import REGISTRY, CheckContext, available_checks, load_all, register  # noqa: F401
