"""forge -- intent-driven code design with signed, priced, content-addressed output.

Four subsystems, one pipeline:

* **intent**   -- a typed network graph describing what a system should be
* **transform** -- immutable, content-addressed records of every build step
* **signing**  -- Bitcoin-style SHA-256d merkle commitments, detached OpenPGP
* **payments** -- a published SEI price list and non-custodial settlement

Design invariants, enforced in code rather than documented and hoped for:

* deterministic: no clock, no PRNG, no unordered iteration in any build path
* non-custodial: no private key is ever held, read, derived, or transmitted
* content-addressed: nothing is identified by name where it can be identified
  by digest
"""

from .config import NETWORKS, Config, Rigor
from .errors import ForgeError
from .intent import Intent
from .transform import Artifact, TransformChain, TransformObject

__version__ = "0.1.0"

__all__ = [
    "__version__",
    "Config",
    "Rigor",
    "NETWORKS",
    "ForgeError",
    "Intent",
    "Artifact",
    "TransformObject",
    "TransformChain",
]
