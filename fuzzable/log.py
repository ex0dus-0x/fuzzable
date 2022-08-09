"""
log.py
"""
import logging
from rich.logging import RichHandler

# hacky way to turn off angr verbosity
for log in ["angr", "pyvex", "claripy", "cle"]:
    logger = logging.getLogger(log)
    logger.disabled = True
    logger.propagate = False

FORMAT = "%(message)s"
logging.basicConfig(
    level="NOTSET", format=FORMAT, datefmt="[%X]", handlers=[RichHandler()]
)
log = logging.getLogger("fuzzable")
log.setLevel(logging.INFO)
