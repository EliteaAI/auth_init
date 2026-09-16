"""Helpers for importing auth_init modules outside the Pylon runtime."""
import importlib
import pathlib
import sys
import types
from typing import Any

# auth_init/__init__.py imports .module, which pulls in the whole Pylon runtime.
# Tests therefore never import the real package: they register a synthetic one
# whose __path__ points at the plugin directory, so relative imports inside the
# module under test resolve against the real files without __init__ running.
PACKAGE_NAME = "auth_init_under_test"

SUBPACKAGES = ("rpc",)


class Log:
    """Pylon's log, recording what the module chose to say."""

    def __init__(self):
        self.warnings = []
        self.exceptions = []

    def info(self, message, *args, **kwargs):
        pass

    def debug(self, message, *args, **kwargs):
        pass

    def error(self, message, *args, **kwargs):
        pass

    def critical(self, message, *args, **kwargs):
        pass

    def warning(self, message, *args, **kwargs):
        self.warnings.append(message % args if args else message)

    def exception(self, message, *args, **kwargs):
        self.exceptions.append(message % args if args else message)


def install_pylon_stubs() -> Log:
    """Register the minimal import surface auth_init's rpc modules need."""
    log = Log()

    pylon = sys.modules.get("pylon") or types.ModuleType("pylon")
    pylon_core = sys.modules.get("pylon.core") or types.ModuleType("pylon.core")
    pylon_core_tools = types.ModuleType("pylon.core.tools")

    pylon_core_tools.log = log
    pylon_core_tools.web = types.SimpleNamespace(rpc=lambda *a, **k: lambda f: f)
    pylon_core_tools.module = types.SimpleNamespace()

    pylon.core = pylon_core
    pylon_core.tools = pylon_core_tools

    sys.modules["pylon"] = pylon
    sys.modules["pylon.core"] = pylon_core
    sys.modules["pylon.core.tools"] = pylon_core_tools

    # from plugins.auth_core.tools import rpc_tools - the real wrap_exceptions
    # converts anything that is not the given type into it. The processor is
    # tested for what it does with exceptions itself, so this passes through.
    rpc_tools = types.ModuleType("plugins.auth_core.tools.rpc_tools")
    rpc_tools.wrap_exceptions = lambda _exception_type: lambda func: func

    plugins = types.ModuleType("plugins")
    plugins_auth_core = types.ModuleType("plugins.auth_core")
    plugins_auth_core_tools = types.ModuleType("plugins.auth_core.tools")
    plugins_auth_core_tools.rpc_tools = rpc_tools

    sys.modules["plugins"] = plugins
    sys.modules["plugins.auth_core"] = plugins_auth_core
    sys.modules["plugins.auth_core.tools"] = plugins_auth_core_tools
    sys.modules["plugins.auth_core.tools.rpc_tools"] = rpc_tools

    # from tools import auth_core - replaced per test with a recorder.
    tools = types.ModuleType("tools")
    tools.auth_core = None
    sys.modules["tools"] = tools

    return log


def register_plugin_package(plugin_root: pathlib.Path) -> None:
    """Map PACKAGE_NAME onto the plugin directory without executing __init__."""
    if PACKAGE_NAME in sys.modules:
        return

    package = types.ModuleType(PACKAGE_NAME)
    package.__path__ = [str(plugin_root)]
    sys.modules[PACKAGE_NAME] = package

    for name in SUBPACKAGES:
        subpackage = types.ModuleType(f"{PACKAGE_NAME}.{name}")
        subpackage.__path__ = [str(plugin_root / name)]
        sys.modules[f"{PACKAGE_NAME}.{name}"] = subpackage
        setattr(package, name, subpackage)


def import_plugin_module(plugin_root: pathlib.Path, dotted: str) -> Any:
    """Import e.g. "rpc.processor" from the plugin, relative imports included."""
    register_plugin_package(plugin_root)

    return importlib.import_module(f"{PACKAGE_NAME}.{dotted}")
