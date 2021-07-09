"""Tests for fix_flask_classful
"""
import sys
import types
import typing
from importlib import import_module

FLASK_CLASSFUL_MODULE = 'flask_classful'
CLASSFUL_FIX_MODULE = 'giftless.classful_fix'


class SysModuleRestore():
    mod_name: str
    mod: typing.Optional[types.ModuleType]

    def __init__(self, mod_name: str):
        self.mod_name = mod_name

    def __enter__(self):
        self.mod = sys.modules.get(self.mod_name, None)
        return self

    def __exit__(self, *args):
        sys.modules[self.mod_name] = self.mod
        if self.mod is None:
            del sys.modules[self.mod_name]


class CaplogClear():
    def __init__(self, caplog):
        self.caplog = caplog

    def __enter__(self):
        pass

    def __exit__(self, *args):
        self.caplog.clear()


def sys_module_remove(mod_name: str):
    sys.modules.pop(mod_name, None)


def test_fix_if_needed(caplog, monkeypatch):
    """Test unconditionally applying fix.
    """
    monkeypatch.setenv('GIFTLESS_CLASSFUL_FIX_SKIP', '1')

    with SysModuleRestore(FLASK_CLASSFUL_MODULE), \
         SysModuleRestore(CLASSFUL_FIX_MODULE):

        with CaplogClear(caplog):
            sys_module_remove(FLASK_CLASSFUL_MODULE)
            sys_module_remove(CLASSFUL_FIX_MODULE)
            import giftless.classful_fix
            giftless.classful_fix.fix_if_needed(force=True)
            giftless.classful_fix.log_print()
            assert giftless.classful_fix.module_inspect_signature(import_module(FLASK_CLASSFUL_MODULE).__dict__)
            assert 'applying fix' in caplog.text


def test_error_module_exists(caplog, monkeypatch):
    """Test for ability to report a too-late import of classful_fix
    """
    monkeypatch.setenv('GIFTLESS_CLASSFUL_FIX_SKIP', '1')

    with SysModuleRestore(FLASK_CLASSFUL_MODULE), \
         SysModuleRestore(CLASSFUL_FIX_MODULE):

        with CaplogClear(caplog):
            # start with neither imported
            # import installed flask_classful and fix
            # ensure warning is reported
            sys_module_remove(FLASK_CLASSFUL_MODULE)
            sys_module_remove(CLASSFUL_FIX_MODULE)
            import_module(FLASK_CLASSFUL_MODULE)
            import giftless.classful_fix
            giftless.classful_fix.fix_if_needed(force=False)
            giftless.classful_fix.log_print()
            assert giftless.classful_fix.module_inspect_signature(import_module(FLASK_CLASSFUL_MODULE).__dict__)
            assert 'module exists at fix_if_needed call time' in caplog.text
