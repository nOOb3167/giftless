"""Flask Classful fixer.
The fix must be called early-on at startup.
Importing this module is sufficient to trigger the fix.
"""
import importlib.resources
import inspect
import logging
import os
import runpy
import sys
import traceback
from types import ModuleType
from typing import Optional
import zipimport

PACKAGE_NAME = 'giftless'
WHEEL_NAME = 'fix_flask_classful.whl'
CLASSFUL_MODULE_NAME = 'flask_classful'


_log = []

def log_msg(s: str) -> None:
    _log.append(s)

def log_print() -> None:
    l = logging.getLogger(__name__)
    for s in _log:
        l.warning(s)
    _log.clear()

def sys_module_remove(mod_name: str):
    sys.modules.pop(mod_name, None)

class SysModuleClearRestore:
    mod_name: str
    only_on_exception: bool
    mod: Optional[ModuleType]

    def __init__(self, mod_name: str, only_on_exception=False):
        self.mod_name = mod_name
        self.only_on_exception = only_on_exception

    def __enter__(self):
        self.mod = sys.modules.pop(self.mod_name, None)
        return self

    def __exit__(self, typ, val, tb):
        if self.mod and (not self.only_on_exception or (self.only_on_exception and val)):
            sys.modules[self.mod_name] = self.mod

def module_inspect_signature(moddict: dict) -> bool:
    """Check is done by looking up and checking object from a passed module dictionary.
    Does the signature look like this: module.FlaskView.register(..., init_argument, ...)
    """
    fw = moddict['FlaskView']
    re = fw.register
    ar = inspect.getfullargspec(re)
    return 'init_argument' in ar.args

def import_from_packaged_wheel() -> None:
    with importlib.resources.path(PACKAGE_NAME, WHEEL_NAME) as p:
        zi = zipimport.zipimporter(p)
        zi.load_module(CLASSFUL_MODULE_NAME)

def fix_if_needed(force=False) -> None:
    """ Detect and fix for being run with a 'bad' flask_classful.
    - Run $CLASSFUL_MODULE_NAME as found on sys.path (but do not 'import' it into sys.modules).
      This lets us inspect its defined classes and functions.
    - On failed inspection import $CLASSFUL_MODULE_NAME from our packaged wheel file.
    """
    try:
        with SysModuleClearRestore(CLASSFUL_MODULE_NAME) as cm:
            if cm.mod:
                log_msg('module exists at fix_if_needed call time')
            moddict = runpy.run_module(CLASSFUL_MODULE_NAME, alter_sys=True)
            if not module_inspect_signature(moddict) or force:
                log_msg('applying fix')
                import_from_packaged_wheel()
    except:
        log_msg(f'skipped having raised [{traceback.format_exc()}]')


if not os.environ.get('GIFTLESS_CLASSFUL_FIX_SKIP'):
    fix_if_needed()
