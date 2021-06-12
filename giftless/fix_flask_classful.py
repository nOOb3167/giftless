"""Flask Classful fixer
"""
import importlib.resources
import inspect
import runpy
import sys
import traceback
import warnings
import zipimport


PACKAGE_NAME = 'giftless'
WHEEL_NAME = 'fix_flask_classful.whl'
CLASSFUL_MODULE_NAME = 'flask_classful'


def module_check_fix_needed(moddict):
    # check for module.FlaskView.register(..., init_argument, ...) signature
    fw = moddict['FlaskView']
    re = fw.register
    ar = inspect.getfullargspec(re)
    return 'init_argument' not in ar.args


def fix_if_needed():
    try:
        if sys.modules.get(CLASSFUL_MODULE_NAME):
            warnings.warn('fix_flask_classful module exists at fix_if_needed call time')
        # run $CLASSFUL_MODULE_NAME as found on sys.path (but do not 'import' it into sys.modules)
        # this lets us inspect its defined classes and functions
        moddict = runpy.run_module(CLASSFUL_MODULE_NAME, alter_sys=True)
        # if fix is needed ...
        if module_check_fix_needed(moddict):
            warnings.warn('fix_flask_classful applying fix', category=DeprecationWarning)
            # ... import $CLASSFUL_MODULE_NAME from our packaged wheel file
            with importlib.resources.path(PACKAGE_NAME, WHEEL_NAME) as p:
                zi = zipimport.zipimporter(p)
                zi.load_module(CLASSFUL_MODULE_NAME)
    except:
        warnings.warn(f'fix_flask_classful skipped having raised [{traceback.format_exc()}]')
