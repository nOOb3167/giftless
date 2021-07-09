"""Tests for fix_flask_classful
"""
import types


class CaplogClear():
    def __init__(self, caplog):
        self.caplog = caplog

    def __enter__(self):
        pass

    def __exit__(self, *args):
        self.caplog.clear()


def test_fix_if_needed(caplog, monkeypatch):
    """Test unconditionally applying fix.
    """
    monkeypatch.setenv('GIFTLESS_CLASSFUL_FIX_SKIP', '1')

    import giftless.classful_fix

    with giftless.classful_fix.SysModuleClearRestore('flask_classful'), \
         giftless.classful_fix.SysModuleClearRestore('giftless.classful_fix'):

        with CaplogClear(caplog):
            giftless.classful_fix.fix_if_needed(force=True)
            giftless.classful_fix.log_print()
            import flask_classful
            assert giftless.classful_fix.module_inspect_signature(flask_classful.__dict__)
            assert 'applying fix' in caplog.text


def test_error_module_exists(caplog, monkeypatch):
    """Test against accidentally importing flask_classful before the fix.
    """
    monkeypatch.setenv('GIFTLESS_CLASSFUL_FIX_SKIP', '1')

    import giftless.classful_fix

    with giftless.classful_fix.SysModuleClearRestore('flask_classful'), \
         giftless.classful_fix.SysModuleClearRestore('giftless.classful_fix'):

        with CaplogClear(caplog):
            import flask_classful

            import giftless.classful_fix
            giftless.classful_fix.fix_if_needed(force=False)
            giftless.classful_fix.log_print()
            assert giftless.classful_fix.module_inspect_signature(flask_classful.__dict__)
            assert 'module exists at fix_if_needed call time' in caplog.text


def test_inspect_signature(monkeypatch):
    def mkmod(s: str):
        m = types.ModuleType('dummy')
        exec(s, m.__dict__)
        return m

    monkeypatch.setenv('GIFTLESS_CLASSFUL_FIX_SKIP', '1')

    import giftless.classful_fix

    assert giftless.classful_fix.module_inspect_signature(mkmod(r'''\
        class FlaskView:
            def register(foo, bar, init_argument=None, baz=None):
                pass
    ''').__dict__)

    assert giftless.classful_fix.module_inspect_signature(mkmod(r'''\
        class FlaskView:
            def register(init_argument=None):
                pass
    ''').__dict__)

    assert not giftless.classful_fix.module_inspect_signature(mkmod(r'''\
        class FlaskView:
            def register():
                pass
    ''').__dict__)

    assert not giftless.classful_fix.module_inspect_signature(mkmod(r'''\
        class FlaskView:
            pass
    ''').__dict__)

    assert not giftless.classful_fix.module_inspect_signature(mkmod(r'''\
        class Foo:
            pass
    ''').__dict__)
