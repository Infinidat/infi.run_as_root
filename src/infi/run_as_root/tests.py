from . import RootPermissions, exit_if_not_root, BYPASS_KEY
from infi import unittest
from mock import patch
import os
import sys

#pylint: disable-all

_environ = os.environ

class TestRootPermissions(unittest.TestCase):
    @unittest.parameters.iterate("result", [True])
    def test_bypass(self, result):
        os.environ = {}
        if result:
            os.environ[BYPASS_KEY] = '1'
        self.assertEqual(RootPermissions().is_root(), result)
        if result:
            del(os.environ[BYPASS_KEY])
        os.environ = _environ

    def test__platorm_specific(self):
        # We just check that there was no error
        _ = RootPermissions().is_root()


class TestDecorator(unittest.TestCase):
    @patch.object(sys, "exit")
    @patch.object(RootPermissions, "is_root",)
    def test__no_root(self, is_root, exit_patch):
        is_root.return_value = False
        @exit_if_not_root
        def callable():
            pass
        callable()
        self.assertTrue(exit_patch.called)

    @patch.object(RootPermissions, "is_root")
    def test__root(self, patch):
        patch.return_value = True
        @exit_if_not_root
        def callable():
            pass
        callable()

