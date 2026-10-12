import unittest
from src.core import compute

class TestCore(unittest.TestCase):
    def test_broken(self):
        self.assertEqual(compute(), 999)
