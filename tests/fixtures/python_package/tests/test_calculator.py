import unittest
from src.calculator import add, multiply

class TestCalculator(unittest.TestCase):
    def test_add(self):
        self.assertEqual(add(2, 3), 5)

    def test_multiply(self):
        self.assertEqual(multiply(3, 4), 12)

if __name__ == "__main__":
    unittest.main()
