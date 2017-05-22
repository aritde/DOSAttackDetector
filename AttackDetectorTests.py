from AttackDetector import AttackDetector 
import unittest

class AttackDetectorTests(unittest.TestCase):
	def test_calculateTimeDifference(self):
		obj = AttackDetector()
		self.assertEqual(obj.calculateTimeDifference('23:03:15','23:07:15'),240000)
if __name__ == '__main__':
	unittest.main()
