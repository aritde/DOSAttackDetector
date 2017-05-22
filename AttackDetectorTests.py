from AttackDetector import AttackDetector
from Record import Record
import unittest
import os

class AttackDetectorTests(unittest.TestCase):
	def setUp(self):
		self.testdata = os.path.join(os.path.dirname(__file__), 'testData.txt')

	def test_loadInput(self):
		obj = AttackDetector()
		self.assertEqual(obj.loadInput(self.testdata),5)

	def test_calculateTimeDifference(self):
		obj = AttackDetector()
		self.assertEqual(obj.calculateTimeDifference('23:03:15','23:07:15'),240000)

	def test_splitFields(self):
		obj = AttackDetector()
		r = obj.splitFields("200.4.91.190 - - [25/May/2015:23:11:15 +0000] \"GET / HTTP/1.0\" 200 3557 \"-\" \"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)")
		self.assertIsInstance(r,Record)
if __name__ == '__main__':
	unittest.main()
