from AttackDetector import AttackDetector
from Record import Record
import unittest
import os

class AttackDetectorTests(unittest.TestCase):
	def setUp(self):
		self.inputData = os.path.join(os.path.dirname(__file__), 'testData.txt')
		self.outputPath = os.path.join(os.path.dirname(__file__),'testSuspicious.txt')

	def test_loadInput(self):
		obj = AttackDetector()
		self.assertEqual(len(obj.loadInput(self.inputData)),803)

	def test_fraudDetection1(self):
		obj = AttackDetector()
		recordList = obj.loadInput(self.inputData)
		self.assertEqual(obj.fraudDetection(recordList,87),set(["211.188.214.36","118.133.241.175","238.164.11.148","73.173.0.163","240.163.130.99"]))
	
	def test_fraudDetection2(self):
                obj = AttackDetector()
                recordList = obj.loadInput(self.inputData)
                self.assertNotEqual(obj.fraudDetection(recordList,87),set(["211.188.214.36","81.41.76.1","238.164.11.148","73.173.0.163","240.163.130.99"]))	
	
	def test_writeOutput(self):
		obj = AttackDetector()
		recordList = obj.loadInput(self.inputData)
		outputData = "/dosDetector/testSuspicious.txt"
		setOfSuspiciousIPs=obj.fraudDetection(recordList,87)
		result = set()
		obj.writeOutput(setOfSuspiciousIPs,outputData)
		contents = open(self.outputPath)
		for line in contents:
			result.add(line[:-1])
		self.assertEqual(result,setOfSuspiciousIPs)
		contents.close()
	"""		 				
	def test_calculateTimeDifference1(self):
		obj = AttackDetector()
		self.assertRaises(TypeError,obj.calculateTimeDifference(230315,'23:07:15'))
	
	def test_calculateTimeDifference2(self):
                obj = AttackDetector()
                self.assertRaises(TypeError,obj.calculateTimeDifference('23:03:15',230715))
	"""
	def test_calculateTimeDifference3(self):
		obj = AttackDetector()
		self.assertEqual(obj.calculateTimeDifference('23:03:15','23:07:15'),240000)
	
	def test_splitFields(self):
		obj = AttackDetector()
		r = obj.splitFields("200.4.91.190 - - [25/May/2015:23:11:15 +0000] \"GET / HTTP/1.0\" 200 3557 \"-\" \"Mozilla/4.0 (compatible; MSIE 6.0; Windows NT 5.1; SV1)")
		self.assertIsInstance(r,Record)
if __name__ == '__main__':
	unittest.main()
