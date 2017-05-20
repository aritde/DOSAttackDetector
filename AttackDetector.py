from Record import Record
from HitStructure import HitStructure
from datetime import datetime
import time
class AttackDetector(object):
	#def __init__(self):
	def calculateTimeDifference(self,lastHitTime,currentTime):
		desiredFormatForDifference = '%H:%M:%S'
		difference = datetime.strptime(currentTime,desiredFormatForDifference) - datetime.strptime(lastHitTime, desiredFormatForDifference)
		difference = difference.seconds*1000
		return difference

	def loadInput(self):
		dataFile=open("/u/aritde/dosDetector/apache-access-log.txt",'r')
		recordList = []
		for line in dataFile:
			record = self.splitFields(line)
			recordList.append(record)
		self.fraudDetection(recordList)
		
	def fraudDetection(self,recordList):
		#print("Record is : "+ r.getIpAddress() +"Time:"+ r.gettimeStamp())
		mapOfRecords = {}
		suspiciousIPs = set()
		for record in recordList:
			ipAddress = record.getIpAddress()
			print("Currently processing :"+ ipAddress)
			currentTime=record.gettimeStamp()
			if ipAddress in mapOfRecords:
				lastHitTime = mapOfRecords[ipAddress].gettimeStamp()
				difference = self.calculateTimeDifference(lastHitTime,currentTime)
				#print("Difference :"+ str(difference))
				diffSeconds = int(difference/1000%60)
				diffMinutes = int(difference/(60*1000)%60)
				diffHours = int(difference/(60*60*1000))
				#print(str(diffSeconds) +" "+str(diffMinutes)+" "+str(diffHours))
				if diffHours == 0 and diffMinutes<1:	
					updateCount = mapOfRecords[ipAddress].getCount();
					h=HitStructure(lastHitTime,updateCount+1)
					mapOfRecords[ipAddress]=h
					if updateCount+1>=89:
						if ipAddress not in suspiciousIPs:
							suspiciousIPs.add(ipAddress)
			else:
				h = HitStructure(currentTime,1)
				mapOfRecords[ipAddress]=h
		print("Suspicious IPs : "+str(len(suspiciousIPs)))
		self.writeOutput(suspiciousIPs)
		
	
	
	def splitFields(self,line):
		fields = line.split(" ")
		timestamp=fields[3].split(":",1)[1].split(" ", 1)[0]
		r = Record(fields[0],timestamp);
		return r
def main():
	attackDetector = AttackDetector()
	attackDetector.loadInput()

if __name__== "__main__":
	main()
