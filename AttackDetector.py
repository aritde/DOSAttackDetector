from Record import Record
from HitStructure import HitStructure
from datetime import datetime
import time
import os
class AttackDetector(object):
	#def __init__(self):
	#Function to calculate the time difference
	def calculateTimeDifference(self,lastHitTime,currentTime):
		desiredFormatForDifference = '%H:%M:%S'
		difference = datetime.strptime(currentTime,desiredFormatForDifference) - datetime.strptime(lastHitTime, desiredFormatForDifference)
		difference = difference.seconds*1000
		return difference

	#Loads the inputfile onto a list and passes onto the fraudDetection function
	def loadInput(self):
		dataFile=open("/u/aritde/dosDetector/apache-access-log.txt",'r')
		recordList = []
		for line in dataFile:
			#sends each line of the file to the split function in order to populate the Record data structure from the required fields of the record in the actual file
			record = self.splitFields(line)
			recordList.append(record)
		#sends the data onto the main function for detecting the suspicious IP's
		self.fraudDetection(recordList)
	
	#Main function responsible for detecting the suspicious IPs	
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

	def writeOutput(self,suspiciousIPs):
		outputFile=os.path.expanduser('~') + '/dosDetector/suspicious.txt'
		try:
    			os.remove(outputFile)
		except OSError:
    			pass
		fileHandler = open(outputFile,'a')
		#outputFile=open("suspicious.txt","w+")
		for ip in suspiciousIPs:
			fileHandler.write(ip+"\n")
		fileHandler.close()
		
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
