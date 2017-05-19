from Record import Record
class AttackDetector(object):
	#def __init__(self):
	
	def loadInput(self):
		dataFile=open("/u/aritde/dosDetector/apache-access-log.txt",'r')
		count=0
		for line in dataFile:
			count=count+1
			r = self.splitFields(line)
			#print("Record is : "+ r.getIpAddress() +"Time:"+ r.gettimeStamp())
			ipAddress = r.getIpAddress()
			print("Currently processing :"+ ipAddress)
			currentTime=r.gettimeStamp()
			if ipAddress in mapOfRecords:
				lastHitTime = mapOfRecords[ipAdress].gettimeStamp()
				desiredFormatForDifference = '%H:%M:%S'
				difference = datetime.strptime(currentTime,desiredFormatForDifference) - datetime.strptime(lastHitTime, desiredFormatForDifference)
				difference = difference.seconds*1000
				
				
				

	
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
