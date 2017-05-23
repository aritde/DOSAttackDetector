import os
import datetime
class SampleDataGenerator(object):
	def loadInput(self,filename):
		dataFile=open(filename,'r')
		recordList = []
		modrecordList =[]
		setOfSuspiciousIPs=set()
		count=0
		validIPmadeInvalid = 0
		for line in dataFile:
			fields = line.split(" ")
			if fields[0] in {"240.163.130.99" , "211.188.214.36" , "118.133.241.175" , "73.173.0.163" , "238.164.11.148"}:
				recordList.append(line)
			elif fields[0] in {"142.94.222.141","150.31.9.239","241.164.143.243"}:
				if validIPmadeInvalid<60:
					recordList.append(line)
					validIPmadeInvalid = validIPmadeInvalid+1
				else:
					timestamp=fields[3].split(":",1)[1].split(" ", 1)[0]
					desiredFormatForDifference = '%H:%M:%S'
					addValue = datetime.datetime.strptime(timestamp,desiredFormatForDifference) +datetime.timedelta(0,240)
					fields[3]=fields[3].replace(timestamp,str(addValue.hour)+":"+str(addValue.minute)+":"+str(addValue.second))
					modifiedRecord = ' '.join(field for field in fields)
					modrecordList.append(modifiedRecord)
			elif count<100:
				recordList.append(line)
				count= count+1
		recordList.extend(modrecordList)
		print(str(len(recordList)))		
		self.writeOutput(recordList)
		#iself.writeOutput(modrecordList)
		dataFile.close()
	def writeOutput(self,recordList):
                outputFile=os.path.expanduser('~') + '/dosDetector/testData.txt'
                try:
                        os.remove(outputFile)#If the file already exists, remove it
                except OSError:
                        pass
                fileHandler = open(outputFile,'a')
                #Write the unique list of suspicious IP's onto a different file
                for record in recordList:
                        fileHandler.write(record)
                fileHandler.close()



def main():
        #Creates an instance of the above class
        sampleDataGenerator= SampleDataGenerator()
        filename = "/u/aritde/dosDetector/apache-access-log.txt"
        result = sampleDataGenerator.loadInput(filename)

if __name__== "__main__":
        main()

