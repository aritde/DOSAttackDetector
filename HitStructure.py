#print("Hello World")

class HitStructure:
	#Constructor
	def __init__(self,timeStamp,count):
		self.timeStamp = timeStamp
		self.count=count 
	#Accessor Methods
	def gettimeStamp(self):
		return self.timeStamp
	def getCount(self):
		return self.count
	#Setter Methods
	def settimeStamp(self,timeStamp)
		self.timeStamp = timeStamp
	def setCount(self,count)
		self.count=count

