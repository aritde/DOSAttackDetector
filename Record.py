class Record(object):
	def __init__(self,ipAddress,timeStamp):
		self.ipAddress = ipAddress
		self.timeStamp =timeStamp
	def getIpAddress(self):
		return self.ipAddress
	def gettimeStamp(self):
		return self.timeStamp
	def setIpAddress(self,ipAddress):
		self.ipAddress = ipAddress
	def settimStamp(self,timeStamp):
		self.timeStamp = timeStamp
