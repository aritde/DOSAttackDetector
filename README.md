# DOSAttackDetector
This project detects the suspicious IP's in a DOS Attack within 2 minutes after the attack.

**Packages Required**

unittest

_Installation :_

pip install unittest

**EXECUTION**

Download the supplied input file in the path /DOSAttackDetector

Go to /src

python3 AttackDetector.py [input-file-path] [output-file-directory] [threshold]

Example :
python3 AttackDetector.py /u/username/DOSAttackDetector/src/apache-access-log.txt /DOSAttackDetector/suspicious.txt 87

Expected Output :
Count of suspicious IPs : 567 (on console)
Set of suspicious IPs in the suspicious.txt file in /DOSAttackDetector

Note: For meaningful results based on the data, a range of good threshold is : 85 - 89

**EXECUTION FOR TESTS**

Go to /tests 

Generate sample test data(testData.txt), if not already present by running _python3 sampleDataGenerator.py_ 

python3 AttackDetectorTests.py -b

