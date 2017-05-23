# DOSAttackDetector
This project detects the suspicious IP's in the DOS Attack within 2 minutes after the attack.

**EXECUTION**

python3 AttackDetector.py [input-file-path] [output-file-directory] [threshold]

Example :
python3 AttackDetector.py /u/username/dosDetector/src/apache-access-log.txt /dosDetector/suspicious.txt 87

Expected Output :
Count of suspicious IPs : 567

Note: For meaningful results based on the data, a range of good threshold is : 85 - 89

**EXECUTION FOR TESTS**

Go to the /test 

Generate sample test data, if not already present by running _python3 sampleDataGenerator.py <input-file-path> <output-file-directory>_

python3 AttackDetectorTests.py

