## Embedded Systems Project (Seng 440)
### RSA Cryptography

* Build using VisualGDB remotely on ugls.ece.uvic.ca
	* Ensure output dir is in home user folder for ease of access to build result
	* `$> arm-linux-gcc -o rsa.exe rsa.c

* From seng440.ece.uvic.ca:
	* Execute tx.lftp using `lftp -f tx.lftp` to upload the executable to the ARM machine
	* Execute rm.lftm in the same fashion to clean the executable from the ARM machine
	* Use telnet to get a shell to run the result `telnet arm` (a ~/.netrc file can help automate login)
	* `./zevisert/rsa.exe` to run - may need to `chmod a+wrx ./zevisert/rsa.exe` beforehand


