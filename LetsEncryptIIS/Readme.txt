Loadbalancer
 - LetsEncryptIIS.exe runs once a week at the loadbalancer having a servers.xml configuration file
 - loadbalancer IIS must have multiple https bindings, for each binding there will be an unique https certfificate
 - ssl offloading, requests are forwarded by the ARR (Application Request Routing)
Webserver(s)
- must have multiple http bindings, no ssl certs needed no https needed (binding names must match those of loadbalancer)

For example:

ServerA (loadbalancer)
 - https://www.example.com/
 - https://www1.example.com/
 - https://www.otherexample.com/
 - https://www.notherexample.com/
 
ServerB
 - http://www.example.com/
 - http://www1.example.com/
 - http://www.otherexample.com/
 
ServerC
 - http://www.notherexample.com/

servers.xml configuration file (location loadbalancer, same dir as LetsEncryptIIS.exe

<?xml version="1.0" encoding="utf-8" ?>
<servers>
	<server name="ServerA">
		www.example.com
		www1.example.com
		www.otherexample.com
	</server>
	<server name="ServerB">
		www.notherexample.com
	</server>
</servers>