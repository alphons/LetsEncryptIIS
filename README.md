# LetsEncryptIIS
LetsEncrypt for IIS servers


This .NET core console application get wildcard certificates from LetsEncrypt for a list of domains.
After validating using a DNS challenge the certificates are downloaded and installed on the local Machine certificate store.
The project uses the [Certes](https://github.com/fszlin/certes) library.
As an example the DNS validation using the [Vimexx_API](https://github.com/alphons/Vimexx_API) is used. 
It checks the local IIS for websites and refreshes the https certificate bindings when necessary.

Starting application as Administrator (for storing certificates in certificate store).

```
LetsEncryptIIS
```

For testing the application can be started in staging mode.

```
LetsEncryptIIS staging
```

There is one configuration file **settings.json** which can contain multiple domain names.

The **PFXPassword** is used for storing the .pfx files.

For connecting to letsencrypt an email adres **Contact** has to be specified.

If there are errors validating domain challenges the log is send by email.
Therefore ** SmtpHost, SmtpPort, SmtpUser, SmtpPassword, SmtpEnableSsl, SmptSubject** must be specified.

LetsEncrypt does a lot of nagging when certificates are about to expire.
Refreshing certicates when time is running out **CertDaysBeforeExpire** prevents this.

For checking and refreshing IIS https bindings, the location of **LocalConfig** must be set.

As an example, the DNS provider **Vimexx** is used.
These credentials **VimexxClientId,VimexxClientKey,VimexxUsername,VimexxPassword** must be set.

The **CSR** information is optional, but it does not hurt to specify your own.

The list **DnsChallenges** contain all domains which will be checked. 
The certifcates are ALL wildcard certificates and will have CN=domain.tld and SAN **domain.tld, *.domain.tld**

Also **HttpChallenges** can be used to make http challenges possible. This solution works only when having an IIS Application Request Routing (ARR) in place. All http challenges are handled on the ARR server itself. Therefore you have to install an additional rule to the ARR ruleset.
This routes **all the Letsencrypt http challenge requests** to a localhost on the ARR server. Make sure there is some safety-net website localhost running. The **LocalhostDir** of the localhost website must be set in the settings file.

![letenscrypt arr rule](https://github.com/alphons/LetsEncryptIIS/blob/master/Example.png?raw=true)


## Example settings.json file

```json
{
	"CertificateStoreName": "WebHosting",
	"AcmeStaging": "acme-staging",
	"AcmeProduction": "acme-production",
	"PFXPassword": "Pas5w0rd!321",
	"Contact": "info@example.com",
	"LogDirectory": "Log",
	"SmtpHost": "smtp.example.com",
	"SmtpPort": 25,
	"SmtpUser": "some-user-id",
	"SmtpPassword": "some-email-password",
	"SmtpEnableSsl": false,
	"SmptSubject": "Rapport SSL cert update core",
	"CertDaysBeforeExpire": 30,
	"LocalConfig": "c:\\windows\\system32\\inetsrv\\config\\applicationHost.config",
	"LocalhostDir": "D:\\inetpub\\wwwroot",
	"VimexxClientId": "1234",
	"VimexxClientKey": "57575473y63yrhrh4jdjd78412345677abcd",
	"VimexxUsername": "vimexxuser321@example.com",
	"VimexxPassword": "Pas5w0rd!321V1mM3xxUser",
	"CSR": "C=NL, ST=Flevoland, L=Lelystad, O=Some Organisation, OU=ICT",
	"DnsChallenges": [
		"example.com",
		"notherexample.org"
	],
	"HttpChallenges": [
		"www.exname1.com",
		"www.othername.com"
	]
}
```

Happy certing on IIS.
