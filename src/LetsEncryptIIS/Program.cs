
using System.Security.Principal;

using LetsEncryptIIS;

/*
For staging: install acme-staging/letsencrypt-stg-root-x1.der into LocalMachine trusted root certificates
( Lokale computer / Vertrouwde basiscertificieringsinstanties / Certificaten )
The .pem file is used at runtime, does not need to be installed

Make sure, there a website is listening on http://localhost having dir on LocalhostDir (settings)
 
Op hoofdnivo van de loadbalancer, 1 rewrite rule, 'Matches pattern' (wildcard)
Pattern: .well-known/acme-challenge/*
Action rewrite: http://localhost/letsencrypt/{R:1}

Dan ALLE challenges die binnenkomen plaatsen onder D:\inetpub\wwwroot\letsencrypt
En niet meer op elke server afzonderlijk.
 
 */


var staging = (args.Length > 0 && args[0] == "staging");

#pragma warning disable CA1416
if (new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
	await CertHelper.LetsEncryptDomainsAsync(staging);
else
	Console.WriteLine("run as administator");
#pragma warning restore CA1416

Console.WriteLine("ready");

