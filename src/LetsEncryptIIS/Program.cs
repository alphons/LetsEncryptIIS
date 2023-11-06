
using System.Security.Principal;

using LetsEncryptIIS2Core;

// For staging: install acme-staging/letsencrypt-stg-root-x1.der into LocalMachine trusted root certificates
// ( Lokale computer / Vertrouwde basiscertificieringsinstanties / Certificaten )
// The .pem file is used at runtime, does not need to be installed

#pragma warning disable CA1416
if (new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
	await CertHelper.LetsEncryptDomainsAsync(false);
else
	Console.WriteLine("must be run as administator");
#pragma warning restore CA1416

Console.WriteLine("ready");

