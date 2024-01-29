
using System.Security.Principal;

using LetsEncryptIIS;

//var log = new StringBuilder();
//log.AppendLine("alphons");
//await CertHelper.MailRapportAsync(log);
//return;

// For staging: install acme-staging/letsencrypt-stg-root-x1.der into LocalMachine trusted root certificates
// ( Lokale computer / Vertrouwde basiscertificieringsinstanties / Certificaten )
// The .pem file is used at runtime, does not need to be installed

var staging = (args.Length > 0 && args[0] == "staging");

#pragma warning disable CA1416
if (new WindowsPrincipal(WindowsIdentity.GetCurrent()).IsInRole(WindowsBuiltInRole.Administrator))
	await CertHelper.LetsEncryptDomainsAsync(staging);
else
	Console.WriteLine("run as administator");
#pragma warning restore CA1416

Console.WriteLine("ready");

