using Certes;
using Certes.Pkcs;
using Certes.Acme;
using Certes.Acme.Resource;

using Microsoft.Web.Administration;

using Vimexx_API;

using System.Net;
using System.Net.Mail;
using System.Text;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;

namespace LetsEncryptIIS;

public class CertHelper
{
	async private static Task AddCertToStoreAsync(StringBuilder log, string PathToPfx)
	{
		var sw = Stopwatch.StartNew();
		try
		{
			using var store = new X509Store(Settings.Get("CertificateStoreName"), StoreLocation.LocalMachine);

			store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite);

			var data = await File.ReadAllBytesAsync(PathToPfx);

			var certificate = new X509Certificate2(data,
				Settings.Get("PFXPassword"),
				X509KeyStorageFlags.MachineKeySet |
				X509KeyStorageFlags.PersistKeySet |
				X509KeyStorageFlags.Exportable);

			store.Add(certificate);
			store.Close();
		}
		catch(Exception e)
		{
			log.AppendLine($"\t\t\tError: AddCertToStoreAsync {e.Message}");
		}
		log.AppendLine($"\t\t\tAdd {PathToPfx} to cert store {sw.ElapsedMilliseconds}ms");
	}

	async private static Task<VimexxApi> GetVimexxApiAsync(StringBuilder log)
	{
		var sw = Stopwatch.StartNew();

		var vimexxApi = new VimexxApi();
		await vimexxApi.LoginAsync(
			Settings.Get("VimexxClientId"),
			Settings.Get("VimexxClientKey"),
			Settings.Get("VimexxUsername"),
			Settings.Get("VimexxPassword"));
		log.AppendLine($"\tGetApiAsync took {sw.ElapsedMilliseconds}ms");
		return vimexxApi;
	}

	async private static Task ClearAuthorizations(StringBuilder log, IOrderContext orderContext, VimexxApi vimexxApi)
	{
		var sw = Stopwatch.StartNew();
		var authorizations = await orderContext.Authorizations();
		foreach (var authz in authorizations)
		{
			var res = await authz.Resource();
			_ = await vimexxApi.LetsEncryptAsync(res.Identifier.Value, new List<string>());
			_ = await authz.Deactivate();
		}
		log.AppendLine($"\t\t\tClearAuthorizations took {sw.ElapsedMilliseconds}ms");
	}

	async private static Task<IOrderContext?> AuthzDns(StringBuilder log, AcmeContext acmeContext, VimexxApi vimexxApi, string[] hosts)
	{
		var sw = Stopwatch.StartNew();

		var orderContext = await acmeContext.NewOrder(hosts);

		var order = await orderContext.Resource();

		var authorizations = await orderContext.Authorizations();

		var dict = new Dictionary<string, List<string>>();

		foreach (var authz in authorizations)
		{
			var res = await authz.Resource();

			var dnsChallenge = await authz.Dns();

			var dnsTxt = acmeContext.AccountKey.DnsTxt(dnsChallenge.Token);

			var domain = res.Identifier.Value;

			if (!dict.ContainsKey(domain))
				dict.Add(domain, new List<string>());

			dict[domain].Add(dnsTxt);
		}

		log.AppendLine($"\t\t\t\tGet Dns challenges took {sw.ElapsedMilliseconds}ms");

		sw.Restart();

		// put DNS challenge(s) records per domain
		foreach(var domain in dict.Keys)
		{
			var challenges = dict[domain];

			var result = await vimexxApi.LetsEncryptAsync(domain, challenges);
		}

		log.AppendLine($"\t\t\t\tPutting Dns challenges took {sw.ElapsedMilliseconds}ms");

		await Task.Delay(1000);

		sw.Restart();

		foreach (var authz in authorizations)
		{
			var res = await authz.Resource();
			if (res.Status == AuthorizationStatus.Pending)
			{
				var dnsChallenge = await authz.Dns();
				await dnsChallenge.Validate();
			}
		}

		log.AppendLine($"\t\t\t\tStarting Validate took {sw.ElapsedMilliseconds}ms");

		sw.Restart();

		for (int i = 1; i <= 60; i++)
		{
			await Task.Delay(1000);

			var statuses = new List<AuthorizationStatus>();
			foreach (var authz in authorizations)
			{
				var a = await authz.Resource();
				if (AuthorizationStatus.Invalid == a?.Status)
				{
					log.AppendLine($"\t\t\t\tAuthorizationStatus.Invalid status in {sw.ElapsedMilliseconds}ms (bailing out)");

					return null;
				}
				else
				{
					statuses.Add(a?.Status ?? AuthorizationStatus.Pending);
				}
			}

			if (statuses.All(s => s == AuthorizationStatus.Valid))
			{
				log.AppendLine($"\t\t\t\tDNS validation OK took {sw.ElapsedMilliseconds}ms");

				return orderContext;
			}
		}

		log.AppendLine($"\t\t\t\tDNS validation TIMEOUT in {sw.ElapsedMilliseconds}ms (bailing out)");

		return null;
	}

	async private static Task<IOrderContext?> ValidateOrderAsync(StringBuilder log, AcmeContext acmeContext, VimexxApi vimexxApi, string[] hosts)
	{
		var sw = Stopwatch.StartNew();

		var orderContext = await AuthzDns(log, acmeContext, vimexxApi, hosts);

		if(orderContext == null)
			log.AppendLine($"\t\t\tAuthzDns ERROR");
		else
			log.AppendLine($"\t\t\tAuthzDns took {sw.ElapsedMilliseconds}ms");

		return orderContext;
	}

	async private static Task MailRapportAsync(string body)
	{
		try
		{
			using var msg = new MailMessage();
			var contact = Settings.Get("Contact");
			msg.From = new MailAddress(contact);
			msg.To.Add(new MailAddress(contact));
			msg.Body = "<pre>" + body + "</pre>";
			msg.Subject = Settings.Get("SmptSubject");
			if (msg.Body.IndexOf("error") > 0 || Debugger.IsAttached)
				msg.Subject += " (errors)";
			msg.IsBodyHtml = true;

			using var smtpclient = new SmtpClient(Settings.Get("SmtpHost"), Settings.Get<int>("SmtpPort"));
			smtpclient.DeliveryMethod = SmtpDeliveryMethod.Network;
			smtpclient.EnableSsl = Settings.Get<bool>("SmtpEnableSsl");
			if (!string.IsNullOrWhiteSpace(Settings.Get("SmtpUser")) ||
				!string.IsNullOrWhiteSpace(Settings.Get("SmtpPassword")))
			{
				smtpclient.Credentials = new NetworkCredential()
				{
					UserName = Settings.Get("SmtpUser"),
					Password = Settings.Get("SmtpPassword"),
				};
			}
			await smtpclient.SendMailAsync(msg);
		}
		catch
		{
		}
	}
	async private static Task<AcmeContext> CreateAcmeContextAsync(StringBuilder log, bool UseStaging)
	{
		var sw = Stopwatch.StartNew();

		var directoryUri = UseStaging ?
			WellKnownServers.LetsEncryptStagingV2 :
			WellKnownServers.LetsEncryptV2;

		var dir = UseStaging ?
			Settings.Get("AcmeStaging") :
			Settings.Get("AcmeProduction");

		var workingdir = Path.Combine(AppContext.BaseDirectory, dir);

		if (!System.IO.Directory.Exists(workingdir))
			System.IO.Directory.CreateDirectory(workingdir);

		System.IO.Directory.SetCurrentDirectory(workingdir); // <-- pfx files are saved to this location

		var contact = Settings.Get("Contact");

		var AccountKeyFile = contact + ".pem";

		AcmeContext acmeContext;

		if (File.Exists(AccountKeyFile))
		{
			var pemKey = await File.ReadAllTextAsync(AccountKeyFile);
			var accountKey = KeyFactory.FromPem(pemKey);
			acmeContext = new AcmeContext(directoryUri, accountKey);
		}
		else
		{
			acmeContext = new AcmeContext(directoryUri);
			_ = await acmeContext.NewAccount(contact, true);
			var pemKey = acmeContext.AccountKey.ToPem();
			await File.WriteAllTextAsync(AccountKeyFile, pemKey);
		}

		log.AppendLine($"\tCreating AcmeContext took {sw.ElapsedMilliseconds}ms");

		return acmeContext;
	}

	async private static Task<CertificateChain?> GetCertificateChainAsync(StringBuilder log, IKey privateKey, IOrderContext orderContext, string[] hosts, string domain)
	{
		var sw = Stopwatch.StartNew();

		var csr = new CertificationRequestBuilder(privateKey);

		csr.AddName(Settings.Get("CSR") + $", CN={domain}");

		foreach (var h in hosts)
		{
			csr.SubjectAlternativeNames.Add(h);
		}

		var der = csr.Generate();

		_ = await orderContext.Finalize(der);

		CertificateChain? certificate = null;

		log.AppendLine($"\t\t\tFinalizing order took {sw.ElapsedMilliseconds}ms");

		sw.Restart();

		for (int i = 0; i < 600; i++)
		{
			await Task.Delay(100);
			try
			{
				certificate = await orderContext.Download(null);
				break;
			}
			catch
			{

			}
		}
		if(certificate != null)
			log.AppendLine($"\t\t\tDownloading certificate took {sw.ElapsedMilliseconds}ms");
		else
			log.AppendLine($"\t\t\tDownloading certificate error timeout {sw.ElapsedMilliseconds}ms");

		return certificate;
	}

	async private static Task SaveCertificateAsync(StringBuilder log, IKey privateKey, CertificateChain certificate, string domain, bool UseStaging)
	{
		var sw = Stopwatch.StartNew();

		var pfxBuilder = certificate.ToPfx(privateKey);

		if (UseStaging)
		{
			var statgingIssuerPem = await File.ReadAllBytesAsync("letsencrypt-stg-root-x1.pem");
			pfxBuilder.AddIssuer(statgingIssuerPem);
		}

		var pfxData = pfxBuilder.Build($"{domain} - {DateTime.Now}", Settings.Get("PFXPassword"));

		await File.WriteAllBytesAsync($"{domain}.pfx", pfxData);

		log.AppendLine($"\t\t\tCreating {domain}.pfx took {sw.ElapsedMilliseconds}ms");
	}

	async private static Task LetsEncryptDomainAsync(StringBuilder log, AcmeContext acmeContext, VimexxApi vimexxApi, string domain, bool UseStaging)
	{
		var sw = Stopwatch.StartNew();

		var hosts = new[] { domain, $"*.{domain}" };

		var orderContext = await ValidateOrderAsync(log, acmeContext, vimexxApi, hosts);

		if (orderContext == null)
			return;

		var privateKey = KeyFactory.NewKey(KeyAlgorithm.ES256);

		var certificate = await GetCertificateChainAsync(log, privateKey, orderContext, hosts, domain);

		await ClearAuthorizations(log, orderContext, vimexxApi);

		if (certificate != null)
		{
			await SaveCertificateAsync(log, privateKey, certificate, domain, UseStaging);

			await AddCertToStoreAsync(log, $"{domain}.pfx");
		}

		log.AppendLine($"\t\tLetsEncryptDomainAsync {domain} took {sw.ElapsedMilliseconds}ms");
	}

	/// <summary>
	/// Remove al certificates from store which are not valid anymore (less than "CertDaysBeforeExpire"))
	/// </summary>
	/// <param name="domain"></param>
	/// <returns></returns>
	private static bool CheckCertValid(string domain)
	{
		using var store = new X509Store(Settings.Get("CertificateStoreName"), StoreLocation.LocalMachine);

		store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite);

		//var col = store.Certificates.Find(X509FindType.FindByIssuerDistinguishedName, "CN=R3, O=Let's Encrypt, C=US", false);

		var certificates = store.Certificates.Find(X509FindType.FindBySubjectDistinguishedName, $"CN={domain}", true);

		var valid = false;
		foreach (var certificate in certificates)
		{
			var ExpirationDate = DateTime.Parse(certificate.GetExpirationDateString());
			var daysValid = ExpirationDate.Subtract(DateTime.Now).TotalDays;
			if (daysValid > Settings.Get<double>("CertDaysBeforeExpire"))
				valid = true;
			else
				store.Remove(certificate);
		}
		store.Close();
		return valid;
	}


	private static byte[] GetCertHashDomain(string domain)
	{
		var certhash = Array.Empty<byte>();

		using var store = new X509Store(Settings.Get("CertificateStoreName"), StoreLocation.LocalMachine);

		store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);

		// For staging: install acme-staging/letsencrypt-stg-root-x1.der into LocalMachine trusted root certificates

		var col = store.Certificates.Find(X509FindType.FindBySubjectDistinguishedName, $"CN={domain}", false);

		if (col.Count == 1)
			certhash = (byte[])col[0].GetCertHash().Clone();

		store.Close();

		return certhash;
	}

	/// <summary>
	/// RefreshBindingsAsync only works when reversed indexed deleting binding 
	/// and adding them again at the end of the collection.
	/// There is NO other way. This is the buggy part of ServerManager.
	/// </summary>
	/// <param name="log"></param>
	/// <returns></returns>
	async private static Task RefreshBindingsAsync(StringBuilder log)
	{
		var sw = Stopwatch.StartNew();

		var iisManager = new ServerManager(Settings.Get("LocalConfig"));

		foreach (var site in iisManager.Sites)
		{
			for(int i= site.Bindings.Count-1; i>=0;i--)
			{
				var binding = site.Bindings[i];

				if (binding.Protocol != "https")
					continue;

				var domain = binding.Host;

				if (string.IsNullOrWhiteSpace(domain))
					continue;

				var ii = domain.IndexOf('.');
				if (ii < 0)
					continue;

				while (domain.Split('.').Length > 2)
				{
					ii = domain.IndexOf('.');
					domain = domain[(ii + 1)..];
				}

				var CertificateHash = GetCertHashDomain(domain);

				if (CertificateHash.Length == 0)
					continue;

				if (binding.CertificateHash != null && binding.CertificateHash.SequenceEqual(CertificateHash))
					continue;

				log.AppendLine($"\t\tRefresh certificate for binding {binding.Host} with new cert {domain}");

				// remove old binding
				site.Bindings.Remove(binding);

				// add the new binding at the back of the collection
				site.Bindings.Add(binding.BindingInformation, CertificateHash, Settings.Get("CertificateStoreName"), SslFlags.Sni);
			}
		}

		// CommitChanges should be ready in 1 try...
		for (int intI = 0; intI < 60; intI++)
		{
			try
			{
				iisManager.CommitChanges();
				break;
			}
			catch(Exception eee)
			{
				log.AppendLine($"\t\tiisManager CommitChanges error {eee.Message} On Try: {intI}");
				await Task.Delay(1000);
			}
		}

		log.AppendLine($"\tRefreshBindingsAsync took {sw.ElapsedMilliseconds}mS");
	}

	async private static Task SaveLogAsync(string log)
	{
		try
		{
			var path = Path.Combine(AppContext.BaseDirectory, "Log", DateTime.Now.ToString("yyyyMMdd") + ".txt");
			var dir = Path.GetDirectoryName(path) ?? @"c:\temp";
			if (!System.IO.Directory.Exists(dir))
				System.IO.Directory.CreateDirectory(dir);
			await File.AppendAllTextAsync(path, log.ToString());
		}
		catch
		{
		}
	}

	async public static Task LetsEncryptDomainsAsync(bool UseStaging = false)
	{
		var sw = Stopwatch.StartNew();

		var log = new StringBuilder();

		try
		{
			log.AppendLine($"LetsEncryptDomains started {DateTime.Now}");

			var domains = Settings.Get<List<string>>("Domains") ?? 
				throw new Exception("Domains is null in settings.json");

			log.AppendLine($"\tChecking: {domains.Count} domains");

			for (int i = domains.Count - 1; i >= 0; i--)
			{
				var domain = domains[i];
				if (string.IsNullOrWhiteSpace(domain))
					continue;
				if (CheckCertValid(domain))
				{
					log.AppendLine($"\t\tCert for {domain} is valid");
					domains.Remove(domain);
					continue;
				}
				log.AppendLine($"\t\tRenewing cert for {domain}");
			}

			if(domains.Count>0)
			{
				var acmeContext = await CreateAcmeContextAsync(log, UseStaging);

				var vimexxApi = await GetVimexxApiAsync(log);

				foreach (var domain in domains)
				{
					await LetsEncryptDomainAsync(log, acmeContext, vimexxApi, domain, UseStaging);
				}
				await RefreshBindingsAsync(log);
			}

			log.AppendLine($"LetsEncryptDomains ended (normal) took {sw.Elapsed}");
		}
		catch(Exception eee)
		{
			log.AppendLine($"***** {eee.Message} ***** ");
			await MailRapportAsync(log.ToString());
		}

		await SaveLogAsync(log.ToString());
	}
}
