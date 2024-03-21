using System.Text;
using System.Net.Mail;
using System.Diagnostics;
using System.Security.Cryptography.X509Certificates;

using Certes;
using Certes.Acme;
using Certes.Acme.Resource;
using Certes.Pkcs;

using Microsoft.Web.Administration;

using Vimexx_API;
using System.Globalization;
using Org.BouncyCastle.Asn1.X509;


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
		catch (Exception e)
		{
			log.AppendLine($"\t\t\tAddCertToStor ERROR {e.Message}");
		}
		log.AppendLine($"\t\t\tAdd {PathToPfx} to cert store {sw.ElapsedMilliseconds}ms");
	}

	async private static Task<VimexxApi> GetVimexxApiAsync(StringBuilder log)
	{
		var sw = Stopwatch.StartNew();

		var vimexxApi = new VimexxApi(log);
		await vimexxApi.LoginAsync(
			Settings.Get("VimexxClientId"),
			Settings.Get("VimexxClientKey"),
			Settings.Get("VimexxUsername"),
			Settings.Get("VimexxPassword"));
		log.AppendLine($"\tGetVimexxApi {sw.ElapsedMilliseconds}ms");
		return vimexxApi;
	}

	async private static Task ClearDnsChallenge(StringBuilder log, IOrderContext orderContext, VimexxApi vimexxApi)
	{
		var sw = Stopwatch.StartNew();
		var authorizations = await orderContext.Authorizations();
		foreach (var authz in authorizations)
		{
			var res = await authz.Resource();
			var totalresult = await vimexxApi.LetsEncryptAsync(res.Identifier.Value, new List<string>());
			if (totalresult == null && res != null && res.Identifier != null)
				log.AppendLine($"Error: ClearAuthorizations: vimexxApi.LetsEncryptAsync returns null on {res.Identifier.Value}");
		}
		log.AppendLine($"\t\t\tClearDnsChallenge {sw.ElapsedMilliseconds}ms");
	}

	private async static Task CreateDnsChallenge(StringBuilder log, AcmeContext acmeContext, VimexxApi vimexxApi, IEnumerable<IAuthorizationContext> authorizations)
	{
		var sw = Stopwatch.StartNew();

		var dict = new Dictionary<string, List<string>>();

		foreach (var authz in authorizations)
		{
			var res = await authz.Resource();

			var dnsChallenge = await authz.Dns();

			var dnsTxt = acmeContext.AccountKey.DnsTxt(dnsChallenge.Token);

			var domain = res.Identifier.Value;

			if (!dict.ContainsKey(domain))
				dict.Add(domain, []);

			dict[domain].Add(dnsTxt);
		}

		log.AppendLine($"\t\t\t\tCreateDnsChallenge (getting challenges) {sw.ElapsedMilliseconds}ms");

		sw.Restart();

		// put DNS challenge(s) records per domain
		foreach (var domain in dict.Keys)
		{
			var challenges = dict[domain];

			var result = await vimexxApi.LetsEncryptAsync(domain, challenges);

			if (result == null)
				log.AppendLine($"Error: vimexxApi.LetsEncryptAsync returns null on {domain}");
		}

		log.AppendLine($"\t\t\t\tCreateDnsChallenge (updating DNS entries) {sw.ElapsedMilliseconds}ms");

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

		log.AppendLine($"\t\t\t\tCreateDnsChallenge Start Validating {sw.ElapsedMilliseconds}ms");
	}

	private async static Task CreateHttpChallenge(StringBuilder log, string? LocalhostDir, IEnumerable<IAuthorizationContext> authorizations)
	{
		if (LocalhostDir == null)
		{
			log.AppendLine($"\t\t\t\tCreateHttpChallenge Error: Settings LocalhostDir == null");
			return;
		}

		var sw = Stopwatch.StartNew();

		foreach (var authz in authorizations)
		{
			var dnsChallenge = await authz.Http();

			var dir = Path.Combine(LocalhostDir, "letsencrypt");

			var challengePath = Path.Combine(dir, dnsChallenge.Token);
			var webconfigPath = Path.Combine(dir, "web.config");

			if (!System.IO.Directory.Exists(dir))
				System.IO.Directory.CreateDirectory(dir);

			await File.WriteAllTextAsync(challengePath, dnsChallenge.KeyAuthz);

			var text = await File.ReadAllTextAsync(@"..\web.config.xml");

			await File.WriteAllTextAsync(webconfigPath, text);

			var res = await authz.Resource();

			if (res.Status == AuthorizationStatus.Pending)
			{
				var challengeContext = await authz.Http();
				await challengeContext.Validate();
			}

		}

		log.AppendLine($"\t\t\t\tCreateHttpChallenge Start Validating {sw.ElapsedMilliseconds}ms");

	}

	private static void ClearHttpChallenge(StringBuilder log, IOrderContext orderContext, string? LocalhostDir)
	{
		if (LocalhostDir == null)
		{
			log.AppendLine($"\t\t\tClearHttpChallenge LocalhostDir is null");
			return;
		}
		var sw = Stopwatch.StartNew();

		var dir = Path.Combine(LocalhostDir, "letsencrypt");

		System.IO.Directory.Delete(dir, true);

		log.AppendLine($"\t\t\tClearHttpChallenge {sw.ElapsedMilliseconds}ms");
	}

	async private static Task<IOrderContext?> CreateChallenge(StringBuilder log, AcmeContext acmeContext, VimexxApi? vimexxApi, string? LocalhostDir, string[] hosts)
	{
		var sw = Stopwatch.StartNew();

		var orderContext = await acmeContext.NewOrder(hosts);

		var order = await orderContext.Resource();

		var authorizations = await orderContext.Authorizations();

		var dict = new Dictionary<string, List<string>>();

		if (vimexxApi != null)
			await CreateDnsChallenge(log, acmeContext, vimexxApi, authorizations);
		else
			await CreateHttpChallenge(log, LocalhostDir, authorizations);

		log.AppendLine($"\t\t\t\tCreateChallenge Start Validating {sw.ElapsedMilliseconds}ms");

		sw.Restart();

		for (int i = 1; i <= 60; i++)
		{
			await Task.Delay(1000);

			var statuses = new List<AuthorizationStatus>();
			foreach (var authz in authorizations)
			{
				var res = await authz.Resource();
				if (AuthorizationStatus.Invalid == res?.Status)
				{
					log.AppendLine($"\t\t\t\tCreateChallenge ERROR AuthorizationStatus.Invalid status in {sw.ElapsedMilliseconds}ms (bailing out)");

					return null;
				}
				else
				{
					statuses.Add(res?.Status ?? AuthorizationStatus.Pending);
				}
			}

			if (statuses.All(s => s == AuthorizationStatus.Valid))
			{
				log.AppendLine($"\t\t\t\tCreateChallenge all Valid {sw.ElapsedMilliseconds}ms");

				if (vimexxApi != null)
					await ClearDnsChallenge(log, orderContext, vimexxApi);
				else
					ClearHttpChallenge(log, orderContext, LocalhostDir);

				return orderContext;
			}
		}

		log.AppendLine($"\t\t\t\tCreateChallenge ERROR timeout in {sw.ElapsedMilliseconds}ms (bailing out)");

		if (vimexxApi != null)
			await ClearDnsChallenge(log, orderContext, vimexxApi);
		else
			ClearHttpChallenge(log, orderContext, LocalhostDir);

		return null;
	}


	async private static Task<IOrderContext?> ValidateOrderAsync(StringBuilder log, AcmeContext acmeContext, VimexxApi? vimexxApi, string? LocalhostDir, string[] hosts)
	{
		var sw = Stopwatch.StartNew();

		var orderContext = await CreateChallenge(log, acmeContext, vimexxApi, LocalhostDir, hosts);

		if (orderContext == null)
			log.AppendLine($"\t\t\tValidateOrder ERROR (no orderContext) {sw.ElapsedMilliseconds}ms");
		else
			log.AppendLine($"\t\t\tValidateOrder OK {sw.ElapsedMilliseconds}ms");

		return orderContext;
	}

	async public static Task MailRapportAsync(StringBuilder log)
	{
		try
		{
			var body = log.ToString();

			if (!body.Contains("Error"))
			{
				log.AppendLine($"NOT MAILED (because there is no error)");
				return;
			}

			using var msg = new MailMessage();
			var contact = Settings.Get("Contact");
			msg.From = new MailAddress(contact);
			msg.To.Add(new MailAddress(contact));
			msg.Body = "<pre>" + body + "</pre>";
			msg.Subject = Settings.Get("SmptSubject");
			msg.IsBodyHtml = true;

			if (body.Contains("Error"))
				msg.Subject = "Error: " + msg.Subject;

			using var smtpclient = new SmtpClient(Settings.Get("SmtpHost"), Settings.Get<int>("SmtpPort"));
			smtpclient.DeliveryMethod = SmtpDeliveryMethod.Network;
			smtpclient.EnableSsl = Settings.Get<bool>("SmtpEnableSsl");
			if (!string.IsNullOrWhiteSpace(Settings.Get("SmtpUser")) ||
				!string.IsNullOrWhiteSpace(Settings.Get("SmtpPassword")))
			{
				smtpclient.Credentials = new System.Net.NetworkCredential()
				{
					UserName = Settings.Get("SmtpUser"),
					Password = Settings.Get("SmtpPassword"),
				};
			}
			await smtpclient.SendMailAsync(msg);
		}
		catch (Exception eee)
		{
			log.AppendLine($"Error: mail : {eee.Message}");
		}
	}
	async private static Task<AcmeContext> GetAcmeContextAsync(StringBuilder log, bool UseStaging)
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

		if (File.Exists(AccountKeyFile))
		{
			var pemKey = await File.ReadAllTextAsync(AccountKeyFile);
			var accountKey = KeyFactory.FromPem(pemKey);
			var acmeContext = new AcmeContext(directoryUri, accountKey);
			log.AppendLine($"\tGetAcmeContext (existing) {sw.ElapsedMilliseconds}ms");
			return acmeContext;
		}
		else
		{
			var acmeContext = new AcmeContext(directoryUri);
			_ = await acmeContext.NewAccount(contact, true);
			var pemKey = acmeContext.AccountKey.ToPem();
			await File.WriteAllTextAsync(AccountKeyFile, pemKey);
			log.AppendLine($"\tGetAcmeContext (new) {sw.ElapsedMilliseconds}ms");
			return acmeContext;
		}
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

		_ = await orderContext.Finalize(csr.Generate());

		log.AppendLine($"\t\t\tGetCertificateChain (finalizing order) {sw.ElapsedMilliseconds}ms");

		sw.Restart();

		CertificateChain? certificate = null;

		for (int i = 0; i < 60; i++)
		{
			try
			{
				await Task.Delay(1000);
				certificate = await orderContext.Download(null);
				break;
			}
			catch
			{
			}
		}
		if (certificate != null)
			log.AppendLine($"\t\t\tGetCertificateChain (downloaded certificate) {sw.ElapsedMilliseconds}ms");
		else
			log.AppendLine($"\t\t\tGetCertificateChain ERROR timeout {sw.ElapsedMilliseconds}ms");

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

		log.AppendLine($"\t\t\tSaveCertificate {domain}.pfx {sw.ElapsedMilliseconds}ms");
	}

	async private static Task ValidateDomainAsync(StringBuilder log, AcmeContext acmeContext, VimexxApi? vimexxApi, string? LocalhostDir, string domain, bool UseStaging)
	{
		var sw = Stopwatch.StartNew();

		string[] hosts = [];

		if (vimexxApi != null)
			hosts = [domain, $"*.{domain}"];

		if (LocalhostDir != null)
			hosts = [domain];

		log.AppendLine($"\t\tLetsEncryptDomain {domain} started");

		var orderContext = await ValidateOrderAsync(log, acmeContext, vimexxApi, LocalhostDir, hosts);

		if (orderContext != null)
		{
			var privateKey = KeyFactory.NewKey(KeyAlgorithm.ES256);

			var certificate = await GetCertificateChainAsync(log, privateKey, orderContext, hosts, domain);

			if (certificate != null)
			{
				await SaveCertificateAsync(log, privateKey, certificate, domain, UseStaging);

				await AddCertToStoreAsync(log, $"{domain}.pfx");
			}

			var authorizations = await orderContext.Authorizations();
			foreach (var authz in authorizations)
				_ = await authz.Deactivate();

		}

		log.AppendLine($"\t\tLetsEncryptDomain {domain} ended {sw.ElapsedMilliseconds}ms");
	}

	/// <summary>
	/// Remove al certificates from store which are not valid anymore (less than "CertDaysBeforeExpire"))
	/// </summary>
	/// <param name="domain"></param>
	/// <returns></returns>
	private static bool CheckDomainCert(string domain)
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


	private static byte[] GetDomainCertHash(string domain)
	{
		var certhash = Array.Empty<byte>();

		using var store = new X509Store(Settings.Get("CertificateStoreName"), StoreLocation.LocalMachine);

		store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);

		// For staging: install acme-staging/letsencrypt-stg-root-x1.der into LocalMachine trusted root certificates

		var col = store.Certificates.Find(X509FindType.FindBySubjectDistinguishedName, $"CN={domain}", false);

		if (col.Count>1) // oops. maybe there are valid and invalid certs also, in this case, take only the valid one
			col = store.Certificates.Find(X509FindType.FindBySubjectDistinguishedName, $"CN={domain}", true);

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
	async private static Task RefreshIISBindingsAsync(StringBuilder log)
	{
		var sw = Stopwatch.StartNew();

		var iisManager = new ServerManager(Settings.Get("LocalConfig"));

		foreach (var site in iisManager.Sites)
		{
			for (int i = site.Bindings.Count - 1; i >= 0; i--)
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

				var CertificateHash = GetDomainCertHash(domain);

				if (CertificateHash.Length == 0)
				{
					while (domain.Split('.').Length > 2)
					{
						ii = domain.IndexOf('.');
						domain = domain[(ii + 1)..];  // strip www. or other names
					}
					CertificateHash = GetDomainCertHash(domain);

					if (CertificateHash.Length == 0)
						continue;
				}

				if (binding.CertificateHash != null && binding.CertificateHash.SequenceEqual(CertificateHash))
					continue;

				log.AppendLine($"\t\tRefreshIISBindings {binding.Host} using new cert {domain}");

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
			catch (Exception eee)
			{
				log.AppendLine($"\t\tRefreshIISBindings ERROR ServerManager (IIS) CommitChanges {eee.Message} On Try: {intI}");
				await Task.Delay(1000);
			}
		}

		log.AppendLine($"\tRefreshIISBindings OK {sw.ElapsedMilliseconds}mS");
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

	private enum TypeChallenge
	{
		None,
		Http,
		Dns
	}

	async private static Task ChallengeDomainsAsync(StringBuilder log, List<string> domains, TypeChallenge challenge, bool UseStaging = false)
	{
		try
		{
			var sw = Stopwatch.StartNew();

			log.AppendLine($"ChallengeDomainsAsync {challenge} started {DateTime.Now}");

			var LocalhostDir = Settings.Get<string>("LocalhostDir");

			log.AppendLine($"\tChecking: {domains.Count} domains started");

			for (int i = domains.Count - 1; i >= 0; i--)
			{
				var domain = domains[i];
				if (string.IsNullOrWhiteSpace(domain))
					continue;
				if (CheckDomainCert(domain))
				{
					domains.Remove(domain);
					log.AppendLine($"\t\tCert for {domain} is valid");
				}
				else
				{
					log.AppendLine($"\t\tCert for {domain} must be renewed");
				}
			}

			log.AppendLine($"\tChecking: {domains.Count} domains remain");

			if (domains.Count > 0)
			{
				var acmeContext = await GetAcmeContextAsync(log, UseStaging);

				VimexxApi? vimexxApi = null;

				foreach (var domain in domains)
				{
					switch(challenge)
					{
						case TypeChallenge.Http:
							await ValidateDomainAsync(log, acmeContext, null, LocalhostDir, domain, UseStaging);
							break;
						case TypeChallenge.Dns:
							vimexxApi ??= await GetVimexxApiAsync(log);
							await ValidateDomainAsync(log, acmeContext, vimexxApi, null, domain, UseStaging);
							break;
						default:
							break;
					}
				}
				await RefreshIISBindingsAsync(log);
			}

			log.AppendLine($"ChallengeDomainsAsync ended (normal) {sw.Elapsed}");
		}
		catch (Exception eee)
		{
			log.AppendLine($"***** Error {eee.Message} ***** ");
		}
	}

	async public static Task LetsEncryptDomainsAsync(bool UseStaging)
	{
		var log = new StringBuilder();

		var domainsDns = Settings.Get<List<string>>("DnsChallenges");

		if (domainsDns != null && domainsDns.Count > 0)
			await ChallengeDomainsAsync(log, domainsDns, TypeChallenge.Dns, UseStaging);

		var domainsHttp = Settings.Get<List<string>>("HttpChallenges");

		if (domainsHttp != null && domainsHttp.Count > 0)
			await ChallengeDomainsAsync(log, domainsHttp, TypeChallenge.Http, UseStaging);

		await MailRapportAsync(log);

		await SaveLogAsync(log.ToString());
	}


}
