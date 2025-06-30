using Certes;
using Certes.Acme;
using Certes.Acme.Resource;
using Certes.Pkcs;
using Microsoft.Web.Administration;
using System.Diagnostics;
using System.Net.Mail;
using System.Security.Cryptography;
using System.Security.Cryptography.X509Certificates;
using System.Text;
using Vimexx_API;

namespace LetsEncryptIIS;

public class CertHelper
{
	async private static Task<bool> AddCertToStoreAsync(StringBuilder log, string PathToPfx)
	{
		var sw = Stopwatch.StartNew();
		try
		{
			using var store = new X509Store(Settings.Get("CertificateStoreName"), Enum.Parse<StoreLocation>(Settings.Get("CertificateStoreLocation")));

			store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite);

			var data = await File.ReadAllBytesAsync(PathToPfx);

			var certificate = new X509Certificate2(data,
				Settings.Get("PFXPassword"),
				X509KeyStorageFlags.MachineKeySet |
				X509KeyStorageFlags.PersistKeySet |
				X509KeyStorageFlags.Exportable);

			store.Add(certificate);
			store.Close();

			log.AppendLine($"\t\t\tAdd {PathToPfx} to cert store {sw.ElapsedMilliseconds}ms");

			return true;
		}
		catch (Exception e)
		{
			log.AppendLine($"\t\t\tAddCertToStor ERROR {e.Message}");
		}
		return false;
	}

	async private static Task<VimexxApi?> GetVimexxApiAsync(StringBuilder log)
	{
		var sw = Stopwatch.StartNew();

		var vimexxApi = new VimexxApi(log);
		var status = await vimexxApi.LoginAsync(
			Settings.Get("VimexxClientId"),
			Settings.Get("VimexxClientKey"),
			Settings.Get("VimexxUsername"),
			Settings.Get("VimexxPassword"));
		if (status == null)
			return null;

		log.AppendLine($"\tGetVimexxApi {status} {sw.ElapsedMilliseconds}ms");

		return vimexxApi;
	}

	async private static Task ClearDnsChallenges(StringBuilder log, IOrderContext orderContext, VimexxApi vimexxApi)
	{
		log.AppendLine($"\t\t\tClearDnsChallenges started");
		var sw = Stopwatch.StartNew();
		var authorizations = await orderContext.Authorizations();

		var domains = new List<string>();

		foreach (var authz in authorizations)
		{
			var res = await authz.Resource();
			if (!domains.Contains(res.Identifier.Value))
				domains.Add(res.Identifier.Value);
		}

		foreach(var domain in domains)
		{
			var totalresult = await vimexxApi.LetsEncryptAsync(domain, []);
			if (totalresult == null)
				log.AppendLine($"Error: ClearAuthorizations: vimexxApi.LetsEncryptAsync returns null on {domain}");
		}

		log.AppendLine($"\t\t\tClearDnsChallenges {sw.ElapsedMilliseconds}ms");
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

		log.AppendLine($"\t\t\tCreateDnsChallenge (getting challenges) {sw.ElapsedMilliseconds}ms");

		sw.Restart();

		// put DNS challenge(s) records per domain
		foreach (var domain in dict.Keys)
		{
			var challenges = dict[domain];

			var result = await vimexxApi.LetsEncryptAsync(domain, challenges);

			if (result == null)
				log.AppendLine($"Error: vimexxApi.LetsEncryptAsync returns null on {domain}");
		}

		log.AppendLine($"\t\t\tCreateDnsChallenge (updating DNS entries) {sw.ElapsedMilliseconds}ms");

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

		log.AppendLine($"\t\t\tCreateDnsChallenge Start Validating {sw.ElapsedMilliseconds}ms");
	}

	private async static Task CreateHttpChallenge(StringBuilder log, string? LocalhostDir, 
		IEnumerable<IAuthorizationContext> authorizations)
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

	async private static Task<IOrderContext?> CreateChallenge(StringBuilder log, 
		AcmeContext acmeContext, VimexxApi? vimexxApi, string? LocalhostDir, string[] hosts)
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

		for (int i = 1; i <= 10; i++)
		{
			await Task.Delay(1000);

			List<AuthorizationStatus> statuses = [];

			foreach (var authz in authorizations)
			{
				var res = await authz.Resource();

				if (AuthorizationStatus.Invalid == res?.Status)
				{
					
					log.AppendLine($"\t\t\t\tCreateChallenge ERROR AuthorizationStatus.Invalid status in {sw.ElapsedMilliseconds}ms (bailing out)");

					if (res?.Challenges.Count > 0)
					{
						foreach (var challenge in res.Challenges)
							log.AppendLine($"\t\t\t\t\tCHallengeError: {challenge?.Error.Detail}");
					}

					await authz.Deactivate();

					// cleanup when in error
					if (vimexxApi != null)
						await ClearDnsChallenges(log, orderContext, vimexxApi);
					else
						ClearHttpChallenge(log, orderContext, LocalhostDir);

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
					await ClearDnsChallenges(log, orderContext, vimexxApi);
				else
					ClearHttpChallenge(log, orderContext, LocalhostDir);

				return orderContext;
			}
		}

		log.AppendLine($"\t\t\t\tCreateChallenge ERROR timeout in {sw.ElapsedMilliseconds}ms (bailing out)");

		if (vimexxApi != null)
			await ClearDnsChallenges(log, orderContext, vimexxApi);
		else
			ClearHttpChallenge(log, orderContext, LocalhostDir);

		return null;
	}


	async private static Task<IOrderContext?> ValidateOrderAsync(StringBuilder log, 
		AcmeContext acmeContext, VimexxApi? vimexxApi, string? LocalhostDir, string[] hosts)
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

			if (!body.Contains("error", StringComparison.CurrentCultureIgnoreCase))
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

	async private static Task<CertificateChain?> GetCertificateChainAsync(StringBuilder log, 
		IKey privateKey, IOrderContext orderContext, string[] hosts, string domain)
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

	/// <summary>
	/// Save cert to domain.pfx
	/// </summary>
	/// <param name="log"></param>
	/// <param name="privateKey"></param>
	/// <param name="certificate"></param>
	/// <param name="domain"></param>
	/// <param name="UseStaging"></param>
	/// <returns></returns>

	async private static Task SaveCertificateAsync(StringBuilder log, 
		IKey privateKey, CertificateChain certificate, string domain, bool UseStaging)
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

	async private static Task ValidateDomainAsync(StringBuilder log, 
		AcmeContext acmeContext, VimexxApi? vimexxApi, string? LocalhostDir, string domain, bool UseStaging)
	{
		var sw = Stopwatch.StartNew();

		string[] hosts = [];

		if (vimexxApi != null)
		{
			if (domain.Split('.').Length == 2) // abc.com
				hosts = [domain, $"*.{domain}"];
			else  // abc.def.com
				hosts = [domain];
		}

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
		using var store = new X509Store(Settings.Get("CertificateStoreName"), Enum.Parse<StoreLocation>(Settings.Get("CertificateStoreLocation")));

		store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite);

		var certificates = store.Certificates.Find(X509FindType.FindBySubjectDistinguishedName, $"CN={domain}", true);

		var valid = false;
		foreach (var certificate in certificates)
		{
			var ExpirationDate = DateTime.Parse(certificate.GetExpirationDateString());
			var daysValid = ExpirationDate.Subtract(DateTime.Now).TotalDays;
			if (daysValid > Settings.Get<double>("CertDaysBeforeExpire"))
				valid = true;
		}
		store.Close();
		return valid;
	}

	private static byte[] StringToByteArray(string hex)
	{
		hex = hex.Replace(" ", "").Replace("-", ""); // Verwijder spaties en streepjes
		int numberChars = hex.Length;
		byte[] bytes = new byte[numberChars / 2];
		for (int i = 0; i < numberChars; i += 2)
		{
			bytes[i / 2] = Convert.ToByte(hex.Substring(i, 2), 16);
		}
		return bytes;
	}

	private static byte[] GetCertHashFromPfx(StringBuilder sb, string domain)
	{
		try
		{
			var pfxFileName = $"{domain}.pfx";

			if (File.Exists(pfxFileName))
			{
				using var certificate = new X509Certificate2(pfxFileName, Settings.Get("PFXPassword"), X509KeyStorageFlags.DefaultKeySet);

				return certificate.GetCertHash();
			}
		}
		catch (CryptographicException ex)
		{
			sb.AppendLine($"Fout bij het laden van het .pfx-bestand. Controleer het bestandspad of wachtwoord. {ex.Message}");
		}
		catch (Exception ex)
		{
			sb.AppendLine($"Onverwachte fout bij het verwerken van het .pfx-bestand. {ex.Equals}");
		}

		return [];
	}

	private static void RemoveDomainCertsFromStore(StringBuilder log, string domain)
	{
		using var store = new X509Store(Settings.Get("CertificateStoreName"), Enum.Parse<StoreLocation>(Settings.Get("CertificateStoreLocation")));

		try
		{
			store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite);

			var col = store.Certificates.Find(X509FindType.FindBySubjectDistinguishedName, $"CN={domain}", false);

			foreach (var c in col)
			{
				try
				{
					store.Remove(c);
					log.AppendLine($"Certificaat met thumbprint {c.Thumbprint} verwijderd.");
				}
				catch (Exception ex)
				{
					log.AppendLine($"Fout bij verwijderen van certificaat {c.Thumbprint}: {ex.Message}");
				}
				finally
				{
					c.Dispose();
				}
			}

			if (col.Count == 0)
			{
				log.AppendLine($"Geen certificaten gevonden voor CN={domain}.");
			}
		}
		catch (Exception ex)
		{
			log.AppendLine($"Fout bij het openen van de certificaatwinkel of verwijderen van certificaten: {ex.Message}");
		}
		finally
		{
			store.Close();
		}
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

		var localConfigFile = Settings.Get("LocalConfig");

		if (string.IsNullOrWhiteSpace(localConfigFile))
		{
			log.AppendLine($"\tRefreshIISBindings Skipped (no LocalConfig)");
			return;
		}

		var iisManager = new ServerManager(localConfigFile);

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

				var CertificateHash = GetCertHashFromPfx(log, domain);

				if (CertificateHash.Length == 0)
				{
					while (domain.Split('.').Length > 2)
					{
						ii = domain.IndexOf('.');
						domain = domain[(ii + 1)..];  // strip www. or other names
					}
					CertificateHash = GetCertHashFromPfx(log, domain);

					if (CertificateHash.Length == 0)
						continue;
				}

				if (binding.CertificateHash != null && binding.CertificateHash.SequenceEqual(CertificateHash))
					continue;

				log.AppendLine($"\t\tRefreshIISBindings {binding.Host} using new cert {domain}");

				site.Bindings.Remove(binding);

				RemoveDomainCertsFromStore(log, domain);

				await AddCertToStoreAsync(log, $"{domain}.pfx");

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

	async private static Task ChallengeDomainsAsync(StringBuilder log, 
		List<string> domains, TypeChallenge challenge, bool UseStaging = false)
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
							vimexxApi = await GetVimexxApiAsync(log); // login again for every domain! 2024-08-21
							if( vimexxApi != null )
								await ValidateDomainAsync(log, acmeContext, vimexxApi, null, domain, UseStaging);
							else
								log.AppendLine($"\tGetVimexxApi ERROR");
							vimexxApi = null;
							log.AppendLine($"\tGetVimexxApi usage ended {sw.Elapsed}");
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

		if(UseStaging)
			log.AppendLine("***STAGING***");

		var domainsDns = Settings.Get<List<string>>("DnsChallenges");

		if (domainsDns != null && domainsDns.Count > 0)
			await ChallengeDomainsAsync(log, domainsDns, TypeChallenge.Dns, UseStaging);

		var domainsHttp = Settings.Get<List<string>>("HttpChallenges");

		if (domainsHttp != null && domainsHttp.Count > 0)
			await ChallengeDomainsAsync(log, domainsHttp, TypeChallenge.Http, UseStaging);

		if (UseStaging)
			log.AppendLine("***STAGING***");

		await MailRapportAsync(log);

		await SaveLogAsync(log.ToString());
	}


}
