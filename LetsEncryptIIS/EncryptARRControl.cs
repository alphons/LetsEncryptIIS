using System;
using System.IO;
using System.Net;
using System.Text;
using System.Linq;
using System.Xml.Linq;
using System.Net.Mail;
using System.Security.Principal;
using System.Collections.Generic;
using System.Security.Cryptography.X509Certificates;

using Microsoft.Web.Administration;

using ACMESharp;
using ACMESharp.ACME;
using ACMESharp.JOSE;
using ACMESharp.PKI;
using ACMESharp.HTTP;

namespace LetsEncryptIIS
{
	public class EncryptARRControl
	{
		private AcmeClient client;

		private StringBuilder sb;

		private Uri BaseUri;

		public class SiteBinding
		{
			public long Id { get; set; }
			public string Name { get; set; }
			public string Path { get; set; }

			public string BindingHost { get; set; }
			public string BindingProtocol { get; set; }
			public string BindingInformation { get; set; }

			public override string ToString()
			{
				return BindingProtocol + "://" + BindingHost + " (" + Path + ")";
			}
		}

		public EncryptARRControl()
		{
			this.sb = new StringBuilder();
			ServicePointManager.SecurityProtocol = SecurityProtocolType.Tls | SecurityProtocolType.Tls11 | SecurityProtocolType.Tls12;

			this.BaseUri = new Uri(Properties.Settings.Default.BaseUriProduction);
			if (System.Diagnostics.Debugger.IsAttached)
				this.BaseUri = new Uri( Properties.Settings.Default.BaseUriStaging);

			var dir = this.BaseUri.Host.Replace(".", "-");

			if (!Directory.Exists(dir))
				Directory.CreateDirectory(dir);

			Directory.SetCurrentDirectory(dir);
		}

		private void Log(string s, params object[] args)
		{
			var path = Path.Combine(Properties.Settings.Default.LogDirectory, DateTime.Now.ToString("yyyyMMdd") + ".txt");
			var dir = Path.GetDirectoryName(path);
			if (!Directory.Exists(dir))
				Directory.CreateDirectory(dir);
			var text = string.Format("{0} {1}", DateTime.Now.ToString("HH:mm:ss"), string.Format(s, args));
			using (var sw = new StreamWriter(path, true))
				sw.WriteLine(text);

			sb.AppendLine(text);
		}

		private void MailRapport()
		{
			using (var msg = new MailMessage())
			{
				var from = Properties.Settings.Default.Contacts.Cast<string>().FirstOrDefault();
				msg.From = new MailAddress(from);
				foreach (var contact in Properties.Settings.Default.Contacts)
				{
					if (!string.IsNullOrWhiteSpace(contact))
						msg.To.Add(new MailAddress(contact.Trim()));
				}
				msg.Body = "<pre>" + sb.ToString() + "</pre>";
				msg.Subject = Properties.Settings.Default.SmptSubject;
				if (msg.Body.IndexOf("error") > 0 || System.Diagnostics.Debugger.IsAttached)
					msg.Subject += " (errors)";
				msg.IsBodyHtml = true;

				using (var smtp = new SmtpClient(Properties.Settings.Default.SmtpHost, Properties.Settings.Default.SmtpPort))
				{
					smtp.DeliveryMethod = SmtpDeliveryMethod.Network;
					smtp.EnableSsl = Properties.Settings.Default.SmtpEnableSsl;
					if (!string.IsNullOrWhiteSpace(Properties.Settings.Default.SmtpUser) ||
						!string.IsNullOrWhiteSpace(Properties.Settings.Default.SmtpPassword))
					{
						smtp.Credentials = new NetworkCredential()
						{
							UserName = Properties.Settings.Default.SmtpUser,
							Password = Properties.Settings.Default.SmtpPassword,
						};
					}
					smtp.Send(msg);
				}
			}
		}

		private string PrefixRoot(string serverName, string s)
		{
			return @"\\" + serverName + @"\" + s[0] + "$" + s.Substring(2);
		}

		private bool CreateChallenge(string path, string contents)
		{
			try
			{
				var dir = Path.GetDirectoryName(path);
				if (!Directory.Exists(dir))
					Directory.CreateDirectory(dir);
				File.WriteAllText(path, contents);
				return true;
			}
			catch (Exception exception)
			{
				Log("\t\t\tError: CreateChallenge, {0}" , exception.Message);
				return false;
			}

		}

		private bool DeleteChallenge(string path)
		{
			try
			{
				var dir = Path.GetDirectoryName(path);
				dir = Path.GetDirectoryName(dir);
				var name = Path.GetFileName(dir);
				if (name == ".well-known" && Directory.Exists(dir))
					Directory.Delete(dir, true);
				return true;
			}
			catch (Exception exception)
			{
				Log("\t\t\tError: DeleteChallenge, {0}" , exception.Message);
				return false;
			}
		}

		private bool CreateWebConfig(string path)
		{
			try
			{
				var directory = Path.GetDirectoryName(path);
				var webConfigPath = Path.Combine(directory, "web.config");
				if (File.Exists(webConfigPath))
					File.Delete(webConfigPath);
				File.WriteAllText(webConfigPath, Properties.Resources.web_config);
				return true;
			}
			catch (Exception exception)
			{
				Log("\t\t\tError: CreateWebConfig, {0}" , exception.Message);
				return false;
			}
		}

		private bool DeleteWebConfig(string path)
		{
			try
			{
				var directory = Path.GetDirectoryName(path);
				var webConfigPath = Path.Combine(directory, "web.config");
				if (File.Exists(webConfigPath))
					File.Delete(webConfigPath);
				return true;
			}
			catch (Exception exception)
			{
				Log("\t\t\tError: DeleteWebConfig, {0}" , exception.Message);
				return false;
			}
		}

		private void ChallengeGetCertAndInstall(List<SiteBinding> sites)
		{
			AuthorizationState authorizationState = null;
			AuthorizeChallenge authorizeChallenge = null;
			HttpChallenge httpChallenge = null;

			Log("\tChallengeGetCertAndInstall started");
			Log("\tChallengeGetCertAndInstall total sites: {0}", sites.Count);
			foreach (var site in sites)
			{
				Log("\t\tChallengeGetCertAndInstall * procesing {0}", site.BindingHost);

				try
				{
					authorizationState = this.client.AuthorizeIdentifier(site.BindingHost);
					Log("\t\tChallengeGetCertAndInstall authorizationState ok");
				}
				catch (Exception exception)
				{
					Log("\t\tChallengeGetCertAndInstall Error AuthorizeIdentifier {0}", exception.Message);
					continue;
				}

				try
				{
					authorizeChallenge = this.client.DecodeChallenge(authorizationState, AcmeProtocol.CHALLENGE_TYPE_HTTP);
				}
				catch (Exception exception)
				{
					Log("\t\tChallengeGetCertAndInstall Error DecodeChallenge {0}", exception.Message);
					continue;
				}

				if (authorizeChallenge == null)
				{
					Log("\t\tChallengeGetCertAndInstall authorizeChallenge == null");
					continue;
				}

				httpChallenge = authorizeChallenge.Challenge as HttpChallenge;
				if(httpChallenge == null)
				{
					Log("\t\tChallengeGetCertAndInstall httpChallenge == null");
					continue;
				}

				var challengePath = Path.Combine(site.Path, httpChallenge.FilePath.Replace('/', '\\'));

				if (!CreateChallenge(challengePath, httpChallenge.FileContent))
					continue;
				if (!CreateWebConfig(challengePath))
					continue;

				// warmup?
				try
				{
					using (var wc = new WebClient())
					{
						var response = wc.DownloadString(httpChallenge.FileUrl);
						if (httpChallenge.FileContent != response)
						{
							Log("\t\tChallengeGetCertAndInstall error FileContent != response for {0}", site.BindingHost);
							continue;
						}
					}
				}
				catch (Exception exception)
				{
					Log("\t\tChallengeGetCertAndInstall DownloadString {0} Error {1}", httpChallenge.FileUrl, exception.Message);
					continue;
				}
				Log("\t\tChallengeGetCertAndInstall Challenge placed for {0}", site.BindingHost);

				authorizationState.Challenges = new AuthorizeChallenge[] { authorizeChallenge };
				this.client.SubmitChallengeAnswer(authorizationState, AcmeProtocol.CHALLENGE_TYPE_HTTP, true);

				for (int intI = 0; intI < 60; intI++)
				{
					System.Threading.Thread.Sleep(1000);
					var newAuthorizationState = this.client.RefreshIdentifierAuthorization(authorizationState);
					if (newAuthorizationState.Status != "pending")
					{
						authorizationState = newAuthorizationState;
						break;
					}
				}

				if(DeleteWebConfig(challengePath))
					Log("\t\tChallengeGetCertAndInstall WebConfig deleted for {0}", site.BindingHost);

				if(DeleteChallenge(challengePath))
					Log("\t\tChallengeGetCertAndInstall Challenge deleted for {0}", site.BindingHost);

				switch (authorizationState.Status)
				{
					default:
						Log("\t\tChallengeGetCertAndInstall unknown status {0}", authorizationState.Status);
						break;
					case "pending":
						Log("\t\tChallengeGetCertAndInstall error pending");
						break;
					case "invalid":
						Log("\t\tChallengeGetCertAndInstall error invalid");
						break;
					case "valid":
						Log("\t\tChallengeGetCertAndInstall valid for {0}", site.BindingHost);
						if(InstallCertificate(site.BindingHost))
							Log("\t\tChallengeGetCertAndInstall ready {0}", site.BindingHost);
						break;
				}
			}
			Log("\tChallengeGetCertAndInstall ended");
		}

		private string GetIssuerCertificate(CertificateRequest certificate, CertificateProvider cp)
		{
			Log("\t\t\t\tGetIssuerCertificate started");

			var linksEnum = certificate.Links;
			if (linksEnum == null)
			{
				Log("\t\t\t\t\tGetIssuerCertificate error linksEnum == null");
				Log("\t\t\t\tGetIssuerCertificate ended"); 
				return null;
			}

			var links = new LinkCollection(linksEnum);
			var upLink = links.GetFirstOrDefault("up");
			if (upLink == null)
			{
				Log("\t\t\t\t\tGetIssuerCertificate error upLink == null");
				Log("\t\t\t\tGetIssuerCertificate ended");
				return null;
			}

			var temporaryFileName = Path.GetTempFileName();
			try
			{
				using (var web = new WebClient())
				{
					var uri = new Uri(this.BaseUri, upLink.Uri);
					web.DownloadFile(uri, temporaryFileName);
				}

				var cacert = new X509Certificate2(temporaryFileName);
				var sernum = cacert.GetSerialNumberString();

				var cacertDerFile = string.Format("ca-{0}-crt.der", sernum);
				var cacertPemFile = string.Format("ca-{0}-crt.pem", sernum);

				if (!File.Exists(cacertDerFile))
					File.Copy(temporaryFileName, cacertDerFile, true);

				if (!File.Exists(cacertPemFile))
					using (FileStream source = new FileStream(cacertDerFile, FileMode.Open),
						target = new FileStream(cacertPemFile, FileMode.Create))
					{
						var caCrt = cp.ImportCertificate(EncodingFormat.DER, source);
						cp.ExportCertificate(caCrt, EncodingFormat.PEM, target);
					}
				Log("\t\t\t\tGetIssuerCertificate ended");
				return cacertPemFile;
			}
			catch (Exception ex)
			{
				Log("\t\t\t\t\tGetIssuerCertificate error {0}", ex.Message);
			}
			finally
			{
				if (File.Exists(temporaryFileName))
					File.Delete(temporaryFileName);
			}
			Log("\t\t\t\tGetIssuerCertificate ended");
			return null;
		}

		private string GetCertificate(string host)
		{
			Log("\t\t\tGetCertificate started");

			var certificateProvider = CertificateProvider.GetProvider();
			var rsaPrivateKeyParams = new RsaPrivateKeyParams()
			{
				NumBits = Properties.Settings.Default.RSAKeyBits,
			};
			var rsaPrivateKey = certificateProvider.GeneratePrivateKey(rsaPrivateKeyParams);
			var csrDetails = new CsrDetails
			{
				CommonName = host,
			};
			var csrParams = new CsrParams
			{
				Details = csrDetails,
			};
			var csr = certificateProvider.GenerateCsr(csrParams, rsaPrivateKey, Crt.MessageDigest.SHA256);
			byte[] derBytes;
			using (var ms = new MemoryStream())
			{
				certificateProvider.ExportCsr(csr, EncodingFormat.DER, ms);
				derBytes = ms.ToArray();
			}

			CertificateRequest requestCertificate = null;
			var derBase64UrlEncoded = JwsHelper.Base64UrlEncode(derBytes);
			try
			{
				requestCertificate = this.client.RequestCertificate(derBase64UrlEncoded);
			}
			catch (Exception ex)
			{
				Log("\t\t\t\tGetCertificate error {0}", ex.InnerException.Message);
				certificateProvider.Dispose();
				return null;
			}

			var crtPfxFile = host + "-all.pfx";

			if (requestCertificate.StatusCode != System.Net.HttpStatusCode.Created)
			{
				crtPfxFile = null;
				Log("\t\t\t\tGetCertificate certRequ.StatusCode {0}", requestCertificate.StatusCode);
			}
			else
			{
				var keyGenFile = host + "-gen-key.json";
				var keyPemFile = host + "-key.pem";
				var csrGenFile = host + "-gen-csr.json";
				var csrPemFile = host + "-csr.pem";
				var crtDerFile = host + "-crt.der";
				var crtPemFile = host + "-crt.pem";
				var chainPemFile = host + "-chain.pem";

				using (var fs = new FileStream(keyGenFile, FileMode.Create))
					certificateProvider.SavePrivateKey(rsaPrivateKey, fs);
				using (var fs = new FileStream(keyPemFile, FileMode.Create))
					certificateProvider.ExportPrivateKey(rsaPrivateKey, EncodingFormat.PEM, fs);
				using (var fs = new FileStream(csrGenFile, FileMode.Create))
					certificateProvider.SaveCsr(csr, fs);
				using (var fs = new FileStream(csrPemFile, FileMode.Create))
					certificateProvider.ExportCsr(csr, EncodingFormat.PEM, fs);

				using (var file = File.Create(crtDerFile))
					requestCertificate.SaveCertificate(file);

				Crt crt;
				using (FileStream source = new FileStream(crtDerFile, FileMode.Open),
					target = new FileStream(crtPemFile, FileMode.Create))
				{
					crt = certificateProvider.ImportCertificate(EncodingFormat.DER, source);
					certificateProvider.ExportCertificate(crt, EncodingFormat.PEM, target);
				}

				// To generate a PKCS#12 (.PFX) file, we need the issuer's public certificate
				var isuPemFile = GetIssuerCertificate(requestCertificate, certificateProvider);

				using (FileStream intermediate = new FileStream(isuPemFile, FileMode.Open),
					certificate = new FileStream(crtPemFile, FileMode.Open),
					chain = new FileStream(chainPemFile, FileMode.Create))
				{
					certificate.CopyTo(chain);
					intermediate.CopyTo(chain);
				}

				using (FileStream source = new FileStream(isuPemFile, FileMode.Open),
					target = new FileStream(crtPfxFile, FileMode.Create))
				{
					try
					{
						var isuCrt = certificateProvider.ImportCertificate(EncodingFormat.PEM, source);
						certificateProvider.ExportArchive(rsaPrivateKey, new[] { crt, isuCrt }, ArchiveFormat.PKCS12, target,
							Properties.Settings.Default.PFXPassword);
					}
					catch (Exception ex)
					{
						Log("\t\t\t\tGetCertificate error {0}", ex.Message);
					}
				}
			}
			certificateProvider.Dispose();
			Log("\t\t\tGetCertificate ended");

			return crtPfxFile;
		}

		private X509Certificate2 InstallCertOnLocalStore(string host, string pfxFilename)
		{
			Log("\t\t\tInstallCertOnLocalStore started");
			var store = new X509Store(Properties.Settings.Default.CertificateStoreName, StoreLocation.LocalMachine);
			store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite);

			X509Certificate2 certificate = null;
			try
			{
				certificate = new X509Certificate2(pfxFilename, Properties.Settings.Default.PFXPassword,
					X509KeyStorageFlags.MachineKeySet | 
					X509KeyStorageFlags.PersistKeySet |
					X509KeyStorageFlags.Exportable);

				certificate.FriendlyName = string.Format("{0} {1}", host, DateTime.Now.ToString("yyyy-MM-dd HH:mm:ss"));

				store.Add(certificate);

				Log("\t\t\t\tInstallCertOnLocalStore {0} added cert {1}", host, certificate.FriendlyName);
			}
			catch (Exception ex)
			{
				Log("\t\t\t\tInstallCertOnLocalStore error {0}", ex.Message);
			}
			store.Close();
			Log("\t\t\tInstallCertOnLocalStore ended");

			return certificate;
		}

		private void UninstallCertOnLocalStore(string host, string FriendlyName)
        {
			Log("\t\t\tUninstallCertOnLocalStore started");

            var store = new X509Store(Properties.Settings.Default.CertificateStoreName, StoreLocation.LocalMachine);

            try
            {
				store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadWrite);
				var col = store.Certificates.Find(X509FindType.FindBySubjectName, host, false);

                foreach (var cert in col)
                {
                    var subjectName = cert.Subject.Split(',');

					if (cert.FriendlyName != FriendlyName && subjectName[0] == "CN=" + host)
                    {
                        store.Remove(cert);
						Log("\t\t\t\tUninstallCertOnLocalStore {0} removed cert {1}", host, cert.FriendlyName);
                    }
                }
            }
            catch (Exception ex)
            {
				Log("\t\t\t\tUninstallCertOnLocalStore error {0}", ex.Message);
            }
            store.Close();
			Log("\t\t\tUninstallCertOnLocalStore ended");
        }

		private bool InstallCertOnLocalIIS(string host, byte[] CertificateHash)
        {
			Log("\t\t\tInstallCertOnLocalIIS started");
			using (var iisManager = new ServerManager())
			{
				// Try existing sites, find https host binding and change to new certificate
				foreach (var site in iisManager.Sites)
				{
					var existingHttpsBinding = site.Bindings.FirstOrDefault(x => x.Protocol == "https" && x.Host == host);
					if (existingHttpsBinding != null)
					{
						existingHttpsBinding.CertificateStoreName = Properties.Settings.Default.CertificateStoreName;
						existingHttpsBinding.CertificateHash = CertificateHash;
						iisManager.CommitChanges();
						Log("\t\t\t\tInstallCertOnLocalIIS {0} {1} {2} (existing binding)", host, site.Id, site.Name);
						Log("\t\t\tInstallCertOnLocalIIS ended");
						return true;
					}
				}

				// Try existing sites, find http (not https) host binding and add new https binding and change to new certificate
				foreach (var site in iisManager.Sites)
				{
					var existingHttpsBinding = site.Bindings.FirstOrDefault(x => x.Protocol == "http" && x.Host == host);
					if (existingHttpsBinding != null)
					{
						var iisBinding = site.Bindings.Add("*:443:" + host, CertificateHash, Properties.Settings.Default.CertificateStoreName);
						iisBinding.Protocol = "https";
						iisBinding.SetAttributeValue("sslFlags", 1); // Enable SNI support
						iisManager.CommitChanges();
						Log("\t\t\t\tInstallCertOnLocalIIS {0} {1} {2} (new binding)", host, site.Id, site.Name);
						Log("\t\t\tInstallCertOnLocalIIS ended");
						return true;
					}
				}

				// Try existing "Default Web Site", add new https binding and change to new certificate
				foreach (var site in iisManager.Sites)
				{
					if (site.Name == "Default Web Site")
					{
						var iisBinding = site.Bindings.Add("*:443:" + host, CertificateHash, Properties.Settings.Default.CertificateStoreName);
						iisBinding.Protocol = "https";
						iisBinding.SetAttributeValue("sslFlags", 1); // Enable SNI support
						iisManager.CommitChanges();
						Log("\t\t\t\tInstallCertOnLocalIIS {0} {1} {2} (new binding)", host, site.Id, site.Name);
						Log("\t\t\tInstallCertOnLocalIIS ended");
						return true;
					}
				}
			}
			Log("\t\t\tInstallCertOnLocalIIS ended not installed!");
			return false;
        }

		private bool InstallCertificate(string host)
		{
			try
			{
				var certPfxFile = GetCertificate(host);
				if (certPfxFile != null)
				{
					var certificate = InstallCertOnLocalStore(host, certPfxFile);
					if (certificate != null)
					{
						InstallCertOnLocalIIS(host, certificate.GetCertHash());
						UninstallCertOnLocalStore(host, certificate.FriendlyName);
						return true;
					}
				}
			}
			catch (Exception ex)
			{
				Log("\t\t\t\tInstallCertificate error {0}", ex.Message);
			}
			return false;
		}


		private void AddSiteBindings(List<SiteBinding> list, string ServerName, string[] websites)
		{
			var appHostConfigFile = string.Format(@"\\{0}\c${1}", ServerName, Properties.Settings.Default.ConfigFile);

			try
			{
				using (var serverManager = new ServerManager(true, appHostConfigFile))
				{
					foreach (var site in serverManager.Sites.Cast<Site>())
					{
						foreach (var binding in site.Bindings)
						{
							if (binding.Protocol != "http")
								continue;
							if (string.IsNullOrWhiteSpace(binding.Host))
								continue;
							if (!websites.Contains(binding.Host))
								continue;
							list.Add(new SiteBinding()
							{
								Id = site.Id,
								Name = site.Name,
								Path = PrefixRoot(ServerName, site.Applications["/"].VirtualDirectories["/"].PhysicalPath),
								BindingProtocol = binding.Protocol,
								BindingHost = binding.Host,
								BindingInformation = binding.BindingInformation,
							});
						}
					}
				}
			}
			catch (Exception exception)
			{
				Log("\t\tAddSiteBindings error {0}", exception.Message);
			}
		}

		/// <summary>
		/// Get list of binding from remote IIS (run this program as Administrator)
		/// </summary>
		/// <param name="serverName">servername of remote IIS</param>
		/// <returns>list of http bindings</returns>
		private List<SiteBinding> GetSiteBindings()
		{
			Log("\tGetSiteBindings started");
			var list = new List<SiteBinding>();

			 var xdoc = XDocument.Load(Path.Combine(AppDomain.CurrentDomain.BaseDirectory,  "servers.xml"));

			 var servers = (from server in xdoc.Descendants("server")
						   select new
							   {
								   ServerName = server.Attribute("name").Value,
								   Websites = server.Value.Split('\n').Select(x => x.Trim()).Where(x => !string.IsNullOrWhiteSpace(x)).ToArray(),
							   }).ToList();

			 foreach (var item in servers)
			 {
				 AddSiteBindings(list, item.ServerName, item.Websites);
			 }
			Log("\tGetSiteBindings total bindings: {0}", list.Count);
			Log("\tGetSiteBindings ended");
			return list;
		}

		public void RemoveValidWebsites(List<SiteBinding> websites)
		{
			Log("\tRemoveValidWebsites started");
			var store = new X509Store(Properties.Settings.Default.CertificateStoreName, StoreLocation.LocalMachine);
			try
			{
				store.Open(OpenFlags.OpenExistingOnly | OpenFlags.ReadOnly);

				for (int intI = websites.Count - 1; intI >= 0; intI--)
				{
					var subject =  "CN=" + websites[intI].BindingHost;
					var col = store.Certificates.Find(X509FindType.FindBySubjectDistinguishedName, subject, true);

					foreach (var cer in col)
					{
						var ExpirationDate = DateTime.Parse(cer.GetExpirationDateString());
						var daysValid = ExpirationDate.Subtract(DateTime.Now).TotalDays;
						if (daysValid > Properties.Settings.Default.CertDaysBeforeExpire)
						{
							Log("\t\tRemoveValidWebsites no update needed for {0} ({1:0.00} days) ", websites[intI], daysValid);
							websites.RemoveAt(intI);
						}
					}
				}
			}
			catch (Exception ex)
			{
				Log("\t\tRemoveValidWebsites error {0}", ex.Message);
			}
			store.Close();
			Log("\t\tRemoveValidWebsites total updates needed {0}", websites.Count);
			Log("\tRemoveValidWebsites ended");
		}


		private bool IsAdministrator()
		{
			return (new WindowsPrincipal(WindowsIdentity.GetCurrent())).IsInRole(WindowsBuiltInRole.Administrator);
		}    

		private bool Worker()
		{
			Log("RefreshCertificate start");
			if (!IsAdministrator())
			{
				Log("\tThis program must be run as administrator");
				Log("RefreshCertificate ended");
				return false;
			}

			// Get all Binding from the different IIS servers, if any
			var sites = GetSiteBindings();

			if (System.Diagnostics.Debugger.IsAttached)
				sites.RemoveRange(1, sites.Count - 1); // only use the first one

			RemoveValidWebsites(sites);
			if (sites.Count == 0)
			{
				Log("RefreshCertificate ended");
				return false;
			}

			var contacts = Properties.Settings.Default.Contacts.Cast<string>().Select(x => "mailto:" + x).ToArray();
			using (var signer = new RS256Signer())
			{
				signer.Init();

				var signerPath = "RSAKeyValue.xml";
				if (File.Exists(signerPath))
				{
					using (var signerStream = File.OpenRead(signerPath))
						signer.Load(signerStream);
					Log("\tLoaded existing {0}", signerPath);
				}
				using (this.client = new AcmeClient(this.BaseUri, new AcmeServerDirectory(), signer))
				{
					this.client.Init();
					this.client.GetDirectory(true);

					var registrationPath = "Registration.json";
					if (File.Exists(registrationPath))
					{
						using (var registrationStream = File.OpenRead(registrationPath))
							this.client.Registration = AcmeRegistration.Load(registrationStream);

						Log("\tLoaded existing {0}", registrationPath);
					}
					else
					{
						var registration = this.client.Register(contacts);

						this.client.UpdateRegistration(true, true);
						using (var registrationStream = File.OpenWrite(registrationPath))
							this.client.Registration.Save(registrationStream);

						Log("\tCreated new {0}", registrationPath);

						using (var signerStream = File.OpenWrite(signerPath))
							signer.Save(signerStream);

						Log("\tCreated new {0}",  signerPath);

					}

					// ACME client is now loaded using signer and registration
					ChallengeGetCertAndInstall(sites);
				}
			}

			Log("RefreshCertificate ended");
			return true;
		}

		/// <summary>
		/// Refresh and installs certificates on the host where this program runs
		/// Can take servername of other IIS server which hosts the websites and localhost is an ARR (loadbalancer)
		/// </summary>
		public static void RefreshCertificate()
		{
			var control = new EncryptARRControl();
			try 
			{ 
				control.Worker(); 
			} 
			catch 
			{ 
			}
			control.MailRapport();
		}


	}

}
