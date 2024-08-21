using System.Text;
using System.Text.Json;

// https://developers.whmcs.com/api/

#nullable enable

namespace Vimexx_API;

public class VimexxApi(StringBuilder log)
{
	private const string USER_AGENT = "Vimexx-WHMCS api agent .NET core 1.0";
	private const string API_URL = "https://api.vimexx.nl";
	private const string API_VERSION = "8.6.1-release.1";

	private string endpoint = API_URL + "/api/v1";

	private AuthToken? token;

	private readonly StringBuilder log = log;

	// we do serialization because vimexx tent to error a lot!! so we can debug
	async private Task<T?> RequestAsync<T>(HttpMethod method, string apiMethod, object data)
	{
		var jsonResult = string.Empty;
		var jsonRequest = string.Empty;

		if (this.token == null)
		{
			log.AppendLine("Error: token is null");
			return default;
		}

		try
		{
			using var httpClient = new HttpClient();

			httpClient.DefaultRequestHeaders.Add("User-Agent", USER_AGENT);

			httpClient.DefaultRequestHeaders.Authorization = 
				new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", this.token.access_token);

			jsonRequest = JsonSerializer.Serialize(new { body = data, version = API_VERSION });

			using var request = new HttpRequestMessage(method, this.endpoint + apiMethod)
			{
				Content = new StringContent(jsonRequest, Encoding.UTF8, "application/json")
			};

			using var httpResponseMessage = await httpClient.SendAsync(request);

			httpResponseMessage.EnsureSuccessStatusCode();

			if (httpResponseMessage.IsSuccessStatusCode)
			{
				using var stream = await httpResponseMessage.Content.ReadAsStreamAsync();

				using var sr = new StreamReader(stream);

				jsonResult = await sr.ReadToEndAsync();

				try
				{
					return JsonSerializer.Deserialize<T>(jsonResult);
				}
				catch
				{
					log.AppendLine($"Error: Deserialize: {method} {apiMethod}{Environment.NewLine}{jsonRequest}{Environment.NewLine}{jsonResult}{Environment.NewLine}");
				}
			}
		}
		catch(Exception eee)
		{
			log.AppendLine($"Error: Exception: {eee.Message}: {method} {apiMethod}{Environment.NewLine}{jsonRequest}{Environment.NewLine}{jsonResult}{Environment.NewLine}");
		}

		return default;
	}

	async public Task<string?> LoginAsync(string clientId, string clientKey, string username, string password, bool testmodus = false)
	{
		if (testmodus)
			this.endpoint = API_URL + "/apitest/v1";

		List<KeyValuePair<string, string>> data = new Dictionary<string, string>
			{
				{ "grant_type",     "password" },
				{ "client_id",      clientId },
				{ "client_secret",  clientKey },
				{ "username",       username },
				{ "password",       password },
				{ "scope",          "whmcs-access" }
			}.ToList();

		var httpClient = new HttpClient();

		httpClient.DefaultRequestHeaders.Add("User-Agent", USER_AGENT);

		var req = new HttpRequestMessage(HttpMethod.Post, API_URL + "/auth/token") { Content = new FormUrlEncodedContent(data) };

		var httpResponseMessage = await httpClient.SendAsync(req);

		httpResponseMessage.EnsureSuccessStatusCode();

		if (httpResponseMessage.IsSuccessStatusCode)
		{
			var stream = await httpResponseMessage.Content.ReadAsStreamAsync();

			this.token = await JsonSerializer.DeserializeAsync<AuthToken>(stream);

			if(this.token != null)
				return $"type:{this.token.token_type} exp:{this.token.expires_in}";
		}
		return null;
	}

	async public Task<GetDNSResponse?> GetDNSAsync(string domainname)
	{
		var args = domainname.Split('.');

		GetDNSResponse? response = null;

		for (int i = 0; i < 5; i++)
		{
			response = await RequestAsync<GetDNSResponse>(HttpMethod.Post, "/whmcs/domain/dns", new { sld = args[^2], tld = args[^1] });
			if (response != null)
				break;
			log.AppendLine($"\t\t\t\tError: GetDNSAsync try {i}");
			await Task.Delay(5000);
		}

		return response;
	}

	async public Task<SaveDNSResponse?> SaveDNSAsync(string domainname, List<DnsRecord> dns_records)
	{
		var args = domainname.Split('.');

		dns_records.Where(x => x.TTL == null).ToList().ForEach(x => x.TTL = 3600); // set everything to an hour

		SaveDNSResponse? response = null;

		for (int i = 0; i < 5; i++)
		{
			response = await RequestAsync<SaveDNSResponse>(HttpMethod.Put, "/whmcs/domain/dns", new { sld = args[^2], tld = args[^1], dns_records });
			if (response != null)
				break;
			log.AppendLine($"\t\t\t\tError: SaveDNSAsync try {i}");
			await Task.Delay(5000);
		}

		return response;
	}

	async public Task<Response<object>?> LetsEncryptAsync(string domainname, List<string> challenges)
	{
		var getdnsresponse = await GetDNSAsync(domainname);

		if (getdnsresponse == null)
		{
			log.AppendLine($"Error: GetDNSAsync returned null on {domainname}");
			return null;
		}

		if (getdnsresponse.result == false)
			return new Response<object>() { result = getdnsresponse.result, message = getdnsresponse.message };
	
		// filter out, the old dns challenges
		var records = getdnsresponse.data.dns_records.Where(x => !x.Name.StartsWith("_acme-challenge.")).ToList();

		var name = "_acme-challenge";

		if (challenges.Count > 0)
		{
			var args = domainname.Split('.');
			if (args.Length > 2)
				name += "." + args[^3];
		}

		// put in new challenges, or none, if challenges = empty array
		foreach (var challenge in challenges)
			records.Add(new DnsRecord() { Name = name, Content = challenge, Type = "TXT", TTL = 300 });

		return await SaveDNSAsync(domainname, records);
	}

}