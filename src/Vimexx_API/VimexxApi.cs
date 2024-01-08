﻿using System.Text;
using System.Text.Json;

#nullable enable

namespace Vimexx_API;

public class VimexxApi
{
	private const string USER_AGENT = "Vimexx-WHMCS api agent .NET core 1.0";
	private const string API_URL = "https://api.vimexx.nl";
	private const string API_VERSION = "8.6.1-release.1";

	private string endpoint = API_URL + "/api/v1";

	private AuthToken? token;

	private readonly StringBuilder log;

	public VimexxApi(StringBuilder log)
	{
		this.log = log;
	}

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
			var httpClient = new HttpClient();

			httpClient.DefaultRequestHeaders.Add("User-Agent", USER_AGENT);

			httpClient.DefaultRequestHeaders.Authorization = 
				new System.Net.Http.Headers.AuthenticationHeaderValue("Bearer", this.token.access_token);

			jsonRequest = JsonSerializer.Serialize(new { body = data, version = API_VERSION });

			var request = new HttpRequestMessage(method, this.endpoint + apiMethod)
			{
				Content = new StringContent(jsonRequest, Encoding.UTF8, "application/json")
			};

			var httpResponseMessage = await httpClient.SendAsync(request);

			httpResponseMessage.EnsureSuccessStatusCode();

			if (httpResponseMessage.IsSuccessStatusCode)
			{
				var stream = await httpResponseMessage.Content.ReadAsStreamAsync();

				var sr = new StreamReader(stream);

				jsonResult = await sr.ReadToEndAsync();

				try
				{
					return JsonSerializer.Deserialize<T>(jsonResult);
				}
				catch
				{
					log.AppendLine($"Error: Deserialize: {apiMethod}{Environment.NewLine}{jsonRequest}{Environment.NewLine}{jsonResult}{Environment.NewLine}");
				}
			}
		}
		catch(Exception eee)
		{
			log.AppendLine($"Error: Exception: {eee.Message}: {apiMethod}{Environment.NewLine}{jsonRequest}{Environment.NewLine}{jsonResult}{Environment.NewLine}");
		}

		return default;
	}

	async public Task LoginAsync(string clientId, string clientKey, string username, string password, bool testmodus = false)
	{
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
		}

		if (testmodus)
			this.endpoint = API_URL + "/apitest/v1";
	}

	async public Task<GetDNSResponse?> GetDNSAsync(string domainname)
	{
		var args = domainname.Split('.');

		return await RequestAsync<GetDNSResponse>(HttpMethod.Post, "/whmcs/domain/dns", new { sld = args[0], tld = args[1] });
	}

	async public Task<SaveDNSResponse?> SaveDNSAsync(string domainname, List<DnsRecord> dns_records)
	{
		var args = domainname.Split('.');

		dns_records.Where(x => x.ttl == null).ToList().ForEach(x => x.ttl = 3600);
		dns_records.Where(x => x.type == "CAA").ToList().ForEach(x => x.ttl = 300);

		return await RequestAsync<SaveDNSResponse>(HttpMethod.Put, "/whmcs/domain/dns", new { sld = args[0], tld = args[1], dns_records });
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

		var records = getdnsresponse.data.dns_records.Where(x => !x.name.StartsWith("_acme-challenge.")).ToList();

		foreach(var challenge in challenges)
			records.Add(new DnsRecord() { name = "_acme-challenge", content = challenge, type = "TXT", ttl = 300 });

		return await SaveDNSAsync(domainname, records);
	}

	async public Task<Response<object>?> LetsEncryptAsync(string domainname, string challenge)
	{
		var getdnsresponse = await GetDNSAsync(domainname);

		if (getdnsresponse == null)
		{
			log.AppendLine($"Error: LetsEncryptAsync GetDNSAsync returns null");
			return null;
		}

		if (getdnsresponse.result == false)
			return new Response<object>() { result = getdnsresponse.result, message = getdnsresponse.message };

		var records = getdnsresponse.data.dns_records;

		// clear all _acme-challenge records
		if (string.IsNullOrWhiteSpace(challenge))
			records = records.Where(x => !x.name.StartsWith("_acme-challenge.")).ToList();

		if(!string.IsNullOrWhiteSpace(challenge))
			records.Add(new DnsRecord() { name = "_acme-challenge", content = challenge, type = "TXT", ttl = 300 });

		return await SaveDNSAsync(domainname, records);
	}


}