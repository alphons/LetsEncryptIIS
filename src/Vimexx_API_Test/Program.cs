
using System.Text;
using Vimexx_API;

var VimexxClientId = "123";
var VimexxClientKey = "85780975tklkjkl76Z7AYB3ajajJJK";
var VimexxUsername = "info@example.com";
var VimexxPassword = "AP@ss5w0rd";

var sb = new StringBuilder();

var api = new VimexxApi(sb);

await api.LoginAsync(VimexxClientId, VimexxClientKey, VimexxUsername, VimexxPassword, false);

var result = await api.GetDNSAsync("hw.nl");
if (result?.Data?.DNSRecords != null)
{
	var saved = await api.SaveDNSAsync("hw.nl", result.Data.DNSRecords);
}

Console.WriteLine(sb.ToString());

