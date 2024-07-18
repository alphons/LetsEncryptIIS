
using System.Text;
using Vimexx_API;

var VimexxClientId = "123";
var VimexxClientKey = "5kfeljkfljefklwfjfewjlfwke";
var VimexxUsername = "info@example.com";
var VimexxPassword = "somepassword";

var sb = new StringBuilder();

var api = new VimexxApi(sb);

await api.LoginAsync(VimexxClientId, VimexxClientKey, VimexxUsername, VimexxPassword, false);

var result = await api.GetDNSAsync("hw.nl");
if (result?.data.dns_records != null)
{
	var saved = await api.SaveDNSAsync("hw.nl", result.data.dns_records);
}

Console.WriteLine(sb.ToString());

