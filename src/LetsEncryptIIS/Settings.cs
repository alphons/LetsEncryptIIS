
using System.Text.Json;

namespace LetsEncryptIIS2Core;

public static class Settings
{
	private static Dictionary<string, JsonElement>? dict;

	public static T? Get<T>(string Name)
	{
		if (dict == null)
		{
			if (!File.Exists("settings.json"))
				throw new Exception("please remname settings-example.json to settings.json");

			using var fs = new FileStream("settings.json", FileMode.Open, FileAccess.Read);

			dict = JsonSerializer.Deserialize<Dictionary<string, JsonElement>>(fs);
		}
		if (dict == null || !dict.ContainsKey(Name))
			return default;

		return dict[Name].Deserialize<T>();
	}

	public static string Get(string Name)
	{
		var val = Get<string>(Name);
		return val ?? "<empty>";
	}
}
