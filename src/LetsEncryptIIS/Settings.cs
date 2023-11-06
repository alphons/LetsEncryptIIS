
using System.Text.Json;

namespace LetsEncryptIIS;

public static class Settings
{
	private const string FILENAME = "settings.json";
	private static Dictionary<string, JsonElement>? dict;

	public static T? Get<T>(string Name)
	{
		if (dict == null)
		{
			if (!File.Exists(FILENAME))
				throw new Exception($"rename example-{FILENAME} to {FILENAME}");

			using var fs = new FileStream(FILENAME, FileMode.Open, FileAccess.Read);

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
