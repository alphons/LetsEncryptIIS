

using System.Text.Json.Serialization;

namespace Vimexx_API;

internal class AuthToken
{
	[JsonPropertyName("token_type")]
	public string? TokenType { get; set; }

	[JsonPropertyName("expires_in")]
	public int ExpiresIn { get; set; }

	[JsonPropertyName("access_token")]
	public string? AccessToken { get; set; }

	[JsonPropertyName("refresh_token")]
	public string? RefreshToken { get; set; }
}
