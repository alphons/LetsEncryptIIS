

using System.Text.Json.Serialization;

namespace Vimexx_API;

public class Response<T> where T : class
{
	[JsonPropertyName("message")]
	public string? Message { get; set; }

	[JsonPropertyName("result")]
	public bool Result { get; set; }

	[JsonPropertyName("data")]
	public T? Data { get; set; }

}
