
using System.Text.Json.Serialization;

namespace Vimexx_API;
public class DnsRecord
{
	[JsonPropertyName("name")]
	public string Name { get; set; }

	[JsonPropertyName("type")]
	public string Type { get; set; }

	[JsonPropertyName("content")]
	public string Content { get; set; }

	[JsonPropertyName("prio")]
	public string? Prio { get; set; }

	[JsonPropertyName("ttl")]
	public int? TTL { get; set; }
}

