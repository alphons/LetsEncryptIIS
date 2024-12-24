
using System.Text.Json.Serialization;

namespace Vimexx_API;

public enum RecordTypeEnum
{
	Unknown,
	A,
	AAAA,
	CNAME,
	MX,
	SRV,
	TLSA,
	TXT,
	CAA
}

public class DnsRecord
{
	[JsonPropertyName("name")]
	public string Name { get; set; } = string.Empty;

	[JsonConverter(typeof(JsonStringEnumConverter))]
	[JsonPropertyName("type")]
	public RecordTypeEnum Type { get; set; }

	[JsonPropertyName("content")]
	public string? Content { get; set; }

	[JsonPropertyName("prio")]
	public string? Prio { get; set; }

	[JsonPropertyName("weight")]
	public int? Weight { get; set; }

	[JsonPropertyName("port")]
	public int? Port { get; set; }

	[JsonPropertyName("ttl")]
	public int? TTL { get; set; }
}

