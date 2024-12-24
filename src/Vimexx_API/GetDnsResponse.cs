using System.Text.Json.Serialization;

namespace Vimexx_API;

public class DnsRecords 
{
	[JsonPropertyName("dns_records")]
	public List<DnsRecord> DNSRecords { get; set; } = [];
}

public class GetDNSResponse : Response<DnsRecords>
{
}
