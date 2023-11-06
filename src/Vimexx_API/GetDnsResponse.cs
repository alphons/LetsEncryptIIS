
using System.Collections.Generic;

namespace Vimexx_API;

public class DnsRecords 
{
	public List<DnsRecord> dns_records { get; set; }
}

public class GetDNSResponse : Response<DnsRecords>
{
}
