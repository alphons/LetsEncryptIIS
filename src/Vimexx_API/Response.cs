

namespace Vimexx_API;

public class Response<T>
{
	public string message { get; set; }
	public bool result { get; set; }
	public T data { get; set; }

}
