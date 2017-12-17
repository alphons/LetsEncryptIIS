using System;

namespace LetsEncryptIIS
{
	class Program
	{
		static void Main(string[] args)
		{
			EncryptARRControl.RefreshCertificate();
		}
	}
}
