using System;
using System.Net.Http;
using System.Threading.Tasks;

class Program
{
    static async Task Main(string[] args)
    {
        var url = "https://www.microsoft.com";
        using (var client = new HttpClient())
        {
            var response = await client.GetAsync(url);
            Console.WriteLine($"Response status code: {response.StatusCode}");
        }
    }
}
