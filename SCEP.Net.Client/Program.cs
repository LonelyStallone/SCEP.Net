using System.Net;

byte[] pkcsreq = File.ReadAllBytes("testdata/PKCSReq.der");
string message = Convert.ToBase64String(pkcsreq);

using (HttpClient client = new HttpClient())
{
    // Создание запроса
    var request = new HttpRequestMessage(HttpMethod.Get, @"https://localhost:7235/scep");

    // Добавление параметров запроса
    var parameters = System.Web.HttpUtility.ParseQueryString(string.Empty);
    parameters["operation"] = "PKIOperation";
    parameters["message"] = message;
    request.RequestUri = new Uri(request.RequestUri + "?" + parameters);

    try
    {
        HttpResponseMessage resp = await client.SendAsync(request);

        if (resp.StatusCode != HttpStatusCode.OK)
        {
            // Обработка ошибки статуса
            throw new Exception($"Expected {(int)HttpStatusCode.OK}, got {(int)resp.StatusCode}");
        }
    }
    catch (HttpRequestException ex)
    {
        // Обработка сетевых ошибок
        throw new Exception("HTTP request failed", ex);
    }
}