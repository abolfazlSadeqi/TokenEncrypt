namespace webTestApi.classes;

public class TokenRequest
{
    public string Username { get; set; }
    public List<string> Roles { get; set; } = new();
    public List<string> Claims { get; set; } = new();
}
