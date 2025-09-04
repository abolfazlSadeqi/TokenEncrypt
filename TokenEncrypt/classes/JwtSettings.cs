namespace TokenEncrypt.classes
{
    public class JwtSettings
    {
        public string Issuer { get; set; }
        public string Audience { get; set; }
        public string SigningKey { get; set; }
        public string EncryptKey1 { get; set; }
    }

}
