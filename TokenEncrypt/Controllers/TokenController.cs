
namespace webTestApi.Controllers;

using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using TokenEncrypt.classes;
using webTestApi.classes;

[ApiController]
[Route("[controller]")]
public class TokenController : ControllerBase
{
    private readonly JwtSettings _jwtSettings;
    private readonly JwtSecurityTokenHandler _tokenHandler = new JwtSecurityTokenHandler();

    public TokenController(IOptions<JwtSettings> jwtSettings)
    {
        _jwtSettings = jwtSettings.Value;
    }

    [HttpPost("generate")]
    public IActionResult GenerateToken([FromBody] TokenRequest request)
    {
        // کلیدها
        var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SigningKey));
        var encryptKey1 = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.EncryptKey1));

        var signingCredentials = new SigningCredentials(signingKey, SecurityAlgorithms.HmacSha256);

        // Claims
        var claims = new List<Claim>
        {
            new Claim(JwtRegisteredClaimNames.Sub, request.Username),
            new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString())
        };
        foreach (var role in request.Roles)
            claims.Add(new Claim(ClaimTypes.Role, role));

        foreach (var claim in request.Claims)
            claims.Add(new Claim("Permision", claim));

        // مرحله 1: JWT Signed
        var signedToken = new JwtSecurityToken(
            issuer: _jwtSettings.Issuer,
            audience: _jwtSettings.Audience,
            claims: claims,
            expires: DateTime.UtcNow.AddHours(1),
            signingCredentials: signingCredentials
        );

        // مرحله 2: Encrypt (JWE)
        var encryptingCredentials1 = new EncryptingCredentials(
            encryptKey1,
            SecurityAlgorithms.Aes256KW,
            SecurityAlgorithms.Aes256CbcHmacSha512
        );

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Issuer = _jwtSettings.Issuer,
            Audience = _jwtSettings.Audience,
            Expires = DateTime.UtcNow.AddHours(1),
            SigningCredentials = signingCredentials,
            EncryptingCredentials = encryptingCredentials1
        };

        var jweToken = _tokenHandler.CreateEncodedJwt(tokenDescriptor);

        return Ok(new { token = jweToken });
    }

    [HttpPost("decrypt")]
    public IActionResult DecryptToken([FromBody] TokenDecryptRequest request)
    {
        var encryptKey1 = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.EncryptKey1));
        var signingKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_jwtSettings.SigningKey));

        var validationParams = new TokenValidationParameters
        {
            ValidateIssuer = true,
            ValidIssuer = _jwtSettings.Issuer,
            ValidateAudience = true,
            ValidAudience = _jwtSettings.Audience,
            ValidateLifetime = true,
            IssuerSigningKey = signingKey,
            TokenDecryptionKey = encryptKey1
        };

        var principal = _tokenHandler.ValidateToken(request.Token, validationParams, out var validatedToken);

        // استخراج Claims
        // ✅ فقط Type و Value رو برمی‌گردون
        var resultClaims = principal.Claims
            .Select(c => new { c.Type, c.Value })
            .ToList();

        return Ok(new { claims = resultClaims });

    }
}
