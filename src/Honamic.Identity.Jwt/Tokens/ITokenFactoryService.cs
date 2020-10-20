using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
using Microsoft.IdentityModel.Tokens;
using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;

namespace Honamic.Identity.Jwt
{
    public class JwtTokensData
    {
        public string AccessToken { get; set; }
        public string RefreshToken { get; set; }
        public string RefreshTokenSerial { get; set; }
        public IEnumerable<Claim> Claims { get; set; }
    }

    public interface ITokenFactoryService<TUser, TRole> where TUser : class where TRole : class
    {
        Task<JwtTokensData> CreateJwtTokensAsync(TUser user, IEnumerable<Claim> additionalClaims);
        string GetRefreshTokenSerial(string refreshTokenValue);

        string CreateMfaTokenAsync(IEnumerable<Claim> claims);
    }

    public class TokenFactoryService<TUser, TRole> : ITokenFactoryService<TUser, TRole>
        where TUser : IdentityUser
        where TRole : class
    {
        private readonly UserClaimsPrincipalFactory<TUser, TRole> _userClaimsPrincipalFactory;

        //private readonly ISecurityService _securityService;
        private readonly IOptionsSnapshot<BearerTokensOptions> _configuration;
        private readonly IRoleStore<TRole> _roleStore;
        private readonly ILogger<TokenFactoryService<TUser, TRole>> _logger;

        public TokenFactoryService(
            UserClaimsPrincipalFactory<TUser, TRole> userClaimsPrincipalFactory,
            //ISecurityService securityService,
            IOptionsSnapshot<BearerTokensOptions> configuration,
            IRoleStore<TRole> roleStore,
            ILogger<TokenFactoryService<TUser, TRole>> logger)
        {
            //_securityService = securityService ?? throw new ArgumentNullException(nameof(securityService));

            _roleStore = roleStore ?? throw new ArgumentNullException(nameof(roleStore));
            _userClaimsPrincipalFactory = userClaimsPrincipalFactory;
            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));

            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
        }

        public async Task<JwtTokensData> CreateJwtTokensAsync(TUser user, IEnumerable<Claim> additionalClaims)
        {
            var (accessToken, claims) = await createAccessTokenAsync(user,additionalClaims);
            var (refreshTokenValue, refreshTokenSerial) = createRefreshToken();
            return new JwtTokensData
            {
                AccessToken = accessToken,
                RefreshToken = refreshTokenValue,
                RefreshTokenSerial = refreshTokenSerial,
                Claims = claims
            };
        }

        public  string  CreateMfaTokenAsync( IEnumerable<Claim> claims)
        { 
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.Value.Key));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var now = DateTime.UtcNow;
            var token = new JwtSecurityToken(
                issuer: _configuration.Value.Issuer,
                audience: _configuration.Value.Audience,
                claims: claims,
                notBefore: now,
                expires: now.AddMinutes(_configuration.Value.MfaTokenExpirationMinutes),
                signingCredentials: creds);

            var tokenString = new JwtSecurityTokenHandler().WriteToken(token);

            return tokenString;
        }

        private (string RefreshTokenValue, string RefreshTokenSerial) createRefreshToken()
        {
            var refreshTokenSerial = Guid.NewGuid().ToString().Replace("-", "");

            var claims = new List<Claim>
            {
                // Unique Id for all Jwt tokes
                new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid() .ToString(), ClaimValueTypes.String, _configuration.Value.Issuer),
                // Issuer
                new Claim(JwtRegisteredClaimNames.Iss, _configuration.Value.Issuer, ClaimValueTypes.String, _configuration.Value.Issuer),
                // Issued at
                new Claim(JwtRegisteredClaimNames.Iat, DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(), ClaimValueTypes.Integer64, _configuration.Value.Issuer),
                // for invalidation
                new Claim(ClaimTypes.SerialNumber, refreshTokenSerial, ClaimValueTypes.String, _configuration.Value.Issuer)
            };
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.Value.Key));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var now = DateTime.UtcNow;
            var token = new JwtSecurityToken(
                issuer: _configuration.Value.Issuer,
                audience: _configuration.Value.Audience,
                claims: claims,
                notBefore: now,
                expires: now.AddMinutes(_configuration.Value.RefreshTokenExpirationMinutes),
                signingCredentials: creds);
            var refreshTokenValue = new JwtSecurityTokenHandler().WriteToken(token);
            return (refreshTokenValue, refreshTokenSerial);
        }

        public string GetRefreshTokenSerial(string refreshTokenValue)
        {
            if (string.IsNullOrWhiteSpace(refreshTokenValue))
            {
                return null;
            }

            ClaimsPrincipal decodedRefreshTokenPrincipal = null;
            try
            {
                decodedRefreshTokenPrincipal = new JwtSecurityTokenHandler().ValidateToken(
                    refreshTokenValue,
                    new TokenValidationParameters
                    {
                        RequireExpirationTime = true,
                        ValidateIssuer = false,
                        ValidateAudience = false,
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.Value.Key)),
                        ValidateIssuerSigningKey = true, // verify signature to avoid tampering
                        ValidateLifetime = true, // validate the expiration
                        ClockSkew = TimeSpan.Zero // tolerance for the expiration date
                    },
                    out _
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Failed to validate refreshTokenValue: `{refreshTokenValue}`.");
            }

            return decodedRefreshTokenPrincipal?.Claims?.FirstOrDefault(c => c.Type == ClaimTypes.SerialNumber)?.Value;
        }

        private async System.Threading.Tasks.Task<(string AccessToken, IEnumerable<Claim> Claims)> createAccessTokenAsync(TUser user, IEnumerable<Claim> additionalClaims)
        {

            var userPrincipal = await _userClaimsPrincipalFactory.CreateAsync(user);

            foreach (var claim in additionalClaims)
            {
                userPrincipal.Identities.First().AddClaim(claim);
            }


            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.Value.Key));
            var creds = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            var now = DateTime.UtcNow;
            var token = new JwtSecurityToken(
                issuer: _configuration.Value.Issuer,
                audience: _configuration.Value.Audience,
                claims: userPrincipal.Claims,
                notBefore: now,
                expires: now.AddMinutes(_configuration.Value.AccessTokenExpirationMinutes),
                signingCredentials: creds);
            return (new JwtSecurityTokenHandler().WriteToken(token), userPrincipal.Claims);
        }
    }
}
