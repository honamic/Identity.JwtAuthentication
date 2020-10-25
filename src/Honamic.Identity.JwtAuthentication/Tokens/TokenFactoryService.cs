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

namespace Honamic.Identity.JwtAuthentication
{
    public class TokenFactoryService<TUser> : ITokenFactoryService<TUser> where TUser : class
    {
        #region ctor

        private readonly IUserClaimsPrincipalFactory<TUser> _userClaimsPrincipalFactory;
        private readonly IOptions<JwtAuthenticationOptions> _configuration;
        private readonly IOptions<IdentityOptions> _identityOptions;
        private readonly ILogger<TokenFactoryService<TUser>> _logger;
        private readonly string _securityStampClaimType = "";
        private readonly string _userIdClaimType = "";

        public TokenFactoryService(IUserClaimsPrincipalFactory<TUser> userClaimsPrincipalFactory,
            IOptions<JwtAuthenticationOptions> configuration,
            IOptions<IdentityOptions> identityOptions,
            ILogger<TokenFactoryService<TUser>> logger)
        {
            _userClaimsPrincipalFactory = userClaimsPrincipalFactory;

            _configuration = configuration ?? throw new ArgumentNullException(nameof(configuration));
            _identityOptions = identityOptions;
            _logger = logger ?? throw new ArgumentNullException(nameof(logger));
            _securityStampClaimType = _identityOptions.Value.ClaimsIdentity.SecurityStampClaimType;
            _userIdClaimType = _identityOptions.Value.ClaimsIdentity.UserIdClaimType;
        }

        #endregion

        public async Task<(string Token, string RefreshToken)> CreateJwtTokensAsync(TUser user, IEnumerable<Claim> additionalClaims)
        {
            var userPrincipal = await _userClaimsPrincipalFactory.CreateAsync(user);

            var cliams = new List<Claim>(userPrincipal.Identities.First().Claims);

            foreach (var claim in additionalClaims)
            {
                cliams.Add(claim);
            }

            AddIssuClaims(cliams);

            var token = CreateToken(cliams, _configuration.Value.AccessTokenExpirationMinutes);

            var refreshClaims = cliams.Where(t => t.Type == _userIdClaimType || t.Type == _securityStampClaimType || t.Type == "amr").ToList();

            AddIssuClaims(refreshClaims);

            var refreshToken = CreateToken(refreshClaims, _configuration.Value.RefreshTokenExpirationMinutes);


            return (token, refreshToken);
        }

        public string CreateMfaTokenAsync(IEnumerable<Claim> claims)
        {
            return CreateToken(claims, _configuration.Value.MfaTokenExpirationMinutes);
        }

        public (string UserId, string SecurityStamp, string AmrCliam) ValidateAndGetRefreshTokenUserIdAndSecurity(string refreshToken)
        {
            string userId = null;
            string securityStamp = null;
            string amrCliam = null;

            if (string.IsNullOrWhiteSpace(refreshToken))
            {
                return (userId, securityStamp, amrCliam);
            }

            ClaimsPrincipal decodedRefreshTokenPrincipal = null;
            try
            {
                decodedRefreshTokenPrincipal = new JwtSecurityTokenHandler().ValidateToken(
                    refreshToken,
                    new TokenValidationParameters
                    {
                        RequireExpirationTime = true,
                        ValidateIssuer = false,
                        ValidateAudience = false,
                        IssuerSigningKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.Value.SigningKey)),
                        TokenDecryptionKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.Value.EncrtyptKey)),
                        ValidateIssuerSigningKey = true, // verify signature to avoid tampering
                        ValidateLifetime = true, // validate the expiration
                        ClockSkew = TimeSpan.FromSeconds(_configuration.Value.ClockSkewSeconds) // tolerance for the expiration date
                    },
                    out _
                );
            }
            catch (Exception ex)
            {
                _logger.LogError(ex, $"Failed to validate refreshTokenValue: `{refreshToken}`.");
            }

            userId = decodedRefreshTokenPrincipal?.Claims?.FirstOrDefault(t => t.Type == _userIdClaimType)?.Value;

            securityStamp = decodedRefreshTokenPrincipal?.Claims?.FirstOrDefault(t => t.Type == _securityStampClaimType)?.Value;

            amrCliam = decodedRefreshTokenPrincipal?.Claims?.FirstOrDefault(t => t.Type == "amr")?.Value;

            if (amrCliam == null)
            {
                amrCliam = decodedRefreshTokenPrincipal?.Claims?
                    .FirstOrDefault(t => t.Type == "http://schemas.microsoft.com/claims/authnmethodsreferences")?.Value;
            }

            return (userId, securityStamp, amrCliam);
        }

        private string CreateToken(IEnumerable<Claim> claims, int expirationMinutes)
        {
            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.Value.SigningKey));
            var signingCredentials = new SigningCredentials(key, SecurityAlgorithms.HmacSha256);
            EncryptingCredentials encryptCredentials = null;

            if (!string.IsNullOrEmpty(_configuration.Value.EncrtyptKey))
            {
                var encryptionkey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration.Value.EncrtyptKey));
                encryptCredentials = new EncryptingCredentials(encryptionkey, SecurityAlgorithms.Aes128KW, SecurityAlgorithms.Aes128CbcHmacSha256);
            }

            var now = DateTime.UtcNow;

            var descriptor = new SecurityTokenDescriptor
            {
                Issuer = _configuration.Value.Issuer,
                Audience = _configuration.Value.Audience,
                IssuedAt = now,
                NotBefore = now,
                Expires = now.AddMinutes(expirationMinutes),
                SigningCredentials = signingCredentials,
                EncryptingCredentials = encryptCredentials,
                Subject = new ClaimsIdentity(claims)
            };

            var tokenHandler = new JwtSecurityTokenHandler();
            var securityToken = tokenHandler.CreateToken(descriptor);
            var encryptedJwt = tokenHandler.WriteToken(securityToken);

            return encryptedJwt;
        }

        private void AddIssuClaims(List<Claim> cliams)
        {
            var issuer = new Claim(JwtRegisteredClaimNames.Iss,
                _configuration.Value.Issuer,
                ClaimValueTypes.String,
                _configuration.Value.Issuer);

            cliams.Add(issuer);

            var issuedAt = new Claim(JwtRegisteredClaimNames.Iat,
                DateTimeOffset.UtcNow.ToUnixTimeSeconds().ToString(),
                ClaimValueTypes.Integer64,
                _configuration.Value.Issuer);

            cliams.Add(issuedAt);
        }
    }
}