using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Honamic.Identity.Jwt
{
    public interface ITokenFactoryService<TUser> where TUser : class
    {
        Task<(string Token, string RefreshToken)> CreateJwtTokensAsync(TUser user, IEnumerable<Claim> additionalClaims);

        string CreateMfaTokenAsync(IEnumerable<Claim> claims);

        public (string UserId, string SecurityStamp) ValidateAndGetRefreshTokenUserIdAndSecurity(string refreshToken);
    }
}