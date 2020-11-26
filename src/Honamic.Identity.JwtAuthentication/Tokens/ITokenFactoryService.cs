using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;

namespace Honamic.Identity.JwtAuthentication
{
    public interface ITokenFactoryService<TUser> where TUser : class
    {
        Task<CreateJwtTokenResult> CreateJwtTokensAsync(TUser user, IEnumerable<Claim> additionalClaims);

        string CreateMfaTokenAsync(IEnumerable<Claim> claims);

        public (string UserId, string SecurityStamp,string AmrCliam) ValidateAndGetRefreshTokenUserIdAndSecurity(string refreshToken);
    }
}