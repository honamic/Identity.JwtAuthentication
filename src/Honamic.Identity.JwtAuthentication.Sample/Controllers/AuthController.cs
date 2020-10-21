using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Linq;
using System.Threading.Tasks;

namespace Honamic.Identity.JwtAuthentication.Sample.Controllers
{
    [Route("api/[controller]")]
    public class AuthController : AuthController<IdentityUser>
    {
        public AuthController(SignInManager<IdentityUser> signInManager,
            ILogger<AuthController<IdentityUser>> logger,
            UserManager<IdentityUser> userManager,
            JwtSignInManager<IdentityUser> jwtSignInManager) :
            base(signInManager, logger, userManager, jwtSignInManager)
        {

        }

        [HttpGet("[action]")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme + ", Identity.Application")]
        public IActionResult SimultaneousCookieAndJwtSupportTest()
        {
            return Ok(GetCurrentUserInfo());
        }

        [HttpGet("[action]")]
        [Authorize(AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public IActionResult MyUserInfoTest()
        {
            return Ok(GetCurrentUserInfo());
        }

        private object GetCurrentUserInfo()
        {
            return new
            {
                HttpContext.User.Identity.Name,
                claims = HttpContext.User.Claims.Select(c => new { c.Type, c.Value })
            };

        }
    }
}
