using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;

namespace Honamic.Identity.Jwt.Sample.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly JwtSignInManager<IdentityUser> _jwtSignInManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly ILogger<AuthController> _logger;

        public AuthController(SignInManager<IdentityUser> signInManager,
            ILogger<AuthController> logger,
            UserManager<IdentityUser> userManager,
            JwtSignInManager<IdentityUser> jwtSignInManager)
        {
            _userManager = userManager;
            _jwtSignInManager = jwtSignInManager;
            _signInManager = signInManager;
            _logger = logger;
        }

        [HttpPost("[action]")]
        [AllowAnonymous]
        public async Task<IActionResult> Login([FromBody] LoginViewModel model)
        {
            var result = await _jwtSignInManager.PasswordSignInAsync(
                model.Email,
                model.Password,
                isPersistent: false,
                lockoutOnFailure: false);

            return Ok(result);
        }

        [HttpGet("[action]")]
        [Authorize(Roles = "Admin", AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme)]
        public IActionResult UserInfo()
        {
            return Ok(this.HttpContext.User.Identity.Name);
        }

        [HttpGet("[action]")]
        [Authorize(Roles = "Admin", AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme + ", Identity.Application")]
        public IActionResult UserAdmin()
        {
            return Ok(this.HttpContext.User.Identity.Name);
        }

        [HttpGet("[action]")]
        [Authorize(AuthenticationSchemes = "bearer.mfa")]
        public async Task<IActionResult> TwoFactorProviders()
        {
            var user = await _jwtSignInManager.GetTwoFactorAuthenticationUserAsync();

            if (user != null)
            {
                var list = await _userManager.GetValidTwoFactorProvidersAsync(user);

                return Ok(list);
            }

            return Unauthorized();
        }

        [HttpGet("[action]")]
        [Authorize(AuthenticationSchemes = "bearer.mfa")]
        public async Task<IActionResult> SendCode(string provider)
        {
            var user = await _jwtSignInManager.GetTwoFactorAuthenticationUserAsync();

            var code = await _userManager.GenerateTwoFactorTokenAsync(user, provider);

            if (code != null)
            {

                return Ok(code);
            }

            return NotFound();
        }

        [HttpGet("[action]")]
        [Authorize(AuthenticationSchemes = "bearer.mfa")]
        public async Task<IActionResult> TwoFactorSignIn(string provider, string code)
        {
            var result = await _jwtSignInManager.TwoFactorSignInAsync(provider, code, false);
             
            return Ok(result);
        }
    }
}
