using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System.Threading.Tasks;

namespace Honamic.Identity.JwtAuthentication
{
    [ApiController]
    public abstract class AuthController<TUser> : ControllerBase where TUser:class
    {
        protected readonly UserManager<TUser> _userManager;
        protected readonly JwtSignInManager<TUser> _jwtSignInManager;
        protected readonly SignInManager<TUser> _signInManager;
        protected readonly ILogger<AuthController<TUser>> _logger;

        public AuthController(SignInManager<TUser> signInManager,
            ILogger<AuthController<TUser>> logger,
            UserManager<TUser> userManager,
            JwtSignInManager<TUser> jwtSignInManager)
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

        [HttpPost("[action]")]
        [AllowAnonymous]
        public async Task<IActionResult> RefreshToken([FromBody] RefreshTokenViewModel model)
        {
            if (model == null)
            {
                return BadRequest("user is not set.");
            }

            var result = await _jwtSignInManager.RefreshTokenAsync(model.RefreshToken);
 
            return Ok(result);
        }

        [HttpGet("[action]")]
        [Authorize(AuthenticationSchemes = JwtAuthenticationOptions.JwtBearerTwoFactorsScheme)]
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

        [HttpPost("[action]")]
        [Authorize(AuthenticationSchemes = JwtAuthenticationOptions.JwtBearerTwoFactorsScheme)]
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

        [HttpPost("[action]")]
        [Authorize(AuthenticationSchemes = JwtAuthenticationOptions.JwtBearerTwoFactorsScheme)]
        public async Task<IActionResult> TwoFactorSignIn(string provider, string code)
        {
            var result = await _jwtSignInManager.TwoFactorSignInAsync(provider, code, false);
             
            return Ok(result);
        }
    }
}