using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Honamic.Identity.JwtAuthentication.Sample.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    [Authorize( AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme + ", Identity.Application")]
    public class RoleController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly RoleManager<IdentityRole> _roleManager;
        private readonly JwtSignInManager<IdentityUser> _jwtSignInManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly ILogger<AuthController> _logger;

        public RoleController(SignInManager<IdentityUser> signInManager,
            ILogger<AuthController> logger,
            UserManager<IdentityUser> userManager,
            RoleManager<IdentityRole> roleManager,
            JwtSignInManager<IdentityUser> jwtSignInManager)
        {
            _userManager = userManager;
            _roleManager = roleManager;
            _jwtSignInManager = jwtSignInManager;
            _signInManager = signInManager;
            _logger = logger;
        }

        [HttpPost("[action]")]
        public async Task<IActionResult> AddRole(string name)
        {
            var result = await _roleManager.CreateAsync(new IdentityRole { Name = name });

            return Ok(result);
        }


    }
}
