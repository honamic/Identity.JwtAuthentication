﻿using Microsoft.AspNetCore.Authentication.Cookies;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Logging;
using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace Honamic.Identity.Jwt.Sample.Controllers
{
    [ApiController]
    [Route("api/[controller]")]
    public class AuthController : ControllerBase
    {
        private readonly UserManager<IdentityUser> _userManager;
        private readonly JwtSignInManager<IdentityUser,IdentityRole> _jwtSignInManager;
        private readonly SignInManager<IdentityUser> _signInManager;
        private readonly ILogger<AuthController> _logger;

        public AuthController(SignInManager<IdentityUser> signInManager,
            ILogger<AuthController> logger,
            UserManager<IdentityUser> userManager,
            JwtSignInManager<IdentityUser, IdentityRole> jwtSignInManager)
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
                model.RememberMe,
                lockoutOnFailure: false, 
                model.TwoFactorRememberMeToken);

            return Ok(result);
        }

        [HttpGet("[action]")]
        public IActionResult UserInfo()
        {
            return Ok(this.HttpContext.User.Identity.Name);
        }

        [HttpGet("[action]")]
        [Authorize(Roles ="Admin",AuthenticationSchemes = JwtBearerDefaults.AuthenticationScheme + ", Identity.Application")]
        public IActionResult UserAdmin()
        {
            return Ok(this.HttpContext.User.Identity.Name);
        }

    }
}
