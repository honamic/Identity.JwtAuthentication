using Moq;
using Xunit;
using System;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Identity.Test;
using System.IdentityModel.Tokens.Jwt;

namespace Honamic.Identity.JwtAuthentication.Test
{
    public partial class JwtSignInManagerTest
    {
        static JwtSignInManagerTest()
        {
            Microsoft.IdentityModel.Logging.IdentityModelEventSource.ShowPII = true;
        }


        [Fact]
        public void ConstructorNullChecks()
        {
            Assert.Throws<ArgumentNullException>("userManager", () => new JwtSignInManager<PocoUser>(null, null, null, null, null, null, null));
            var userManager = MockHelpers.MockUserManager<PocoUser>().Object;
            Assert.Throws<ArgumentNullException>("contextAccessor", () => new JwtSignInManager<PocoUser>(userManager, null, null, null, null, null, null));

        }

        [Fact]
        public async Task CheckPasswordAlwaysResetLockoutWhenQuirked()
        {
            AppContext.SetSwitch("Microsoft.AspNetCore.Identity.CheckPasswordSignInAlwaysResetLockoutOnSuccess", true);

            // Setup
            var user = new PocoUser { UserName = "Foo" };
            var manager = SetupUserManager(user);
            manager.Setup(m => m.SupportsUserLockout).Returns(true).Verifiable();
            manager.Setup(m => m.IsLockedOutAsync(user)).ReturnsAsync(false).Verifiable();
            manager.Setup(m => m.CheckPasswordAsync(user, "password")).ReturnsAsync(true).Verifiable();
            manager.Setup(m => m.ResetAccessFailedCountAsync(user)).ReturnsAsync(IdentityResult.Success).Verifiable();

            var context = new DefaultHttpContext();
            var helper = SetupSignInManager(manager.Object, context);

            // Act
            var result = await helper.CheckPasswordSignInAsync(user, "password", false);

            // Assert
            Assert.True(result.Succeeded);
            manager.Verify();

            AppContext.SetSwitch("Microsoft.AspNetCore.Identity.CheckPasswordSignInAlwaysResetLockoutOnSuccess", false);
        }


        private static Mock<UserManager<PocoUser>> SetupUserManager(PocoUser user)
        {
            var manager = MockHelpers.MockUserManager<PocoUser>();
            manager.Setup(m => m.FindByNameAsync(user.UserName)).ReturnsAsync(user);
            manager.Setup(m => m.FindByIdAsync(user.Id)).ReturnsAsync(user);
            manager.Setup(m => m.GetUserIdAsync(user)).ReturnsAsync(user.Id.ToString());
            manager.Setup(m => m.GetUserNameAsync(user)).ReturnsAsync(user.UserName);
            return manager;
        }


        private static JwtSignInManager<PocoUser> SetupSignInManager(UserManager<PocoUser> manager, HttpContext context, ILogger logger = null, IdentityOptions identityOptions = null, IAuthenticationSchemeProvider schemeProvider = null)
        {
            var contextAccessor = new Mock<IHttpContextAccessor>();
            contextAccessor.Setup(a => a.HttpContext).Returns(context);
            var roleManager = MockHelpers.MockRoleManager<PocoRole>();
            identityOptions = identityOptions ?? new IdentityOptions();
            var options = new Mock<IOptions<IdentityOptions>>();
            options.Setup(a => a.Value).Returns(identityOptions);
            var claimsFactory = new UserClaimsPrincipalFactory<PocoUser, PocoRole>(manager, roleManager.Object, options.Object);
            schemeProvider = schemeProvider ?? new Mock<IAuthenticationSchemeProvider>().Object;

            //news
            var jwtOptions = OptionsHelpers.Default;
            var jwtIOptions = new Mock<IOptions<JwtAuthenticationOptions>>();
            jwtIOptions.Setup(a => a.Value).Returns(jwtOptions);
            var tokenfactoryLogger = new TestLogger<TokenFactoryService<PocoUser>>();
            var tokenfactory = new TokenFactoryService<PocoUser>(claimsFactory, jwtIOptions.Object, options.Object, tokenfactoryLogger);


            var sm = new JwtSignInManager<PocoUser>(manager, contextAccessor.Object, options.Object, null, schemeProvider, new DefaultUserConfirmation<PocoUser>(), tokenfactory);
            sm.Logger = logger ?? NullLogger<JwtSignInManager<PocoUser>>.Instance;
            return sm;
        }

        private Mock<IAuthenticationService> MockAuth(HttpContext context)
        {
            var auth = new Mock<IAuthenticationService>();
            context.RequestServices = new ServiceCollection().AddSingleton(auth.Object).BuildServiceProvider();
            return auth;
        }

        private static void SetupSignIn(HttpContext context, Mock<IAuthenticationService> auth, string userId = null, bool? isPersistent = null, string loginProvider = null, string amr = null)
        {
            return;

            auth.Setup(a => a.SignInAsync(context,
                IdentityConstants.ApplicationScheme,
                It.Is<ClaimsPrincipal>(id =>
                    (userId == null || id.FindFirstValue(ClaimTypes.NameIdentifier) == userId) &&
                    (loginProvider == null || id.FindFirstValue(ClaimTypes.AuthenticationMethod) == loginProvider) &&
                    (amr == null || id.FindFirstValue("amr") == amr)),
                It.Is<AuthenticationProperties>(v => isPersistent == null || v.IsPersistent == isPersistent))).Returns(Task.FromResult(0)).Verifiable();
        }


        public bool VerifyToken(string token, string userId = null, bool? isPersistent = null, string loginProvider = null, string amr = null)
        {
            var securityToken = ReadToken(token);

            var userIdvalidate = userId == null
                || securityToken.Claims.First(claim => claim.Type == "nameid").Value == userId;

            var loginProviderValidate = loginProvider == null
                || securityToken.Claims.First(claim => claim.Type == ClaimTypes.AuthenticationMethod).Value == loginProvider;

            var amrValidate = amr == null
                || securityToken.Claims.First(claim => claim.Type == "amr").Value == amr;

            return userIdvalidate && loginProviderValidate && amrValidate;

        }

        public bool VerifyRefreshToken(string token, string userId = null, bool? isPersistent = null, string loginProvider = null, string amr = null)
        {
            var securityToken = ReadToken(token);

            var userIdvalidate = userId == null
                || securityToken.Claims.First(claim => claim.Type == "nameid").Value == userId;

            var loginProviderValidate = loginProvider == null
                || securityToken.Claims.First(claim => claim.Type == ClaimTypes.AuthenticationMethod).Value == loginProvider;

            var amrValidate = amr == null
                || securityToken.Claims.First(claim => claim.Type == "amr").Value == amr;

            return userIdvalidate && loginProviderValidate && amrValidate;

        }

        public JwtSecurityToken ReadToken(string token)
        {
            var tokenHandler = new JwtSecurityTokenHandler();

            var securityToken = tokenHandler.ReadToken(token) as JwtSecurityToken;

            return securityToken;
        }

    }
}