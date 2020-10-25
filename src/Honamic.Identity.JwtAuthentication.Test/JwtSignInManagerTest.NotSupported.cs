using Moq;
using Xunit;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;

using Microsoft.AspNetCore.Identity.Test;

namespace Honamic.Identity.JwtAuthentication.Test
{
    public partial class JwtSignInManagerTest
    {

        [Fact(Skip = "Not Implemented")]
        public async Task RememberClientStoresUserId()
        {
            // Setup
            var user = new PocoUser { UserName = "Foo" };
            var manager = SetupUserManager(user);
            var context = new DefaultHttpContext();
            var auth = MockAuth(context);
            var helper = SetupSignInManager(manager.Object, context);
            auth.Setup(a => a.SignInAsync(
                context,
                IdentityConstants.TwoFactorRememberMeScheme,
                It.Is<ClaimsPrincipal>(i => i.FindFirstValue(ClaimTypes.Name) == user.Id
                    && i.Identities.First().AuthenticationType == IdentityConstants.TwoFactorRememberMeScheme),
                It.Is<AuthenticationProperties>(v => v.IsPersistent == true))).Returns(Task.FromResult(0)).Verifiable();


            // Act
            await helper.RememberTwoFactorClientAsync(user);

            // Assert
            manager.Verify();
            auth.Verify();
        }

        [Theory(Skip = "Not Implemented")]
        [InlineData(true)]
        [InlineData(false)]
        public async Task RememberBrowserSkipsTwoFactorVerificationSignIn(bool isPersistent)
        {
            // Setup
            var user = new PocoUser { UserName = "Foo" };
            var manager = SetupUserManager(user);
            manager.Setup(m => m.GetTwoFactorEnabledAsync(user)).ReturnsAsync(true).Verifiable();
            IList<string> providers = new List<string>();
            providers.Add("PhoneNumber");
            manager.Setup(m => m.GetValidTwoFactorProvidersAsync(user)).Returns(Task.FromResult(providers)).Verifiable();
            manager.Setup(m => m.SupportsUserLockout).Returns(true).Verifiable();
            manager.Setup(m => m.SupportsUserTwoFactor).Returns(true).Verifiable();
            manager.Setup(m => m.IsLockedOutAsync(user)).ReturnsAsync(false).Verifiable();
            manager.Setup(m => m.CheckPasswordAsync(user, "password")).ReturnsAsync(true).Verifiable();
            var context = new DefaultHttpContext();

            var auth = MockAuth(context);
            SetupSignIn(context, auth);

            var id = new ClaimsIdentity(IdentityConstants.TwoFactorRememberMeScheme);
            id.AddClaim(new Claim(ClaimTypes.Name, user.Id));
            auth.Setup(a => a.AuthenticateAsync(context, IdentityConstants.TwoFactorRememberMeScheme))
                .ReturnsAsync(AuthenticateResult.Success(new AuthenticationTicket(new ClaimsPrincipal(id), null, IdentityConstants.TwoFactorRememberMeScheme))).Verifiable();
            var helper = SetupSignInManager(manager.Object, context);

            // Act
            var result = await helper.PasswordSignInAsync(user.UserName, "password", isPersistent, false);

            // Assert
            Assert.True(result.Succeeded);
            manager.Verify();
            auth.Verify();
        }



        [Theory(Skip = "Not rewritten for jwt")]
        [InlineData(true, true)]
        [InlineData(true, false)]
        [InlineData(false, true)]
        [InlineData(false, false)]
        public async Task CanTwoFactorRecoveryCodeSignIn(bool supportsLockout, bool externalLogin)
        {
            // Setup
            var user = new PocoUser { UserName = "Foo" };
            const string bypassCode = "someCode";
            var manager = SetupUserManager(user);
            manager.Setup(m => m.SupportsUserLockout).Returns(supportsLockout).Verifiable();
            manager.Setup(m => m.RedeemTwoFactorRecoveryCodeAsync(user, bypassCode)).ReturnsAsync(IdentityResult.Success).Verifiable();
            if (supportsLockout)
            {
                manager.Setup(m => m.ResetAccessFailedCountAsync(user)).ReturnsAsync(IdentityResult.Success).Verifiable();
            }
            var context = new DefaultHttpContext();
            var auth = MockAuth(context);
            var helper = SetupSignInManager(manager.Object, context);
            var twoFactorInfo = new JwtSignInManager<PocoUser>.TwoFactorAuthenticationInfo { UserId = user.Id };
            var loginProvider = "loginprovider";
            var twoFactureToken = helper.StoreTwoFactorInfo(user.Id, externalLogin ? loginProvider : null);

            ClaimsPrincipal twoFactureClaimsPrincipal = null;// read from twoFactureToken

            if (externalLogin)
            {
                auth.Setup(a => a.SignInAsync(context,
                    IdentityConstants.ApplicationScheme,
                    It.Is<ClaimsPrincipal>(i => i.FindFirstValue(ClaimTypes.AuthenticationMethod) == loginProvider
                        && i.FindFirstValue(ClaimTypes.NameIdentifier) == user.Id),
                    It.IsAny<AuthenticationProperties>())).Returns(Task.FromResult(0)).Verifiable();
                auth.Setup(a => a.SignOutAsync(context, IdentityConstants.ExternalScheme, It.IsAny<AuthenticationProperties>())).Returns(Task.FromResult(0)).Verifiable();
                auth.Setup(a => a.SignOutAsync(context, IdentityConstants.TwoFactorUserIdScheme, It.IsAny<AuthenticationProperties>())).Returns(Task.FromResult(0)).Verifiable();
            }
            else
            {
                SetupSignIn(context, auth, user.Id);
            }
            auth.Setup(a => a.AuthenticateAsync(context, IdentityConstants.TwoFactorUserIdScheme))
                .ReturnsAsync(AuthenticateResult.Success(new AuthenticationTicket(twoFactureClaimsPrincipal, null, IdentityConstants.TwoFactorUserIdScheme))).Verifiable();

            // Act
            var result = await helper.TwoFactorRecoveryCodeSignInAsync(bypassCode);

            // Assert
            Assert.True(result.Succeeded);
            manager.Verify();
            auth.Verify();
        }




        [Theory(Skip = "Not rewritten for jwt")]
        [InlineData(null, true, true)]
        [InlineData("Authenticator", false, true)]
        [InlineData("Gooblygook", true, false)]
        [InlineData("--", false, false)]
        public async Task CanTwoFactorAuthenticatorSignIn(string providerName, bool isPersistent, bool rememberClient)
        {
            // Setup
            var user = new PocoUser { UserName = "Foo" };
            const string code = "3123";
            var manager = SetupUserManager(user);
            manager.Setup(m => m.SupportsUserLockout).Returns(true).Verifiable();
            manager.Setup(m => m.VerifyTwoFactorTokenAsync(user, providerName ?? TokenOptions.DefaultAuthenticatorProvider, code)).ReturnsAsync(true).Verifiable();
            manager.Setup(m => m.ResetAccessFailedCountAsync(user)).ReturnsAsync(IdentityResult.Success).Verifiable();

            var context = new DefaultHttpContext();
            var auth = MockAuth(context);
            var helper = SetupSignInManager(manager.Object, context);
            var twoFactorInfo = new JwtSignInManager<PocoUser>.TwoFactorAuthenticationInfo { UserId = user.Id };
            if (providerName != null)
            {
                helper.Options.Tokens.AuthenticatorTokenProvider = providerName;
            }
            var twoFactureToken = helper.StoreTwoFactorInfo(user.Id, null);
            ClaimsPrincipal twoFactureClaimsPrincipal = null;// read from twoFactureToken

            SetupSignIn(context, auth, user.Id, isPersistent);
            auth.Setup(a => a.AuthenticateAsync(context, IdentityConstants.TwoFactorUserIdScheme))
                .ReturnsAsync(AuthenticateResult.Success(new AuthenticationTicket(twoFactureClaimsPrincipal, null, IdentityConstants.TwoFactorUserIdScheme))).Verifiable();
            if (rememberClient)
            {
                auth.Setup(a => a.SignInAsync(context,
                    IdentityConstants.TwoFactorRememberMeScheme,
                    It.Is<ClaimsPrincipal>(i => i.FindFirstValue(ClaimTypes.Name) == user.Id
                        && i.Identities.First().AuthenticationType == IdentityConstants.TwoFactorRememberMeScheme),
                    It.IsAny<AuthenticationProperties>())).Returns(Task.FromResult(0)).Verifiable();
            }

            // Act
            var result = await helper.TwoFactorAuthenticatorSignInAsync(code, rememberClient);

            // Assert
            Assert.True(result.Succeeded);
            manager.Verify();
            auth.Verify();
        }


        [Theory(Skip = "Not rewritten for jwt")]
        [InlineData(true, true)]
        [InlineData(true, false)]
        [InlineData(false, true)]
        [InlineData(false, false)]
        public async Task CanResignIn(
                            // Suppress warning that says theory methods should use all of their parameters.
                            // See comments below about why this isn't used.
#pragma warning disable xUnit1026
                            bool isPersistent,
#pragma warning restore xUnit1026
                            bool externalLogin)
        {
            //// Setup
            //var user = new PocoUser { UserName = "Foo" };
            //var context = new DefaultHttpContext();
            //var auth = MockAuth(context);
            //var loginProvider = "loginprovider";
            //var id = new ClaimsIdentity();
            //if (externalLogin)
            //{
            //    id.AddClaim(new Claim(ClaimTypes.AuthenticationMethod, loginProvider));
            //}
            //// REVIEW: auth changes we lost the ability to mock is persistent
            ////var properties = new AuthenticationProperties { IsPersistent = isPersistent };
            //var authResult = AuthenticateResult.NoResult();
            //auth.Setup(a => a.AuthenticateAsync(context, IdentityConstants.ApplicationScheme))
            //    .Returns(Task.FromResult(authResult)).Verifiable();
            //var manager = SetupUserManager(user);
            //var signInManager = new Mock<JwtSignInManager<PocoUser>>(manager.Object,
            //    new HttpContextAccessor { HttpContext = context },
            //    new Mock<IUserClaimsPrincipalFactory<PocoUser>>().Object,
            //    null, null, new Mock<IAuthenticationSchemeProvider>().Object, null)
            //{ CallBase = true };

            //signInManager.Setup(s => s.SignInWithClaimsAsync(user, It.IsAny<AuthenticationProperties>(), It.IsAny<IEnumerable<Claim>>())).Returns(Task.FromResult(0)).Verifiable();
            //signInManager.Object.Context = context;

            //// Act
            //await signInManager.Object.RefreshSignInAsync(user);

            //// Assert
            //auth.Verify();
            //signInManager.Verify();
        }


        [Theory(Skip = "Not rewritten for jwt")]
        [InlineData(true, true, true, true)]
        [InlineData(true, true, false, true)]
        [InlineData(true, false, true, true)]
        [InlineData(true, false, false, true)]
        [InlineData(false, true, true, true)]
        [InlineData(false, true, false, true)]
        [InlineData(false, false, true, true)]
        [InlineData(false, false, false, true)]
        [InlineData(true, true, true, false)]
        [InlineData(true, true, false, false)]
        [InlineData(true, false, true, false)]
        [InlineData(true, false, false, false)]
        [InlineData(false, true, true, false)]
        [InlineData(false, true, false, false)]
        [InlineData(false, false, true, false)]
        [InlineData(false, false, false, false)]
        public async Task CanTwoFactorSignIn(bool isPersistent, bool supportsLockout, bool externalLogin, bool rememberClient)
        {
            // Setup
            var user = new PocoUser { UserName = "Foo" };
            var manager = SetupUserManager(user);
            var provider = "twofactorprovider";
            var code = "123456";
            manager.Setup(m => m.SupportsUserLockout).Returns(supportsLockout).Verifiable();
            if (supportsLockout)
            {
                manager.Setup(m => m.IsLockedOutAsync(user)).ReturnsAsync(false).Verifiable();
                manager.Setup(m => m.ResetAccessFailedCountAsync(user)).ReturnsAsync(IdentityResult.Success).Verifiable();
            }
            manager.Setup(m => m.VerifyTwoFactorTokenAsync(user, provider, code)).ReturnsAsync(true).Verifiable();
            var context = new DefaultHttpContext();
            var auth = MockAuth(context);
            var helper = SetupSignInManager(manager.Object, context);
            var twoFactorInfo = new JwtSignInManager<PocoUser>.TwoFactorAuthenticationInfo { UserId = user.Id };
            var loginProvider = "loginprovider";
            var twoFactureToken = helper.StoreTwoFactorInfo(user.Id, externalLogin ? loginProvider : null);
            ClaimsPrincipal twoFactureClaimsPrincipal = null;// read from twoFactureToken

            if (externalLogin)
            {
                auth.Setup(a => a.SignInAsync(context,
                    IdentityConstants.ApplicationScheme,
                    It.Is<ClaimsPrincipal>(i => i.FindFirstValue(ClaimTypes.AuthenticationMethod) == loginProvider
                        && i.FindFirstValue("amr") == "mfa"
                        && i.FindFirstValue(ClaimTypes.NameIdentifier) == user.Id),
                    It.IsAny<AuthenticationProperties>())).Returns(Task.FromResult(0)).Verifiable();
                // REVIEW: restore ability to test is persistent
                //It.Is<AuthenticationProperties>(v => v.IsPersistent == isPersistent))).Verifiable();
                auth.Setup(a => a.SignOutAsync(context, IdentityConstants.ExternalScheme, It.IsAny<AuthenticationProperties>())).Returns(Task.FromResult(0)).Verifiable();
                auth.Setup(a => a.SignOutAsync(context, IdentityConstants.TwoFactorUserIdScheme, It.IsAny<AuthenticationProperties>())).Returns(Task.FromResult(0)).Verifiable();
            }
            else
            {
                SetupSignIn(context, auth, user.Id, isPersistent, null, "mfa");
            }
            if (rememberClient)
            {
                auth.Setup(a => a.SignInAsync(context,
                    IdentityConstants.TwoFactorRememberMeScheme,
                    It.Is<ClaimsPrincipal>(i => i.FindFirstValue(ClaimTypes.Name) == user.Id
                        && i.Identities.First().AuthenticationType == IdentityConstants.TwoFactorRememberMeScheme),
                    It.IsAny<AuthenticationProperties>())).Returns(Task.FromResult(0)).Verifiable();
                //It.Is<AuthenticationProperties>(v => v.IsPersistent == true))).Returns(Task.FromResult(0)).Verifiable();
            }
            auth.Setup(a => a.AuthenticateAsync(context, IdentityConstants.TwoFactorUserIdScheme))
                .ReturnsAsync(AuthenticateResult.Success(new AuthenticationTicket(twoFactureClaimsPrincipal, null, IdentityConstants.TwoFactorUserIdScheme))).Verifiable();

            // Act
            var result = await helper.TwoFactorSignInAsync(provider, code, rememberClient);

            // Assert
            Assert.True(result.Succeeded);
            manager.Verify();
            auth.Verify();
        }

        [Fact(Skip = "Not supported on Jwt")]
        public async Task SignOutCallsContextResponseSignOut()
        {
            // Setup
            var manager = MockHelpers.TestUserManager<PocoUser>();
            var context = new DefaultHttpContext();
            var auth = MockAuth(context);
            auth.Setup(a => a.SignOutAsync(context, IdentityConstants.ApplicationScheme, It.IsAny<AuthenticationProperties>())).Returns(Task.FromResult(0)).Verifiable();
            auth.Setup(a => a.SignOutAsync(context, IdentityConstants.TwoFactorUserIdScheme, It.IsAny<AuthenticationProperties>())).Returns(Task.FromResult(0)).Verifiable();
            auth.Setup(a => a.SignOutAsync(context, IdentityConstants.ExternalScheme, It.IsAny<AuthenticationProperties>())).Returns(Task.FromResult(0)).Verifiable();
            var helper = SetupSignInManager(manager, context, null, manager.Options);

            // Act
            await helper.SignOutAsync();

            // Assert
            auth.Verify();
        }





    }
}