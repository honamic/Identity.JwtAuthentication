using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.DependencyInjection;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Logging.Abstractions;
using Microsoft.Extensions.Options;
using Moq;
using Xunit;
using Microsoft.AspNetCore.Identity.Test;
using Honamic.Identity.JwtAuthentication;

namespace Honamic.Identity.JwtAuthentication.Test
{
    public partial class JwtSignInManagerTest
    {
        //[Theory]
        //[InlineData(true)]
        //[InlineData(false)]
        //public async Task ExternalSignInRequiresVerificationIfNotBypassed(bool bypass)
        //{
        //    // Setup
        //    var user = new PocoUser { UserName = "Foo" };
        //    const string loginProvider = "login";
        //    const string providerKey = "fookey";
        //    var manager = SetupUserManager(user);
        //    manager.Setup(m => m.SupportsUserLockout).Returns(false).Verifiable();
        //    manager.Setup(m => m.FindByLoginAsync(loginProvider, providerKey)).ReturnsAsync(user).Verifiable();
        //    if (!bypass)
        //    {
        //        IList<string> providers = new List<string>();
        //        providers.Add("PhoneNumber");
        //        manager.Setup(m => m.GetValidTwoFactorProvidersAsync(user)).Returns(Task.FromResult(providers)).Verifiable();
        //        manager.Setup(m => m.SupportsUserTwoFactor).Returns(true).Verifiable();
        //        manager.Setup(m => m.GetTwoFactorEnabledAsync(user)).ReturnsAsync(true).Verifiable();
        //    }
        //    var context = new DefaultHttpContext();
        //    var auth = MockAuth(context);
        //    var helper = SetupSignInManager(manager.Object, context);

        //    if (bypass)
        //    {
        //        SetupSignIn(context, auth, user.Id, false, loginProvider);
        //    }
        //    else
        //    {
        //        auth.Setup(a => a.SignInAsync(context, IdentityConstants.TwoFactorUserIdScheme,
        //            It.Is<ClaimsPrincipal>(id => id.FindFirstValue(ClaimTypes.Name) == user.Id),
        //            It.IsAny<AuthenticationProperties>())).Returns(Task.FromResult(0)).Verifiable();
        //    }

        //    // Act
        //    var result = await helper.ExternalLoginSignInAsync(loginProvider, providerKey, isPersistent: false, bypassTwoFactor: bypass);

        //    // Assert
        //    Assert.Equal(bypass, result.Succeeded);
        //    Assert.Equal(!bypass, result.RequiresTwoFactor);
        //    manager.Verify();
        //    auth.Verify();
        //}

        //[Theory]
        //[InlineData(true, true)]
        //[InlineData(true, false)]
        //[InlineData(false, true)]
        //[InlineData(false, false)]
        //public async Task CanExternalSignIn(bool isPersistent, bool supportsLockout)
        //{
        //    // Setup
        //    var user = new PocoUser { UserName = "Foo" };
        //    const string loginProvider = "login";
        //    const string providerKey = "fookey";
        //    var manager = SetupUserManager(user);
        //    manager.Setup(m => m.SupportsUserLockout).Returns(supportsLockout).Verifiable();
        //    if (supportsLockout)
        //    {
        //        manager.Setup(m => m.IsLockedOutAsync(user)).ReturnsAsync(false).Verifiable();
        //    }
        //    manager.Setup(m => m.FindByLoginAsync(loginProvider, providerKey)).ReturnsAsync(user).Verifiable();

        //    var context = new DefaultHttpContext();
        //    var auth = MockAuth(context);
        //    var helper = SetupSignInManager(manager.Object, context);
        //    SetupSignIn(context, auth, user.Id, isPersistent, loginProvider);

        //    // Act
        //    var result = await helper.ExternalLoginSignInAsync(loginProvider, providerKey, isPersistent);

        //    // Assert
        //    Assert.True(result.Succeeded);
        //    manager.Verify();
        //    auth.Verify();
        //}



        //        [Fact]
        //        public async Task GetExternalLoginInfoAsyncReturnsCorrectProviderDisplayName()
        //        {
        //            // Arrange
        //            var user = new PocoUser { Id = "foo", UserName = "Foo" };
        //            var userManager = SetupUserManager(user);
        //            var context = new DefaultHttpContext();
        //            var identity = new ClaimsIdentity();
        //            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, "bar"));
        //            var principal = new ClaimsPrincipal(identity);
        //            var properties = new AuthenticationProperties();
        //            properties.Items["LoginProvider"] = "blah";
        //            var authResult = AuthenticateResult.Success(new AuthenticationTicket(principal, properties, "blah"));
        //            var auth = MockAuth(context);
        //            auth.Setup(s => s.AuthenticateAsync(context, IdentityConstants.ExternalScheme)).ReturnsAsync(authResult);
        //            var schemeProvider = new Mock<IAuthenticationSchemeProvider>();
        //            var handler = new Mock<IAuthenticationHandler>();
        //            schemeProvider.Setup(s => s.GetAllSchemesAsync())
        //                .ReturnsAsync(new[]
        //                {
        //                    new AuthenticationScheme("blah", "Blah blah", handler.Object.GetType())
        //                });
        //            var signInManager = SetupSignInManager(userManager.Object, context, schemeProvider: schemeProvider.Object);

        //            // Act
        //            var externalLoginInfo = await signInManager.GetExternalLoginInfoAsync();

        //            // Assert
        //            Assert.Equal("Blah blah", externalLoginInfo.ProviderDisplayName);
        //        }



        //        [Fact]
        //        public async Task ExternalLoginInfoAsyncReturnsAuthenticationPropertiesWithCustomValue()
        //        {
        //            // Arrange
        //            var user = new PocoUser { Id = "foo", UserName = "Foo" };
        //            var userManager = SetupUserManager(user);
        //            var context = new DefaultHttpContext();
        //            var identity = new ClaimsIdentity();
        //            identity.AddClaim(new Claim(ClaimTypes.NameIdentifier, "bar"));
        //            var principal = new ClaimsPrincipal(identity);
        //            var properties = new AuthenticationProperties();
        //            properties.Items["LoginProvider"] = "blah";
        //            properties.Items["CustomValue"] = "fizzbuzz";
        //            var authResult = AuthenticateResult.Success(new AuthenticationTicket(principal, properties, "blah"));
        //            var auth = MockAuth(context);
        //            auth.Setup(s => s.AuthenticateAsync(context, IdentityConstants.ExternalScheme)).ReturnsAsync(authResult);
        //            var schemeProvider = new Mock<IAuthenticationSchemeProvider>();
        //            var handler = new Mock<IAuthenticationHandler>();
        //            schemeProvider.Setup(s => s.GetAllSchemesAsync())
        //                .ReturnsAsync(new[]
        //                    {
        //                        new AuthenticationScheme("blah", "Blah blah", handler.Object.GetType())
        //                    });
        //            var signInManager = SetupSignInManager(userManager.Object, context, schemeProvider: schemeProvider.Object);
        //            var externalLoginInfo = await signInManager.GetExternalLoginInfoAsync();

        //            // Act
        //            var externalProperties = externalLoginInfo.AuthenticationProperties;
        //            var customValue = externalProperties?.Items["CustomValue"];

        //            // Assert
        //            Assert.NotNull(externalProperties);
        //            Assert.Equal("fizzbuzz", customValue);
        //        }


    }
}
