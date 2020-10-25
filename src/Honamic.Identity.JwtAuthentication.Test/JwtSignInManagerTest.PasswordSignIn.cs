using Moq;
using Xunit;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Options;
using Microsoft.AspNetCore.Identity.Test;

namespace Honamic.Identity.JwtAuthentication.Test
{
    public partial class JwtSignInManagerTest
    {
        [Fact]
        public async Task PasswordSignInReturnsLockedOutWhenLockedOut()
        {
            // Setup
            var user = new PocoUser { UserName = "Foo" };
            var manager = SetupUserManager(user);
            manager.Setup(m => m.SupportsUserLockout).Returns(true).Verifiable();
            manager.Setup(m => m.IsLockedOutAsync(user)).ReturnsAsync(true).Verifiable();

            var context = new Mock<HttpContext>();
            var contextAccessor = new Mock<IHttpContextAccessor>();
            contextAccessor.Setup(a => a.HttpContext).Returns(context.Object);
            var roleManager = MockHelpers.MockRoleManager<PocoRole>();
            var identityOptions = new IdentityOptions();
            var options = new Mock<IOptions<IdentityOptions>>();
            options.Setup(a => a.Value).Returns(identityOptions);
            var claimsFactory = new UserClaimsPrincipalFactory<PocoUser, PocoRole>(manager.Object, roleManager.Object, options.Object);
            var logger = new TestLogger<JwtSignInManager<PocoUser>>();

            //news
            var jwtOptions = OptionsHelpers.Default;
            var jwtIOptions = new Mock<IOptions<JwtAuthenticationOptions>>();
            jwtIOptions.Setup(a => a.Value).Returns(jwtOptions);
            var tokenfactoryLogger = new TestLogger<TokenFactoryService<PocoUser>>();
            var tokenfactory = new TokenFactoryService<PocoUser>(claimsFactory, jwtIOptions.Object, options.Object, tokenfactoryLogger);

            var helper = new JwtSignInManager<PocoUser>(manager.Object, contextAccessor.Object, options.Object, logger,
                new Mock<IAuthenticationSchemeProvider>().Object, new DefaultUserConfirmation<PocoUser>(), tokenfactory);

            // Act
            var result = await helper.PasswordSignInAsync(user.UserName, "bogus", false, false);

            // Assert
            Assert.False(result.Succeeded);
            Assert.True(result.IsLockedOut);
            //Assert.Contains($"User {user.Id} is currently locked out.", logger.LogMessages);
            Assert.Contains($"User is currently locked out.", logger.LogMessages);
            manager.Verify();
        }


        [Fact]
        public async Task CheckPasswordSignInReturnsLockedOutWhenLockedOut()
        {
            // Setup
            var user = new PocoUser { UserName = "Foo" };
            var manager = SetupUserManager(user);
            manager.Setup(m => m.SupportsUserLockout).Returns(true).Verifiable();
            manager.Setup(m => m.IsLockedOutAsync(user)).ReturnsAsync(true).Verifiable();

            var context = new Mock<HttpContext>();
            var contextAccessor = new Mock<IHttpContextAccessor>();
            contextAccessor.Setup(a => a.HttpContext).Returns(context.Object);
            var roleManager = MockHelpers.MockRoleManager<PocoRole>();
            var identityOptions = new IdentityOptions();
            var options = new Mock<IOptions<IdentityOptions>>();
            options.Setup(a => a.Value).Returns(identityOptions);
            var claimsFactory = new UserClaimsPrincipalFactory<PocoUser, PocoRole>(manager.Object, roleManager.Object, options.Object);
            var logger = new TestLogger<JwtSignInManager<PocoUser>>();

            //news
            var jwtOptions = OptionsHelpers.Default;
            var jwtIOptions = new Mock<IOptions<JwtAuthenticationOptions>>();
            jwtIOptions.Setup(a => a.Value).Returns(jwtOptions);
            var tokenfactoryLogger = new TestLogger<TokenFactoryService<PocoUser>>();
            var tokenfactory = new TokenFactoryService<PocoUser>(claimsFactory, jwtIOptions.Object, options.Object, tokenfactoryLogger);

            var helper = new JwtSignInManager<PocoUser>(manager.Object, contextAccessor.Object,  options.Object, logger, new Mock<IAuthenticationSchemeProvider>().Object, new DefaultUserConfirmation<PocoUser>(), tokenfactory);

            // Act
            var result = await helper.CheckPasswordSignInAsync(user, "bogus", false);

            // Assert
            Assert.False(result.Succeeded);
            Assert.True(result.IsLockedOut);
            Assert.Contains($"User is currently locked out.", logger.LogMessages);
            manager.Verify();
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public async Task CheckPasswordOnlyResetLockoutWhenTfaNotEnabled(bool tfaEnabled)
        {
            // Setup
            var user = new PocoUser { UserName = "Foo" };
            var manager = SetupUserManager(user);
            manager.Setup(m => m.SupportsUserLockout).Returns(true).Verifiable();
            manager.Setup(m => m.IsLockedOutAsync(user)).ReturnsAsync(false).Verifiable();
            manager.Setup(m => m.SupportsUserTwoFactor).Returns(tfaEnabled).Verifiable();
            manager.Setup(m => m.CheckPasswordAsync(user, "password")).ReturnsAsync(true).Verifiable();

            if (tfaEnabled)
            {
                manager.Setup(m => m.GetTwoFactorEnabledAsync(user)).ReturnsAsync(true).Verifiable();
                manager.Setup(m => m.GetValidTwoFactorProvidersAsync(user)).ReturnsAsync(new string[1] { "Fake" }).Verifiable();
            }
            else
            {
                manager.Setup(m => m.ResetAccessFailedCountAsync(user)).ReturnsAsync(IdentityResult.Success).Verifiable();
            }

            var context = new DefaultHttpContext();
            var helper = SetupSignInManager(manager.Object, context);

            // Act
            var result = await helper.CheckPasswordSignInAsync(user, "password", false);

            // Assert
            Assert.True(result.Succeeded);
            manager.Verify();
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public async Task CanPasswordSignIn(bool isPersistent)
        {
            // Setup
            var user = new PocoUser { UserName = "Foo" };
            var manager = SetupUserManager(user);
            manager.Setup(m => m.SupportsUserLockout).Returns(true).Verifiable();
            manager.Setup(m => m.IsLockedOutAsync(user)).ReturnsAsync(false).Verifiable();
            manager.Setup(m => m.CheckPasswordAsync(user, "password")).ReturnsAsync(true).Verifiable();
            var context = new DefaultHttpContext();
            var helper = SetupSignInManager(manager.Object, context);

            // Act
            var result = await helper.PasswordSignInAsync(user.UserName, "password", isPersistent, false);

            // Assert
            Assert.True(result.Succeeded);
            Assert.True(VerifyToken(result.Token, user.Id, isPersistent, loginProvider: null, amr: "pwd"));
            Assert.True(VerifyRefreshToken(result.RefreshToken, user.Id, isPersistent, loginProvider: null, amr: "pwd"));

            manager.Verify();
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public async Task PasswordSignInRequiresVerification(bool supportsLockout)
        {
            // Setup
            var user = new PocoUser { UserName = "Foo" };
            var manager = SetupUserManager(user);
            manager.Setup(m => m.SupportsUserLockout).Returns(supportsLockout).Verifiable();
            if (supportsLockout)
            {
                manager.Setup(m => m.IsLockedOutAsync(user)).ReturnsAsync(false).Verifiable();
            }
            IList<string> providers = new List<string>();
            providers.Add("PhoneNumber");
            manager.Setup(m => m.GetValidTwoFactorProvidersAsync(user)).Returns(Task.FromResult(providers)).Verifiable();
            manager.Setup(m => m.SupportsUserTwoFactor).Returns(true).Verifiable();
            manager.Setup(m => m.GetTwoFactorEnabledAsync(user)).ReturnsAsync(true).Verifiable();
            manager.Setup(m => m.CheckPasswordAsync(user, "password")).ReturnsAsync(true).Verifiable();
            manager.Setup(m => m.GetValidTwoFactorProvidersAsync(user)).ReturnsAsync(new string[1] { "Fake" }).Verifiable();
            var context = new DefaultHttpContext();
            var helper = SetupSignInManager(manager.Object, context);

            // Act
            var result = await helper.PasswordSignInAsync(user.UserName, "password", false, false);

            // Assert
            Assert.False(result.Succeeded);
            Assert.True(result.RequiresTwoFactor);

            var securityToken = ReadToken(result.TwoFactorToken);
            var UserIdcliam = securityToken.Claims.First(claim => claim.Type == "unique_name");

            Assert.Equal(UserIdcliam.Value, user.Id);
            manager.Verify();
        }

        [Fact]
        public async Task CanPasswordSignInWithNoLogger()
        {
            // Setup
            var user = new PocoUser { UserName = "Foo" };
            var manager = SetupUserManager(user);
            manager.Setup(m => m.SupportsUserLockout).Returns(true).Verifiable();
            manager.Setup(m => m.IsLockedOutAsync(user)).ReturnsAsync(false).Verifiable();
            manager.Setup(m => m.CheckPasswordAsync(user, "password")).ReturnsAsync(true).Verifiable();

            var context = new DefaultHttpContext();

            var helper = SetupSignInManager(manager.Object, context);

            // Act
            var result = await helper.PasswordSignInAsync(user.UserName, "password", false, false);

            // Assert
            Assert.True(result.Succeeded);
            manager.Verify();
            Assert.True(VerifyToken(result.Token, user.Id, null, loginProvider: null, amr: "pwd"));
            Assert.True(VerifyRefreshToken(result.RefreshToken, user.Id, null, loginProvider: null, amr: "pwd"));
        }


        [Fact]
        public async Task PasswordSignInWorksWithNonTwoFactorStore()
        {
            // Setup
            var user = new PocoUser { UserName = "Foo" };
            var manager = SetupUserManager(user);
            manager.Setup(m => m.SupportsUserLockout).Returns(true).Verifiable();
            manager.Setup(m => m.IsLockedOutAsync(user)).ReturnsAsync(false).Verifiable();
            manager.Setup(m => m.CheckPasswordAsync(user, "password")).ReturnsAsync(true).Verifiable();
            manager.Setup(m => m.ResetAccessFailedCountAsync(user)).ReturnsAsync(IdentityResult.Success).Verifiable();

            var context = new DefaultHttpContext();
            var auth = MockAuth(context);
            SetupSignIn(context, auth);
            var helper = SetupSignInManager(manager.Object, context);

            // Act
            var result = await helper.PasswordSignInAsync(user.UserName, "password", false, false);

            // Assert
            Assert.True(result.Succeeded);
            manager.Verify();
            auth.Verify();
        }





        [Fact]
        public async Task PasswordSignInFailsWithWrongPassword()
        {
            // Setup
            var user = new PocoUser { UserName = "Foo" };
            var manager = SetupUserManager(user);
            manager.Setup(m => m.SupportsUserLockout).Returns(true).Verifiable();
            manager.Setup(m => m.IsLockedOutAsync(user)).ReturnsAsync(false).Verifiable();
            manager.Setup(m => m.CheckPasswordAsync(user, "bogus")).ReturnsAsync(false).Verifiable();
            var context = new Mock<HttpContext>();
            var logger = new TestLogger<JwtSignInManager<PocoUser>>();
            var helper = SetupSignInManager(manager.Object, context.Object, logger);

            // Act
            var result = await helper.PasswordSignInAsync(user.UserName, "bogus", false, false);
            var checkResult = await helper.CheckPasswordSignInAsync(user, "bogus", false);

            // Assert
            Assert.False(result.Succeeded);
            Assert.False(checkResult.Succeeded);
            Assert.Contains($"User failed to provide the correct password.", logger.LogMessages);
            manager.Verify();
            context.Verify();
        }

        [Fact]
        public async Task PasswordSignInFailsWithUnknownUser()
        {
            // Setup
            var manager = MockHelpers.MockUserManager<PocoUser>();
            manager.Setup(m => m.FindByNameAsync("bogus")).ReturnsAsync(default(PocoUser)).Verifiable();
            var context = new Mock<HttpContext>();
            var helper = SetupSignInManager(manager.Object, context.Object);

            // Act
            var result = await helper.PasswordSignInAsync("bogus", "bogus", false, false);

            // Assert
            Assert.False(result.Succeeded);
            manager.Verify();
            context.Verify();
        }

        [Fact]
        public async Task PasswordSignInFailsWithWrongPasswordCanAccessFailedAndLockout()
        {
            // Setup
            var user = new PocoUser { UserName = "Foo" };
            var manager = SetupUserManager(user);
            var lockedout = false;
            manager.Setup(m => m.AccessFailedAsync(user)).Returns(() =>
            {
                lockedout = true;
                return Task.FromResult(IdentityResult.Success);
            }).Verifiable();
            manager.Setup(m => m.SupportsUserLockout).Returns(true).Verifiable();
            manager.Setup(m => m.IsLockedOutAsync(user)).Returns(() => Task.FromResult(lockedout));
            manager.Setup(m => m.CheckPasswordAsync(user, "bogus")).ReturnsAsync(false).Verifiable();
            var context = new Mock<HttpContext>();
            var helper = SetupSignInManager(manager.Object, context.Object);

            // Act
            var result = await helper.PasswordSignInAsync(user.UserName, "bogus", false, true);

            // Assert
            Assert.False(result.Succeeded);
            Assert.True(result.IsLockedOut);
            manager.Verify();
        }

        [Fact]
        public async Task CheckPasswordSignInFailsWithWrongPasswordCanAccessFailedAndLockout()
        {
            // Setup
            var user = new PocoUser { UserName = "Foo" };
            var manager = SetupUserManager(user);
            var lockedout = false;
            manager.Setup(m => m.AccessFailedAsync(user)).Returns(() =>
            {
                lockedout = true;
                return Task.FromResult(IdentityResult.Success);
            }).Verifiable();
            manager.Setup(m => m.SupportsUserLockout).Returns(true).Verifiable();
            manager.Setup(m => m.IsLockedOutAsync(user)).Returns(() => Task.FromResult(lockedout));
            manager.Setup(m => m.CheckPasswordAsync(user, "bogus")).ReturnsAsync(false).Verifiable();
            var context = new Mock<HttpContext>();
            var helper = SetupSignInManager(manager.Object, context.Object);

            // Act
            var result = await helper.CheckPasswordSignInAsync(user, "bogus", true);

            // Assert
            Assert.False(result.Succeeded);
            Assert.True(result.IsLockedOut);
            manager.Verify();
        }

        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public async Task CanRequireConfirmedEmailForPasswordSignIn(bool confirmed)
        {
            // Setup
            var user = new PocoUser { UserName = "Foo" };
            var manager = SetupUserManager(user);
            manager.Setup(m => m.IsEmailConfirmedAsync(user)).ReturnsAsync(confirmed).Verifiable();
            if (confirmed)
            {
                manager.Setup(m => m.CheckPasswordAsync(user, "password")).ReturnsAsync(true).Verifiable();
            }
            var context = new DefaultHttpContext();
            var auth = MockAuth(context);
            if (confirmed)
            {
                manager.Setup(m => m.CheckPasswordAsync(user, "password")).ReturnsAsync(true).Verifiable();
                SetupSignIn(context, auth, user.Id, isPersistent: null, loginProvider: null, amr: "pwd");
            }
            var identityOptions = new IdentityOptions();
            identityOptions.SignIn.RequireConfirmedEmail = true;
            var logger = new TestLogger<JwtSignInManager<PocoUser>>();
            var helper = SetupSignInManager(manager.Object, context, logger, identityOptions);

            // Act
            var result = await helper.PasswordSignInAsync(user, "password", false, false);

            // Assert

            Assert.Equal(confirmed, result.Succeeded);
            Assert.NotEqual(confirmed, result.IsNotAllowed);

            var message = "User cannot sign in without a confirmed email.";
            if (!confirmed)
            {
                Assert.Contains(message, logger.LogMessages);
            }
            else
            {
                Assert.DoesNotContain(message, logger.LogMessages);
            }

            manager.Verify();
            auth.Verify();
        }



        [Theory]
        [InlineData(true)]
        [InlineData(false)]
        public async Task CanRequireConfirmedPhoneNumberForPasswordSignIn(bool confirmed)
        {
            // Setup
            var user = new PocoUser { UserName = "Foo" };
            var manager = SetupUserManager(user);
            manager.Setup(m => m.IsPhoneNumberConfirmedAsync(user)).ReturnsAsync(confirmed).Verifiable();
            var context = new DefaultHttpContext();
            var auth = MockAuth(context);
            if (confirmed)
            {
                manager.Setup(m => m.CheckPasswordAsync(user, "password")).ReturnsAsync(true).Verifiable();
                SetupSignIn(context, auth, user.Id, isPersistent: null, loginProvider: null, amr: "pwd");
            }

            var identityOptions = new IdentityOptions();
            identityOptions.SignIn.RequireConfirmedPhoneNumber = true;
            var logger = new TestLogger<JwtSignInManager<PocoUser>>();
            var helper = SetupSignInManager(manager.Object, context, logger, identityOptions);

            // Act
            var result = await helper.PasswordSignInAsync(user, "password", false, false);

            // Assert
            Assert.Equal(confirmed, result.Succeeded);
            Assert.NotEqual(confirmed, result.IsNotAllowed);

            var message = $"User cannot sign in without a confirmed phone number.";
            if (!confirmed)
            {
                Assert.Contains(message, logger.LogMessages);
            }
            else
            {
                Assert.DoesNotContain(message, logger.LogMessages);
            }

            manager.Verify();
            auth.Verify();
        }


    }
}
