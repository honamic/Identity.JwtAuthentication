using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;
[assembly: System.Runtime.CompilerServices.InternalsVisibleToAttribute("Honamic.Identity.JwtAuthentication.Test")]

namespace Honamic.Identity.JwtAuthentication
{
    public partial class JwtSignInManager<TUser> where TUser : class
    {
        public JwtSignInManager(UserManager<TUser> userManager,
            IHttpContextAccessor contextAccessor,
            IOptions<IdentityOptions> optionsAccessor,
            ILogger<JwtSignInManager<TUser>> logger,
            IAuthenticationSchemeProvider schemes,
            IUserConfirmation<TUser> confirmation,
            ITokenFactoryService<TUser> tokenFactoryService)
        {
            if (userManager == null)
            {
                throw new ArgumentNullException(nameof(userManager));
            }
            if (contextAccessor == null)
            {
                throw new ArgumentNullException(nameof(contextAccessor));
            }


            UserManager = userManager;
            Options = optionsAccessor?.Value ?? new IdentityOptions();
            Logger = logger;
            _schemes = schemes;
            _confirmation = confirmation;
            _tokenFactoryService = tokenFactoryService;
            _contextAccessor = contextAccessor;
        }

        private readonly IHttpContextAccessor _contextAccessor;
        private HttpContext _context;
        private IAuthenticationSchemeProvider _schemes;
        private IUserConfirmation<TUser> _confirmation;
        private readonly ITokenFactoryService<TUser> _tokenFactoryService;


        #region Properties

        public virtual ILogger Logger { get; set; }

        public UserManager<TUser> UserManager { get; set; }

        public IdentityOptions Options { get; set; }

        public HttpContext Context
        {
            get
            {
                var context = _context ?? _contextAccessor?.HttpContext;
                if (context == null)
                {
                    throw new InvalidOperationException("HttpContext must not be null.");
                }
                return context;
            }
            set
            {
                _context = value;
            }
        }

        #endregion


        protected virtual async Task<JwtSignInResult> SignInOrTwoFactorAsync(TUser user,
            string loginProvider = null,
            bool bypassTwoFactor = false)
        {
            if (!bypassTwoFactor && await IsTfaEnabled(user))
            {
                if (!await IsTwoFactorClientRememberedAsync(user))
                {
                    // Store the userId for use after two factor check
                    var userId = await UserManager.GetUserIdAsync(user);
                    var twoFactorStepOneToken = StoreTwoFactorInfo(userId, loginProvider);
                    return JwtSignInResult.TwoFactorRequired(twoFactorStepOneToken);
                }
            }

            if (loginProvider != null)
            {
                // no need for jwt token!?
                // await Context.SignOutAsync(IdentityConstants.ExternalScheme);
            }

            (string Token, string RefreshToken) tokens;

            if (loginProvider == null)
            {
                tokens = await SignInWithClaimsAsync(user, new Claim[] { new Claim("amr", "pwd") });
            }
            else
            {
                IList<Claim> additionalClaims = Array.Empty<Claim>();
                tokens = await SignInWithClaimsAsync(user, additionalClaims);
            }

            return JwtSignInResult.Success(tokens.Token, tokens.RefreshToken);
        }

        private async Task<bool> IsTfaEnabled(TUser user)
    => UserManager.SupportsUserTwoFactor &&
    await UserManager.GetTwoFactorEnabledAsync(user) &&
    (await UserManager.GetValidTwoFactorProvidersAsync(user)).Count > 0;

        public virtual async Task<bool> IsTwoFactorClientRememberedAsync(TUser user)
        {
            return false;

            var userId = await UserManager.GetUserIdAsync(user);

            var result = await Context.AuthenticateAsync(IdentityConstants.TwoFactorRememberMeScheme);

            return (result != null && result.Principal.FindFirstValue(ClaimTypes.Name) == userId);
        }

        public virtual async Task<(string Token, string RefreshToken)> SignInWithClaimsAsync(TUser user, IEnumerable<Claim> additionalClaims)
        {
            return await _tokenFactoryService.CreateJwtTokensAsync(user, additionalClaims);
        }

        protected virtual async Task<JwtSignInResult> PreSignInCheck(TUser user)
        {
            if (!await CanSignInAsync(user))
            {
                return JwtSignInResult.NotAllowed;
            }
            if (await IsLockedOut(user))
            {
                return await LockedOut(user);
            }
            return null;
        }

        public virtual async Task<bool> CanSignInAsync(TUser user)
        {
            if (Options.SignIn.RequireConfirmedEmail && !(await UserManager.IsEmailConfirmedAsync(user)))
            {
                Logger.LogWarning(0, "User cannot sign in without a confirmed email.");
                return false;
            }
            if (Options.SignIn.RequireConfirmedPhoneNumber && !(await UserManager.IsPhoneNumberConfirmedAsync(user)))
            {
                Logger.LogWarning(1, "User cannot sign in without a confirmed phone number.");
                return false;
            }
            if (Options.SignIn.RequireConfirmedAccount && !(await _confirmation.IsConfirmedAsync(UserManager, user)))
            {
                Logger.LogWarning(4, "User cannot sign in without a confirmed account.");
                return false;
            }
            return true;
        }

        protected virtual async Task<bool> IsLockedOut(TUser user)
        {
            return UserManager.SupportsUserLockout && await UserManager.IsLockedOutAsync(user);
        }

        protected virtual Task<JwtSignInResult> LockedOut(TUser user)
        {
            Logger.LogWarning(3, "User is currently locked out.");
            return Task.FromResult(JwtSignInResult.LockedOut);
        }

        protected virtual Task ResetLockout(TUser user)
        {
            if (UserManager.SupportsUserLockout)
            {
                return UserManager.ResetAccessFailedCountAsync(user);
            }
            return Task.CompletedTask;
        }

        public virtual Task SignOutAsync()
        {
            return Task.CompletedTask;

            //todo for jwt

            //await Context.SignOutAsync(IdentityConstants.ApplicationScheme);
            //await Context.SignOutAsync(IdentityConstants.ExternalScheme);
            //await Context.SignOutAsync(IdentityConstants.TwoFactorUserIdScheme);
        }

        internal string StoreTwoFactorInfo(string userId, string loginProvider)
        {
            var additionalClaims = new List<Claim>();

            additionalClaims.Add(new Claim(ClaimTypes.Name, userId));

            if (loginProvider != null)
            {
                additionalClaims.Add(new Claim(ClaimTypes.AuthenticationMethod, loginProvider));
            }

            return _tokenFactoryService.CreateMfaTokenAsync(additionalClaims);
        }

        public virtual async Task ValidateSecurityStampAsync(TokenValidatedContext context)
        {
            if (context?.Principal == null)
            {
                context.Fail("This token is expired. Please login again.");
            }
            var user = await UserManager.GetUserAsync(context.Principal);

            if (await ValidateSecurityStampAsync(user, context.Principal.FindFirstValue(Options.ClaimsIdentity.SecurityStampClaimType)))
            {
                return;
            }
            Logger.LogDebug(4, "Failed to validate a security stamp.");
            context.Fail("Failed to validate.");
        }

        public virtual async Task<TUser> ValidateTwoFactorSecurityStampAsync(ClaimsPrincipal principal)
        {
            if (principal == null || principal.Identity?.Name == null)
            {
                return null;
            }
            var user = await UserManager.FindByIdAsync(principal.Identity.Name);
            if (await ValidateSecurityStampAsync(user, principal.FindFirstValue(Options.ClaimsIdentity.SecurityStampClaimType)))
            {
                return user;
            }
            Logger.LogDebug(5, "Failed to validate a security stamp.");
            return null;
        }

        public virtual async Task<bool> ValidateSecurityStampAsync(TUser user, string securityStamp)
            => user != null &&
            // Only validate the security stamp if the store supports it
            (!UserManager.SupportsUserSecurityStamp || securityStamp == await UserManager.GetSecurityStampAsync(user));

        public virtual async Task<JwtSignInResult> RefreshTokenAsync(string refreshToken)
        {
            var result = _tokenFactoryService.ValidateAndGetRefreshTokenUserIdAndSecurity(refreshToken);

            if (result.UserId == null || result.SecurityStamp == null)
            {
                return JwtSignInResult.Failed("invalid token");
            }

            var user = await UserManager.FindByIdAsync(result.UserId);

            if (user == null || !await ValidateSecurityStampAsync(user, result.SecurityStamp))
            {
                return JwtSignInResult.Failed("token expired");
            }

            IList<Claim> additionalClaims = Array.Empty<Claim>();
            
            if (!string.IsNullOrEmpty(result.AmrCliam))
            {
                additionalClaims.Add(new Claim("amr", result.AmrCliam));
            }
          
            var tokens = await SignInWithClaimsAsync(user, additionalClaims);

            return JwtSignInResult.Success(tokens.Token, tokens.RefreshToken);
        }
    }
}

