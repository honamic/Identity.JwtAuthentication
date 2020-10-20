using System;
using System.Collections.Generic;
using System.Security.Claims;
using System.Text.Json;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authentication;
using Microsoft.AspNetCore.Authentication.JwtBearer;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.Extensions.Logging;
using Microsoft.Extensions.Options;

namespace Honamic.Identity.Jwt
{
    public partial class JwtSignInManager<TUser> where TUser : class
    {
        public JwtSignInManager(UserManager<TUser> userManager,
            IHttpContextAccessor contextAccessor,
            // IUserClaimsPrincipalFactory<TUser> claimsFactory,
            IOptions<IdentityOptions> optionsAccessor,
            ILogger<SignInManager<TUser>> logger,
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


        protected virtual async Task<JwtSignInResult> SignInOrTwoFactorAsync(TUser user, bool isPersistent,
            string loginProvider = null,
            bool bypassTwoFactor = false,
            string twoFactorRememberMeToken = null)
        {
            if (!bypassTwoFactor && await IsTfaEnabled(user))
            {
                if (!await IsTwoFactorClientRememberedAsync(user, twoFactorRememberMeToken))
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


        public virtual async Task<bool> IsTwoFactorClientRememberedAsync(TUser user, string twoFactorRememberMeToken)
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

        public virtual async Task SignOutAsync()
        {
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



        /// <summary>
        /// Validates the security stamp for the specified <paramref name="principal"/> against
        /// the persisted stamp for the current user, as an asynchronous operation.
        /// </summary>
        /// <param name="principal">The principal whose stamp should be validated.</param>
        /// <returns>The task object representing the asynchronous operation. The task will contain the <typeparamref name="TUser"/>
        /// if the stamp matches the persisted value, otherwise it will return false.</returns>
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

        /// <summary>
        /// Validates the security stamp for the specified <paramref name="principal"/> from one of
        /// the two factor principals (remember client or user id) against
        /// the persisted stamp for the current user, as an asynchronous operation.
        /// </summary>
        /// <param name="principal">The principal whose stamp should be validated.</param>
        /// <returns>The task object representing the asynchronous operation. The task will contain the <typeparamref name="TUser"/>
        /// if the stamp matches the persisted value, otherwise it will return false.</returns>
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

        /// <summary>
        /// Validates the security stamp for the specified <paramref name="user"/>.  If no user is specified, or if the store
        /// does not support security stamps, validation is considered successful.
        /// </summary>
        /// <param name="user">The user whose stamp should be validated.</param>
        /// <param name="securityStamp">The expected security stamp value.</param>
        /// <returns>The result of the validation.</returns>
        public virtual async Task<bool> ValidateSecurityStampAsync(TUser user, string securityStamp)
            => user != null &&
            // Only validate the security stamp if the store supports it
            (!UserManager.SupportsUserSecurityStamp || securityStamp == await UserManager.GetSecurityStampAsync(user));

    }
}

