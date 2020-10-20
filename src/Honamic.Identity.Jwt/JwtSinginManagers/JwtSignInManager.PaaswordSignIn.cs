using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Honamic.Identity.Jwt
{
    public partial class JwtSignInManager<TUser>
    {
        public virtual async Task<JwtSignInResult> PasswordSignInAsync(string userName,
            string password,
            bool isPersistent,
            bool lockoutOnFailure,
            string twoFactorRememberMeToken
            )
        {
            var user = await UserManager.FindByNameAsync(userName);

            if (user == null)
            {
                return JwtSignInResult.Failed;
            }

            var attempt = await CheckPasswordSignInAsync(user, password, lockoutOnFailure, twoFactorRememberMeToken);

            if (!attempt.Succeeded)
            {
                return attempt;
            }

            return await SignInOrTwoFactorAsync(user, isPersistent, twoFactorRememberMeToken: twoFactorRememberMeToken);
        }

        public virtual async Task<JwtSignInResult> CheckPasswordSignInAsync(TUser user, string password, bool lockoutOnFailure, string twoFactorRememberMeToken)
        {
            if (user == null)
            {
                throw new ArgumentNullException(nameof(user));
            }

            var error = await PreSignInCheck(user);

            if (error != null)
            {
                return error;
            }

            if (await UserManager.CheckPasswordAsync(user, password))
            {
                var alwaysLockout = AppContext.TryGetSwitch("Microsoft.AspNetCore.Identity.CheckPasswordSignInAlwaysResetLockoutOnSuccess", out var enabled) && enabled;
                // Only reset the lockout when not in quirks mode if either TFA is not enabled or the client is remembered for TFA.
                if (alwaysLockout || !await IsTfaEnabled(user) || await IsTwoFactorClientRememberedAsync(user, twoFactorRememberMeToken))
                {
                    await ResetLockout(user);
                }

                return JwtSignInResult.Success(null, null);
            }

            Logger.LogWarning(2, "User failed to provide the correct password.");

            if (UserManager.SupportsUserLockout && lockoutOnFailure)
            {
                // If lockout is requested, increment access failed count which might lock out the user
                await UserManager.AccessFailedAsync(user);
                if (await UserManager.IsLockedOutAsync(user))
                {
                    return await LockedOut(user);
                }
            }
            return JwtSignInResult.Failed;
        }
    }
}