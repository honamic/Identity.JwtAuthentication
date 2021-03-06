﻿using System;
using System.Threading.Tasks;
using Microsoft.Extensions.Logging;

namespace Honamic.Identity.JwtAuthentication
{
    public partial class JwtSignInManager<TUser>
    {
        public virtual async Task<JwtSignInResult> PasswordSignInAsync(string userName, string password, bool isPersistent, bool lockoutOnFailure)
        {
            TUser val = await UserManager.FindByNameAsync(userName);
            if (val == null)
            {
                return JwtSignInResult.Failed("invalid user name or password");
            }
            return await PasswordSignInAsync(val, password, isPersistent, lockoutOnFailure);
        }

        public virtual async Task<JwtSignInResult> PasswordSignInAsync(TUser user, string password, bool isPersistent, bool lockoutOnFailure)
        {
            if (user == null)
            {
                throw new ArgumentNullException("user");
            }          

            var attempt = await CheckPasswordSignInAsync(user, password, lockoutOnFailure);

            if (!attempt.Succeeded)
            {
                return attempt;
            }

            return await SignInOrTwoFactorAsync(user);
        }

        public virtual async Task<JwtSignInResult> CheckPasswordSignInAsync(TUser user, string password, bool lockoutOnFailure)
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
                if (alwaysLockout || !await IsTfaEnabled(user) || await IsTwoFactorClientRememberedAsync(user))
                {
                    await ResetLockout(user);
                }

                return JwtSignInResult.Success(null);
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
            return JwtSignInResult.Failed();
        }
    }
}