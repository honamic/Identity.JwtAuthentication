using System.Collections.Generic;
using System.Text.Json;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace Honamic.Identity.Jwt
{
    public partial class JwtSignInManager<TUser, TRole>
    {


        public virtual async Task<JwtSignInResult> TwoFactorAuthenticatorSignInAsync(string code, bool isPersistent, bool rememberClient, string twoFactorStepOneToken)
        {
            var twoFactorInfo = RetrieveTwoFactorInfoAsync(twoFactorStepOneToken);
            if (twoFactorInfo == null || twoFactorInfo.UserId == null)
            {
                return JwtSignInResult.Failed;
            }
            var user = await UserManager.FindByIdAsync(twoFactorInfo.UserId);
            if (user == null)
            {
                return JwtSignInResult.Failed;
            }

            var error = await PreSignInCheck(user);
            if (error != null)
            {
                return error;
            }

            if (await UserManager.VerifyTwoFactorTokenAsync(user, Options.Tokens.AuthenticatorTokenProvider, code))
            {
                return await DoTwoFactorSignInAsync(user, twoFactorInfo, isPersistent, rememberClient);
            }

            // If the token is incorrect, record the failure which also may cause the user to be locked out
            await UserManager.AccessFailedAsync(user);
            return JwtSignInResult.Failed;
        }




        public virtual async Task<JwtSignInResult> TwoFactorRecoveryCodeSignInAsync(string recoveryCode, string twoFactorStepOneToken)
        {
            var twoFactorInfo = RetrieveTwoFactorInfoAsync(twoFactorStepOneToken);
            if (twoFactorInfo == null || twoFactorInfo.UserId == null)
            {
                return JwtSignInResult.Failed;
            }
            var user = await UserManager.FindByIdAsync(twoFactorInfo.UserId);
            if (user == null)
            {
                return JwtSignInResult.Failed;
            }

            var result = await UserManager.RedeemTwoFactorRecoveryCodeAsync(user, recoveryCode);
            if (result.Succeeded)
            {
                return await DoTwoFactorSignInAsync(user, twoFactorInfo, isPersistent: false, rememberClient: false);
            }

            // We don't protect against brute force attacks since codes are expected to be random.
            return JwtSignInResult.Failed;
        }

        private TwoFactorAuthenticationInfo RetrieveTwoFactorInfoAsync(string twoFactorStepOneToken)
        {
            var result = JsonSerializer.Deserialize<ClaimsPrincipal>(twoFactorStepOneToken);
            if (result != null)
            {
                return new TwoFactorAuthenticationInfo
                {
                    UserId = result.FindFirstValue(ClaimTypes.Name),
                    LoginProvider = result.FindFirstValue(ClaimTypes.AuthenticationMethod)
                };
            }
            return null;
        }


        private async Task<JwtSignInResult> DoTwoFactorSignInAsync(TUser user, TwoFactorAuthenticationInfo twoFactorInfo, bool isPersistent, bool rememberClient)
        {
            // When token is verified correctly, clear the access failed count used for lockout
            await ResetLockout(user);

            var claims = new List<Claim>();
            claims.Add(new Claim("amr", "mfa"));

            // Cleanup external cookie
            if (twoFactorInfo.LoginProvider != null)
            {
                claims.Add(new Claim(ClaimTypes.AuthenticationMethod, twoFactorInfo.LoginProvider));
                //await Context.SignOutAsync(IdentityConstants.ExternalScheme);
            }

            // todo: review + no need 
            // Cleanup two factor user id cookie
            //await Context.SignOutAsync(IdentityConstants.TwoFactorUserIdScheme);


            string rememberTwoFactor = null;

            if (rememberClient)
            {
                rememberTwoFactor = await RememberTwoFactorClientAsync(user);
            }

            var token = await SignInWithClaimsAsync(user, isPersistent, claims);

            return JwtSignInResult.Success(token, rememberTwoFactor);
        }

        public virtual async Task<string> RememberTwoFactorClientAsync(TUser user)
        {
            var principal = await StoreRememberClient(user);

            return JsonSerializer.Serialize(principal);

            //await Context.SignInAsync(IdentityConstants.TwoFactorRememberMeScheme,
            //    principal,
            //    new AuthenticationProperties { IsPersistent = true });
        }

        public virtual async Task<JwtSignInResult> TwoFactorSignInAsync(string provider, string code, bool isPersistent, bool rememberClient, string twoFactorStepOneToken)
        {
            var twoFactorInfo = RetrieveTwoFactorInfoAsync(twoFactorStepOneToken);
            if (twoFactorInfo == null || twoFactorInfo.UserId == null)
            {
                return JwtSignInResult.Failed;
            }
            var user = await UserManager.FindByIdAsync(twoFactorInfo.UserId);
            if (user == null)
            {
                return JwtSignInResult.Failed;
            }

            var error = await PreSignInCheck(user);
            if (error != null)
            {
                return error;
            }
            if (await UserManager.VerifyTwoFactorTokenAsync(user, provider, code))
            {
                return await DoTwoFactorSignInAsync(user, twoFactorInfo, isPersistent, rememberClient);
            }
            // If the token is incorrect, record the failure which also may cause the user to be locked out
            await UserManager.AccessFailedAsync(user);
            return JwtSignInResult.Failed;
        }

        public virtual async Task<TUser> GetTwoFactorAuthenticationUserAsync(string twoFactorStepOneToken)
        {
            var info = RetrieveTwoFactorInfoAsync(twoFactorStepOneToken);
            
            if (info == null)
            {
                return null;
            }

            return await UserManager.FindByIdAsync(info.UserId);
        }

        internal async Task<ClaimsPrincipal> StoreRememberClient(TUser user)
        {
            var userId = await UserManager.GetUserIdAsync(user);
            var rememberBrowserIdentity = new ClaimsIdentity(IdentityConstants.TwoFactorRememberMeScheme);
            rememberBrowserIdentity.AddClaim(new Claim(ClaimTypes.Name, userId));
            if (UserManager.SupportsUserSecurityStamp)
            {
                var stamp = await UserManager.GetSecurityStampAsync(user);
                rememberBrowserIdentity.AddClaim(new Claim(Options.ClaimsIdentity.SecurityStampClaimType, stamp));
            }
            return new ClaimsPrincipal(rememberBrowserIdentity);
        }

        internal class TwoFactorAuthenticationInfo
        {
            public string UserId { get; set; }
            public string LoginProvider { get; set; }
        }
    }
}
