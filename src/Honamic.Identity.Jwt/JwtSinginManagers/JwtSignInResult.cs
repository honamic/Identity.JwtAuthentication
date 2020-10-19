using Microsoft.AspNetCore.Identity;

namespace Honamic.Identity.Jwt
{
    public class JwtSignInResult
    {
        private static readonly JwtSignInResult _failed = new JwtSignInResult();
        private static readonly JwtSignInResult _lockedOut = new JwtSignInResult { IsLockedOut = true };
        private static readonly JwtSignInResult _notAllowed = new JwtSignInResult { IsNotAllowed = true };

        public bool Succeeded { get; protected set; }

        public bool IsLockedOut { get; protected set; }

        public bool IsNotAllowed { get; protected set; }

        public bool RequiresTwoFactor { get; protected set; }

        public string Token { get; set; }
        
        public string RefreshToken { get; set; }

        public string TwoFactorRememberMeToken { get; protected set; }

        public string TwoFactorStepOneToken { get; protected set; }

        public string ExternalProviderToken { get; protected set; }


        public static JwtSignInResult Success(string token, string twoFactorRememberMeToken=null)
        {
            return new JwtSignInResult { Succeeded = true, Token = token, TwoFactorRememberMeToken= twoFactorRememberMeToken };
        }

        public static JwtSignInResult Failed => _failed;

        public static JwtSignInResult LockedOut => _lockedOut;

        public static JwtSignInResult NotAllowed => _notAllowed;

        public static JwtSignInResult TwoFactorRequired(string twoFactorStepOneToken)
        {
            return new JwtSignInResult { RequiresTwoFactor = true, TwoFactorStepOneToken = twoFactorStepOneToken };
        }


        public override string ToString()
        {
            return IsLockedOut ? "Lockedout" :
                      IsNotAllowed ? "NotAllowed" :
                   RequiresTwoFactor ? "RequiresTwoFactor" :
                   Succeeded ? "Succeeded" : "Failed";
        }

    }
}
