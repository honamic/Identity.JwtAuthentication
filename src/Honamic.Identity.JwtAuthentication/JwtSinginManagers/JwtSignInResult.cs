using Microsoft.AspNetCore.Identity;

namespace Honamic.Identity.JwtAuthentication
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

        public CreateJwtTokenResult Tokens { get; protected set; }

        public string TwoFactorToken { get; protected set; }

        public string Message { get; protected set; }

        public static JwtSignInResult Success(CreateJwtTokenResult tokenResult)
        {
            return new JwtSignInResult { 
                Succeeded = true,
                Tokens = tokenResult
            };
        }

        public static JwtSignInResult Failed(string message = null)
        {
            return new JwtSignInResult { Message = message };
        }

        public static JwtSignInResult LockedOut => _lockedOut;

        public static JwtSignInResult NotAllowed => _notAllowed;

        public static JwtSignInResult TwoFactorRequired(string twoFactorToken)
        {
            return new JwtSignInResult { RequiresTwoFactor = true, TwoFactorToken = twoFactorToken };
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
