using System;
using System.Collections.Generic;
using System.Text;

namespace Honamic.Identity.Jwt
{
    public class BearerTokensOptions
    {
        public BearerTokensOptions()
        {
            MfaTokenExpirationMinutes = 3;
        }

        public string Key { set; get; }

        public string Issuer { set; get; }

        public string Audience { set; get; }

        public int AccessTokenExpirationMinutes { set; get; }

        public int MfaTokenExpirationMinutes { set; get; }

        public int RefreshTokenExpirationMinutes { get; set; }

        public bool AllowMultipleLoginsFromTheSameUser { set; get; }

        public bool AllowSignoutAllUserActiveClients { set; get; }
    }
}
