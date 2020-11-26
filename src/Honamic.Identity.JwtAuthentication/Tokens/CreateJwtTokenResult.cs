using System;
using System.Collections.Generic;
using System.Text;

namespace Honamic.Identity.JwtAuthentication
{
    public class CreateJwtTokenResult
    {
        public string Token { get; set; }

        public string RefreshToken { get; set; }

        public DateTimeOffset TokenExpirationTime { get; set; }

        public DateTimeOffset RefreshTokenExpirationTime { get; set; }
    }
}
