using System.ComponentModel.DataAnnotations;

namespace Honamic.Identity.JwtAuthentication
{
    public class JwtAuthenticationOptions
    {
        public JwtAuthenticationOptions()
        {
            MfaTokenExpirationMinutes = 3;
            AccessTokenExpirationMinutes = 15;
            RefreshTokenExpirationMinutes = 24 * 60;
            ClockSkewSeconds = 0;
        }

        [Required]
        public string Key { set; get; }

        [Required]
        public string Issuer { set; get; }

        [Required]
        public string Audience { set; get; }

        [Range(0, int.MaxValue)]
        public int ClockSkewSeconds { set; get; }

        [Range(1, int.MaxValue)]
        public int AccessTokenExpirationMinutes { set; get; }

        [Range(1, int.MaxValue)]
        public int MfaTokenExpirationMinutes { set; get; }

        [Range(1, int.MaxValue)]
        public int RefreshTokenExpirationMinutes { get; set; }
    }
}