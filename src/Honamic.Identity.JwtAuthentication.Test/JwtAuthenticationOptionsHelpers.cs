using Honamic.Identity.JwtAuthentication;

namespace Honamic.Identity.JwtAuthentication.Test
{
    public static class OptionsHelpers
    {
        public static JwtAuthenticationOptions Default;

        static OptionsHelpers()
        {
            Default = new JwtAuthenticationOptions()
            {
                SigningKey = "1234567890123456",
                Issuer = "honamic",
                Audience = "any",
            };
        } 
    }
}
