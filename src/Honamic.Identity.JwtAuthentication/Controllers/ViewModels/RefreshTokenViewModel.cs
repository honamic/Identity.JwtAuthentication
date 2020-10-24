using System.ComponentModel.DataAnnotations;

namespace Honamic.Identity.JwtAuthentication
{
    public class RefreshTokenViewModel
    {
        [Required]
        public string RefreshToken { set; get; }
    }
}
