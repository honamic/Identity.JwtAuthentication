using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;

namespace Honamic.Identity.JwtAuthentication
{
    public class LoginWithRecoveryCodeViewModel
    {
        [Required]
        public string RecoveryCode { get; set; }
    }
}
