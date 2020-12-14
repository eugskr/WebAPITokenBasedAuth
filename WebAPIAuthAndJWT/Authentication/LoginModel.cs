using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations;
using System.Linq;
using System.Threading.Tasks;

namespace WebAPIAuthAndJWT.Authentication
{
    public class LoginModel
    {
        [Required(ErrorMessage = "Login is required")]
        public string Login { get; set; }

        [Required(ErrorMessage = "Password is required")]
        public string Password { get; set; }
    }
}
