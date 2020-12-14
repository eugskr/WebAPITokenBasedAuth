using System;
using System.Collections.Generic;
using System.Linq;
using System.Security.Claims;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using WebAPIAuthAndJWT.Authentication;

namespace WebAPIAuthAndJWT.Controllers
{
    [ApiController]
    [Route("[controller]")]
    [Authorize]
    public class UsersController : ControllerBase
    {
        private readonly UserManager<AppUser> _userManager;
        
        public UsersController(UserManager<AppUser> userManager)
        {
            _userManager = userManager;          
        }

        [HttpGet]
        public async Task<IActionResult> Get()
        {
            var name = HttpContext.User.Claims.FirstOrDefault(c => c.Type == ClaimTypes.Name)?.Value;
            var user = await _userManager.FindByNameAsync(name);
            AppUserResponse userResponse = new AppUserResponse { FirstName=user.FirstName, LastName=user.LastName,PhoneNumber=user.PhoneNumber };

            return Ok(userResponse);
        }
    }
}
