using System;
using System.Collections.Generic;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Text;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.Extensions.Configuration;
using Microsoft.IdentityModel.Tokens;
using WebAPIAuthAndJWT.Authentication;

namespace WebAPIAuthAndJWT.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthenticationController : ControllerBase
    {
        private readonly UserManager<AppUser> _userManager;
      
        private readonly IConfiguration _configuration;
        public AuthenticationController(UserManager<AppUser> userManager, IConfiguration configuration)
        {
            _userManager = userManager;
        
            _configuration = configuration;
        }
        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody] RegisterModel model)
        {
            var userExist = await _userManager.FindByNameAsync(model.Login);
            if (userExist != null)
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User with this login already exist" });
         
            AppUser user = new AppUser()
            {
                SecurityStamp = Guid.NewGuid().ToString(),
                UserName = model.Login,
                FirstName = model.FirstName,
                LastName = model.LastName,
                PhoneNumber = model.PhoneNumber
            };
            var result = await _userManager.CreateAsync(user, model.Password);
            if (!result.Succeeded)
            {
                return StatusCode(StatusCodes.Status500InternalServerError, new Response { Status = "Error", Message = "User Creation Failed" });

            }
            return Ok(new Response { Status = "Success", Message = "User Created Successfully" });
        }

        [HttpPost]
        [Route("Login")]
        public async Task<IActionResult> Login([FromBody] LoginModel model)
        {
            var user = await _userManager.FindByNameAsync(model.Login);
            if (user != null && await _userManager.CheckPasswordAsync(user, model.Password))
            {
                var authClaims = new List<Claim>
                {
                    new Claim(ClaimTypes.Name, model.Login),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                };
                var authSigninKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_configuration["JWT:SecretKey"]));
                var token = new JwtSecurityToken(issuer: _configuration["JWT:ValidIssuer"],
                    audience: _configuration["JWT:ValidAudience"],
                    expires: DateTime.Now.AddHours(5),    
                    claims:authClaims,
                    signingCredentials: new SigningCredentials(authSigninKey, SecurityAlgorithms.HmacSha256)
                    );

                return Ok(new
                {
                    token = new JwtSecurityTokenHandler().WriteToken(token)

                });
            }
            return Unauthorized();
        }
    }
}
