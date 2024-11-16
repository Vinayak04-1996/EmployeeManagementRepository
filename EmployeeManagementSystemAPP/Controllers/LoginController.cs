using EmployeeManagementSystemAPP.Models;
using EmpManagementSystemAPI.Models;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;

namespace EmployeeManagementSystemAPP.Controllers
{
    public class LoginController : Controller
    {
        private readonly EmpManagementSystemAPI.Controllers.UserController _userController;
        private IConfiguration _config;

        public LoginController(EmpManagementSystemAPI.Controllers.UserController userController, IConfiguration config) 
        {
            _userController = userController;
            _config = config;
        }


        // GET: LoginController
        public ActionResult Login()
        {
            TempData["Login"] = "Login";
            return View(new Login());
        }

        [HttpPost]
        public ActionResult Login(Login login)
        {
            var user = _userController.GetUserByName(login.UserName,login.Password);
            if (user != null)
            {
                var token = GenerateToken(user);
                Response.Cookies.Append("JwtToken", token, new CookieOptions
                {
                    HttpOnly = true,
                    Secure = true, // set to true for HTTPS
                    SameSite = SameSiteMode.Strict,
                    Expires = DateTime.Now.AddHours(1)
                });
                ModelState.AddModelError(string.Empty, "Login successfully");
                return RedirectToAction("Index", "Employee");
            }
            else
            {
                ModelState.AddModelError(string.Empty, "Invalid username or password.");
                return BadRequest("Invalid username or password");
            }
        }

        private string GenerateToken(User user)
        {
            var securityKey = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(_config["Jwt:Key"]));
            var credentials = new SigningCredentials(securityKey, SecurityAlgorithms.HmacSha256);
            var claims = new List<Claim>
            {
                new Claim("Myapp_User_Id", user.Id.ToString()),
                new Claim(ClaimTypes.NameIdentifier, user.Username),
                new Claim(ClaimTypes.Email, user.Email),
                new Claim(JwtRegisteredClaimNames.Sub, user.Id.ToString())
            };
            var token = new JwtSecurityToken(
                issuer: _config["Jwt:Issuer"],
                audience: _config["Jwt:Audience"],
                claims: claims,
                expires: DateTime.Now.AddHours(1), 
                signingCredentials: credentials);
            return new JwtSecurityTokenHandler().WriteToken(token);
        }
    }
}
