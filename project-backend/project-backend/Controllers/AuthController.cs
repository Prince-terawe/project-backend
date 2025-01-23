using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using project_backend.Data;
using project_backend.Models;
using project_backend.Services;
using project_backend.Utils;
using LoginRequest = project_backend.Models.LoginRequest;
using ResetPasswordRequest = project_backend.Models.ResetPasswordRequest;

namespace project_backend.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {
        private readonly AuthService _authService;
        private readonly JwtService _jwtService;
        // private readonly MongoDbContext _context;

        public AuthController(AuthService authService, JwtService jwtService, MongoDbContext mongoContext)
        {
            _authService = authService;
            _jwtService = jwtService;
            // _context = mongoContext;
        }

        [HttpPost("signup")]
        public async Task<IActionResult> SignUp([FromBody] User user)
        {
            try
            {
                if (!ValidationHelper.IsValidEmail(user.Email))
                    return BadRequest(new { message = "Invalid email format" });

                user.Password = ValidationHelper.HashPassword(user.Password);
                await _authService.CreateUserAsync(user);

                return Ok(new { message = "User created successfully" });
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error occurred during signup: {e.Message}");

                return StatusCode(500, new { message = "An error occurred while creating the user. Please try again later." });

            }

        }

        [HttpPost("login")]
        public async Task<IActionResult> Login([FromBody] LoginRequest loginRequest)
        {
            try
            {
                var user = await _authService.FindUserByEmailAsync(loginRequest.Email);

                if (user == null || string.IsNullOrWhiteSpace(user.Password) ||
                    user.Password != ValidationHelper.HashPassword(loginRequest.Password))
                {
                    return Unauthorized(new { message = "Invalid email or password" });
                }

                var token = _jwtService.GenerateToken(user.Id, user.Email);
                return Ok(new { token });
            }
            catch (Exception e)
            {
                Console.WriteLine($"Error occurred during login: {e.Message}");

                return StatusCode(500, new { message = "An error occurred while processing your login request. Please try again later." });
            }

        }

        [HttpPut("reset-password")]
        public async Task<IActionResult> ResetPassword([FromBody] ResetPasswordRequest resetPasswordRequest)
        {
            try
            {
                var user = await _authService.FindUserByEmailAsync(resetPasswordRequest.Email);
                if (user == null)
                    return NotFound(new { message = "User not found" });

                // Update the user's password
                var password = ValidationHelper.HashPassword(resetPasswordRequest.NewPassword);
                await _authService.UpdatePasswordAsync(user.Id, password);

                return Ok(new { message = "Password reset successfully" });
            }
            catch (Exception ex)
            {
                Console.WriteLine($"Error occurred during password reset: {ex.Message}");

                return StatusCode(500, new { message = "An error occurred while resetting the password. Please try again later." });
            }
        }
    }
}
