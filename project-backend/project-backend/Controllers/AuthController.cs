using System.IdentityModel.Tokens.Jwt;
using System.Security.Claims;
using System.Text;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity.Data;
using Microsoft.AspNetCore.Mvc;
using Microsoft.IdentityModel.Tokens;
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
        private readonly UserLogService _userLogService;
        private readonly UserService _userService;

        public AuthController(AuthService authService, JwtService jwtService, MongoDbContext mongoContext, UserLogService userLogService, UserService userService)
        {
            _authService = authService;
            _jwtService = jwtService;
            // _context = mongoContext;
            _userLogService = userLogService;
            _userService = userService;
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
                var expireTime = DateTime.UtcNow.AddHours(1);
                var userLog = new UserLog()
                {
                    LoginCount = (user.UserLog?.LoginCount ?? 0) + 1,
                    LastLogin = DateTime.UtcNow,
                    SessionExpire = expireTime,
                    SessionDuration = (user.UserLog?.SessionDuration ?? 0),
                };
                await _userLogService.UpdateLogAsync(user.Id, userLog);
                return Ok(new { token });
            }
            catch (Exception e)
            {
                return StatusCode(500, new { message = "An error occurred while processing your login request. Please try again later." });
            }

        }

        [HttpPut("logout")]
        [Authorize]
        public async Task<IActionResult> Logout()
        {
            try
            {
                // Retrieve the user id from the JWT claims populated by the middleware.
                var userId = User.FindFirst(ClaimTypes.NameIdentifier)?.Value;
                if (string.IsNullOrEmpty(userId))
                {
                    return Unauthorized(new { message = "Invalid token or user not found." });
                }

                // Retrieve and update the user log as needed
                var userLog = await _userLogService.GetUserLogAsync(userId);
                if (userLog == null)
                {
                    return NotFound(new { message = "User log not found" });
                }

                // Calculate session duration
                var logoutTime = DateTime.UtcNow;
                var sessionDuration = (logoutTime - userLog.LastLogin).TotalMinutes;

                var log = new UserLog()
                {
                    LoginCount = userLog.LoginCount,
                    LastLogin = userLog.LastLogin,
                    SessionExpire = userLog.SessionExpire,
                    SessionDuration = userLog.SessionDuration+ (int)sessionDuration,
                };

                await _userLogService.UpdateLogAsync(userId, log);

                return Ok(new { message = "Logged out successfully"});
            }
            catch (Exception e)
            {
                return StatusCode(500, new { message = "An error occurred while logging out. Please try again later." });
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
                return StatusCode(500, new { message = "An error occurred while resetting the password. Please try again later." });
            }
        }

        [HttpPost("validate-token")]
        public IActionResult ValidateToken([FromBody] TokenRequest request)
        {
            if (string.IsNullOrWhiteSpace(request.Token))
                return BadRequest(new { message = "Token is required" });

            var key = new SymmetricSecurityKey(Encoding.UTF8.GetBytes(Environment.GetEnvironmentVariable("JWT_SECRET_KEY") ?? throw new InvalidOperationException()));
            var tokenHandler = new JwtSecurityTokenHandler();

            try
            {
                tokenHandler.ValidateToken(request.Token, new TokenValidationParameters
                {
                    ValidateIssuerSigningKey = true,
                    IssuerSigningKey = key,
                    ValidateIssuer = false,
                    ValidateAudience = false,
                    ClockSkew = TimeSpan.Zero
                }, out SecurityToken validatedToken);

                var jwtToken = (JwtSecurityToken)validatedToken;
                var userId = jwtToken.Claims.First(claim => claim.Type == ClaimTypes.NameIdentifier).Value;

                // Calculate session duration based on token expiration
                var expirationTime = jwtToken.ValidTo;
                var sessionDuration = (expirationTime - DateTime.UtcNow).TotalMinutes;

                return Ok(new { valid = true, userId, sessionDuration });
            }
            catch (SecurityTokenExpiredException)
            {
                // Calculate session duration based on token expiration time
                var jwtToken = tokenHandler.ReadJwtToken(request.Token);
                var expirationTime = jwtToken.ValidTo;
                var sessionDuration = (expirationTime - jwtToken.ValidFrom).TotalMinutes;

                return Unauthorized(new { valid = false, message = "Token has expired", sessionDuration });
            }
            catch (Exception)
            {
                return Unauthorized(new { valid = false, message = "Invalid token" });
            }
        }

        [HttpGet("profile/{userId}")]
        public async Task<IActionResult> GetUserProfile(string userId)
        {
            try
            {
                var userProfile = await _authService.GetUserProfileAsync(userId);
                if (userProfile == null)
                    return NotFound(new { message = "User not found" });

                return Ok(userProfile);
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { message = "An error occurred while fetching the user profile. Please try again later." });
            }
        }
        public class TokenRequest
        {
            public string? Token { get; set; }
        }
    }
}
