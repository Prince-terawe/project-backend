using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Mvc;
using project_backend.Models;
using project_backend.Services;

namespace project_backend.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserLogController : ControllerBase
    {
        private readonly UserLogService _logService;

        public UserLogController(UserLogService logService)
        {
            _logService = logService;
        }

        [HttpGet("getUserLog/{id}")]
        [Authorize]
        public async Task<IActionResult> GetLog(string id)
        {
            try
            {
                var userLog = await _logService.GetUserLogAsync(id);
                if (userLog == null)
                {
                    return NotFound(new { Message = "No Log found" });
                }
                return Ok(userLog);
            }
            catch (Exception e)
            {
                return StatusCode(500, new { Message = "An error occurred while fetching the user", Error = e.Message });
            }
        }

        [HttpPatch("addUserLog/{id}")]
        [Authorize]
        public async Task<IActionResult> AddLog(string id, [FromBody] UserLog userLog)
        {
            try
            {
                await _logService.UpdateLogAsync(id,userLog);
                return Ok(new { Message = "Log added successfully" });
            }
            catch (Exception e)
            {
                return StatusCode(500, new { Message = "An error occurred while fetching the user", Error = e.Message });
            }
        }

        [HttpPut("updateUserLog/{id}")]
        // [Authorize]
        public async Task<IActionResult> UpdateLog(string id)
        {
            try
            {
                var expTime = DateTime.UtcNow;
                var userLog = await _logService.GetUserLogAsync(id);
                if (userLog == null)
                {
                    return NotFound(new { message = "User log not found" });
                }
                var duration = (expTime - userLog.LastLogin).TotalMinutes;
                var log = new UserLog()
                {
                    LoginCount = userLog.LoginCount,
                    LastLogin = userLog.LastLogin,
                    SessionExpire = userLog.SessionExpire,
                    SessionDuration = userLog.SessionDuration+ (int)duration,
                };
                await _logService.UpdateLogAsync(id,log);
                return Ok(new { Message = "Log updated successfully" });
            }
            catch (Exception e)
            {
                return StatusCode(500, new { Message = "An error occurred while fetching the user", Error = e.Message });
            }
        }
    }
}

