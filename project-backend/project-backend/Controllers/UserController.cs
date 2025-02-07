using Microsoft.AspNetCore.Mvc;
using project_backend.Models;
using project_backend.Services;

namespace project_backend.Controllers
{
    [Route("api/[controller]")]
    [ApiController]
    public class UserController: ControllerBase
    {
        private readonly UserService _userService;

        public UserController(UserService userService)
        {
            _userService = userService;
        }

        [HttpGet("allUsers")]
        public async Task<IActionResult> GetUsers([FromQuery] int page = 1, [FromQuery] int pageSize = 10)
        {
            try
            {
                var users = await _userService.GetUsersAsync(page, pageSize);
                if (users == null || users.Count == 0)
                {
                    return NotFound(new { Message = "No users found" });
                }

                var totalUsers = await _userService.GetTotalUsersCountAsync();

                var totalPages = (int)Math.Ceiling((double)totalUsers / pageSize);

                var usersList = new List<object>();
                foreach (var user in users)
                {
                    usersList.Add(new
                    {
                        Id = user.Id,
                        Name = user.Name,
                        Email = user.Email
                    });
                }

                return Ok(new { Page = page, PageSize = pageSize, TotalPages= totalPages, TotalUsers = totalUsers, Users = usersList });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { Message = "An error occurred while fetching users", Error = ex.Message });
            }
        }

        [HttpGet("getUser/{id}")]
        public async Task<IActionResult> GetUser(string id)
        {
            try
            {
                var user = await _userService.GetUserByIdAsync(id);
                if (user == null)
                {
                    return NotFound(new { Message = "No user found" });
                }

                return Ok(new
                {
                    Id = user.Id,
                    Name = user.Name,
                    Email = user.Email
                });
            }
            catch (Exception ex)
            {
                return StatusCode(500, new { Message = "An error occurred while fetching the user", Error = ex.Message });
            }
        }
    }
}


