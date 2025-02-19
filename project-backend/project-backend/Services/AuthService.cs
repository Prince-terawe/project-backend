using MongoDB.Driver;
using project_backend.Data;
using project_backend.Models;

namespace project_backend.Services
{
    public class AuthService
    {
        private readonly IMongoCollection<User> _users;

        public AuthService(MongoDbContext dbContext)
        {
            _users = dbContext.Users;
        }

        public async Task CreateUserAsync(User user)
        {
            await _users.InsertOneAsync(user);
        }

        public async Task<User> FindUserByEmailAsync(string email)
        {
            return await _users.Find(u => u.Email == email).FirstOrDefaultAsync();
        }

        public async Task UpdatePasswordAsync(string userId, string newPassword)
        {

            var updateDefinition = Builders<User>.Update.Set(u => u.Password, newPassword);

            await _users.UpdateOneAsync(u => u.Id == userId, updateDefinition);
        }

        public async Task<object> GetUserProfileAsync(string userId)
        {
            var user = await _users.Find(u => u.Id == userId).FirstOrDefaultAsync();
            if (user == null)
                return null;

            // Return all user data except the password
            return new
            {
                user.Id,
                user.Email,
                user.Name,
                user.UserLog,
                // Add other fields you want to return
            };
        }

    }
}
