using MongoDB.Driver;
using project_backend.Data;
using project_backend.Models;

namespace project_backend.Services;

public class UserService
{
    private readonly IMongoCollection<User> _users;

    public UserService(MongoDbContext dbContext)
    {
        _users = dbContext.Users;
    }

    public async Task<User> GetUserByIdAsync(string id)
    {
        return await _users.Find(u => u.Id == id).FirstOrDefaultAsync();
    }

    public async Task<List<User>> GetUsersAsync(int pageNumber, int pageSize)
    {
        // var projection = Builders<User>.Projection
        //     .Exclude(user => user.Password);
        return await _users
            .Find(user => true)
            .Skip((pageNumber - 1) * pageSize)
            .Limit(pageSize)
            .ToListAsync();
    }

    public async Task<long> GetTotalUsersCountAsync()
    {
        return await _users.CountDocumentsAsync(user => true);
    }
}
