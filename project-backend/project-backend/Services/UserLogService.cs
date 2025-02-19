using MongoDB.Driver;
using project_backend.Data;
using project_backend.Models;

namespace project_backend.Services;

public class UserLogService
{
    private readonly IMongoCollection<User> _logger;

    public UserLogService(MongoDbContext dbContext)
    {
        _logger = dbContext.Users;
    }

    public async Task UpdateLogAsync(string id, UserLog userLog)
    {
        var updateDefinition = Builders<User>.Update.Set(u => u.UserLog, userLog);
        await _logger.UpdateOneAsync(user => user.Id == id, updateDefinition);
    }

    public async Task<UserLog?> GetUserLogAsync(string id)
    {
        var userLog = await _logger.Find(u => u.Id == id).FirstOrDefaultAsync();
        return userLog?.UserLog;
    }

}
