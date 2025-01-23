using MongoDB.Driver;
using project_backend.Models;

namespace project_backend.Data
{
    public class MongoDbContext
    {
        private readonly IMongoDatabase _database;

        public MongoDbContext(IConfiguration configuration)
        {
            var connectionString = configuration.GetConnectionString("mongodb");

            var client = new MongoClient(connectionString);
            _database = client.GetDatabase("Project");
        }

        public IMongoCollection<User> Users => _database.GetCollection<User>("Users");
    }
}
