using MongoDB.Bson;
using MongoDB.Bson.Serialization.Attributes;
namespace project_backend.Models;

public class User
{
    [BsonId]
    [BsonRepresentation(BsonType.ObjectId)]
    public string? Id { get; set; }

    public string? Name { get; set; }

    [BsonElement("Email")]
    [BsonRequired]
    public string Email { get; set; } = null!;

    public string? Password { get; set; }

    [BsonElement("UserLog")]
    public UserLog? UserLog { get; set; }

}

public class UserLog
{
    public int LoginCount { get; set; }
    public DateTime LastLogin { get; set; }
    public DateTime SessionExpire { get; set; }
    public int? SessionDuration { get; set; }
}
