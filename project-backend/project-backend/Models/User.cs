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

}
