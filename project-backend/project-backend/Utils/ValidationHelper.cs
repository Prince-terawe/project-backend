using System.Text;
using System.Text.RegularExpressions;

namespace project_backend.Utils
{
    public static class ValidationHelper
    {
        public static bool IsValidEmail(string email) =>
            Regex.IsMatch(email, @"^[^@\s]+@[^@\s]+\.[^@\s]+$");

        public static string HashPassword(string password)
        {
            using var sha256 = System.Security.Cryptography.SHA256.Create();
            var hashedBytes = sha256.ComputeHash(Encoding.UTF8.GetBytes(password));
            return Convert.ToBase64String(hashedBytes);
        }
    }
}
