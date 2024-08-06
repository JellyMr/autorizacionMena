using System.ComponentModel.DataAnnotations;

namespace AuthAPI.Api.Dto;

public class RegisterDto
{
    [Required] [EmailAddress] public string Email { get; set; } = string.Empty;
    [Required] public string FullName { get; set; } = string.Empty;
    [Required] public string UserName { get; set; } = "";
    public string Password { get; set; } = string.Empty;
    public List<string>? Roles { get; set; }
}