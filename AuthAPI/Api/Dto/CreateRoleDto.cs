using System.ComponentModel.DataAnnotations;

namespace AuthAPI.Api.Dto;

public class CreateRoleDto
{
    [Required(ErrorMessage = "Role Name is required.")]
    public string RoleName { get; set; } = null!;
}