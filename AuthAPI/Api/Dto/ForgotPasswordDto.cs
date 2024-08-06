﻿using System.ComponentModel.DataAnnotations;

namespace AuthAPI.Api.Dto;

public class ForgotPasswordDto
{
    [Required]
    [EmailAddress]
    public string Email { get; set; } = string.Empty;
    
}