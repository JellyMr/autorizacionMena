using System.IdentityModel.Tokens.Jwt;
using System.Net;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using AuthAPI.Api.Dto;
using AuthAPI.Models;
using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.IdentityModel.Tokens;
using RestSharp;

namespace AuthAPI.Controllers;

[Authorize]
[ApiController]
[Route("api/[controller]")]
//api/account
public class AccountController(UserManager<AppUser> userManager, IConfiguration configuration)
    : ControllerBase
{
    // api/account/register
    [AllowAnonymous]
    [HttpPost("register")]
    public async Task<ActionResult<string>> Register(RegisterDto registerDto)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var user = new AppUser
        {
            Email = registerDto.Email,
            FullName = registerDto.FullName,
            UserName = registerDto.UserName
        };

        var result = await userManager.CreateAsync(user, registerDto.Password);

        if (!result.Succeeded)
        {
            return BadRequest(result.Errors);
        }

        if (registerDto.Roles is null)
        {
            await userManager.AddToRoleAsync(user, "User");
        }
        else
        {
            foreach (var role in registerDto.Roles)
            {
                await userManager.AddToRoleAsync(user, role);
            }
        }

        return Ok(new AuthResponseDto
        {
            IsSuccess = true,
            Message = "Account Created Successfully!!!"
        });
    }

    // api/account/login
    [AllowAnonymous]
    [HttpPost("login")]
    public async Task<ActionResult<AuthResponseDto>> Login(LoginDto loginDto)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var user = await userManager.FindByEmailAsync(loginDto.Email);

        if (user == null)
        {
            return Unauthorized(new AuthResponseDto
            {
                IsSuccess = false,
                Message = "User not found with this email"
            });
        }

        var result = await userManager.CheckPasswordAsync(user, loginDto.Password);

        if (!result)
        {
            return Unauthorized(new AuthResponseDto
            {
                IsSuccess = false,
                Message = "Invalid Password"
            });
        }

        var token = GenerateToken(user);
        var refreshToken = GenerateRefreshToken();
        _ = int.TryParse(configuration.GetSection("JTWSetting").GetSection("RefreshTokenValidityIn").Value!,
            out var refreshTokenValidityIn);
        user.RefreshToken = refreshToken;
        user.RefreshTokenExpiryTime = DateTime.UtcNow.AddMinutes(refreshTokenValidityIn);
        await userManager.UpdateAsync(user);

        return Ok(new AuthResponseDto
        {
            Token = token,
            IsSuccess = true,
            Message = "Login Success",
            RefreshToken = refreshToken
        });
    }

    // api/account/refresh-token
    [AllowAnonymous]
    [HttpPost("refresh-token")]
    public async Task<ActionResult<AuthResponseDto>> Refresh(TokenDto tokenDto)
    {
        if (!ModelState.IsValid)
        {
            return BadRequest(ModelState);
        }

        var principal = GetPrincipalFromExpiredToken(tokenDto.Token);
        var user = await userManager.FindByEmailAsync(tokenDto.Email);

        // ReSharper disable once ConditionIsAlwaysTrueOrFalseAccordingToNullableAPIContract
        if (principal is null || user is null || user.RefreshToken != tokenDto.RefreshToken ||
            user.RefreshTokenExpiryTime <= DateTime.UtcNow)
            return BadRequest(new AuthResponseDto
            {
                IsSuccess = false,
                Message = "Invalid client request"
            });

        var newJwtToken = GenerateToken(user);
        var newRefreshToken = GenerateRefreshToken();
        _ = int.TryParse(configuration.GetSection("JTWSetting").GetSection("RefreshTokenValidityIn").Value!,
            out var refreshTokenValidityIn);
        user.RefreshToken = newRefreshToken;
        user.RefreshTokenExpiryTime = DateTime.UtcNow.AddMinutes(refreshTokenValidityIn);

        await userManager.UpdateAsync(user);

        return Ok(new AuthResponseDto
        {
            IsSuccess = true,
            Token = newJwtToken,
            RefreshToken = newRefreshToken,
            Message = "Refreshed token successfully."
        });
    }

    private ClaimsPrincipal GetPrincipalFromExpiredToken(string token)
    {
        var tokenParameters = new TokenValidationParameters
        {
            ValidateAudience = false,
            ValidateIssuer = false,
            ValidateIssuerSigningKey = true,
            IssuerSigningKey =
                new SymmetricSecurityKey(
                    Encoding.UTF8.GetBytes(configuration.GetSection("JwtSetting").GetSection("securityKey").Value!)),
            ValidateLifetime = false
        };

        var tokenHandler = new JwtSecurityTokenHandler();
        var principal = tokenHandler.ValidateToken(token, tokenParameters, out SecurityToken securityToken);

        if (securityToken is not JwtSecurityToken jwtSecurityToken ||
            !jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256, StringComparison.InvariantCulture))
            throw new SecurityTokenException("Invalid token");

        return principal;
    }

    [AllowAnonymous]
    [HttpPost("forgot-password")]
    public async Task<ActionResult> ForgotPassword(ForgotPasswordDto forgotPasswordDto)
    {
        var user = await userManager.FindByEmailAsync(forgotPasswordDto.Email);

        if (user is null)
        {
            return Ok(new AuthResponseDto
            {
                IsSuccess = false,
                Message = "User does not exist with this email"
            });
        }

        var token = await userManager.GeneratePasswordResetTokenAsync(user);
        var resetLink = $"http://localhost:4200/reset-password?email={user.Email}&token={WebUtility.UrlEncode(token)}";

        var client = new RestClient("https://send.api.mailtrap.io/api/send");

        var request = new RestRequest
        {
            Method = Method.Post,
            RequestFormat = DataFormat.Json
        };

        request.AddHeader("Authorization", "Bearer 21e8652dcb07996a60f73e88850a6c3e");
        request.AddJsonBody(new
        {
            from = new { email = "mailtrap@demomailtrap.com" },
            to = new[] { new { email = user.Email } },
            template_uuid = "e321b852-c2d6-4263-a58a-9febf625d1b6",
            template_variables = new { user_email = user.Email, pass_reset_link = resetLink }
        });

        var response = client.Execute(request);

        if (response.IsSuccessful)
        {
            return Ok(new AuthResponseDto
            {
                IsSuccess = true,
                Message = "Email sent with password reset link. Please check your email."
            });
        }
        else
        {
            return BadRequest(new AuthResponseDto
            {
                IsSuccess = false,
                Message = response.Content!
            });
        }
    }

    [AllowAnonymous]
    [HttpPost("reset-password")]
    public async Task<IActionResult> ResetPassword(ResetPasswordDto resetPasswordDto)
    {
        var user = await userManager.FindByEmailAsync(resetPasswordDto.Email);
        // resetPasswordDto.Token = WebUtility.UrlDecode(resetPasswordDto.Token);

        if (user is null)
        {
            return BadRequest(new AuthResponseDto
            {
                IsSuccess = false,
                Message = "User does not exist with this email."
            });
        }

        var result = await userManager.ResetPasswordAsync(user, resetPasswordDto.Token, resetPasswordDto.NewPassword);

        if (result.Succeeded)
        {
            return Ok(new AuthResponseDto
            {
                IsSuccess = true,
                Message = "Password reset Successfully."
            });
        }

        return BadRequest(new AuthResponseDto
        {
            IsSuccess = false,
            Message = result.Errors.FirstOrDefault()!.Description
        });
    }

    [HttpPost("change-password")]
    public async Task<ActionResult> ChangePassword(ChangePasswordDto dto)
    {
        var user = await userManager.FindByEmailAsync(dto.Email);

        if (user is null)
        {
            return BadRequest(new AuthResponseDto
            {
                IsSuccess = false,
                Message = "User does not exist with this email"
            });
        }

        var result = await userManager.ChangePasswordAsync(user, dto.CurrentPassword, dto.NewPassword);

        if (result.Succeeded)
        {
            return Ok(new AuthResponseDto
            {
                IsSuccess = true,
                Message = "Password changed successfully"
            });
        }

        return BadRequest(new AuthResponseDto
        {
            IsSuccess = false,
            Message = result.Errors.FirstOrDefault()!.Description
        });
    }

    private string GenerateRefreshToken()
    {
        var randomNumber = new byte[32];
        using var rng = RandomNumberGenerator.Create();
        rng.GetBytes(randomNumber);

        return Convert.ToBase64String(randomNumber);
    }

    private string GenerateToken(AppUser user)
    {
        var tokenHandler = new JwtSecurityTokenHandler();
        var key = Encoding.ASCII.GetBytes(configuration.GetSection("JWTSetting").GetSection("securityKey").Value!);
        var roles = userManager.GetRolesAsync(user).Result;

        List<Claim> claims =
        [
            new(JwtRegisteredClaimNames.Email, user.Email ?? ""),
            new(JwtRegisteredClaimNames.Name, user.FullName ?? ""),
            new(JwtRegisteredClaimNames.NameId, user.Id),
            new(JwtRegisteredClaimNames.Aud,
                configuration.GetSection("JWTSetting").GetSection("ValidAudience").Value!),
            new(JwtRegisteredClaimNames.Iss, configuration.GetSection("JWTSetting").GetSection("ValidIssuer").Value!)
        ];
        claims.AddRange(roles.Select(role => new Claim(ClaimTypes.Role, role)));

        var tokenDescriptor = new SecurityTokenDescriptor
        {
            Subject = new ClaimsIdentity(claims),
            Expires = DateTime.UtcNow.AddMinutes(1),
            SigningCredentials = new SigningCredentials(
                new SymmetricSecurityKey(key),
                SecurityAlgorithms.HmacSha256
            )
        };

        var token = tokenHandler.CreateToken(tokenDescriptor);
        return tokenHandler.WriteToken(token);
    }

    // api/account/detail
    [Authorize]
    [HttpGet("detail")]
    public async Task<ActionResult<UserDetailDto>> GetUserDetail()
    {
        var currentUserId = User.FindFirstValue(ClaimTypes.NameIdentifier);
        var user = await userManager.FindByIdAsync(currentUserId!);

        if (user == null)
        {
            return NotFound(new AuthResponseDto
            {
                IsSuccess = false,
                Message = "User not found"
            });
        }

        return Ok(new UserDetailDto
        {
            Id = user.Id,
            Email = user.Email,
            FullName = user.FullName,
            Roles = [..await userManager.GetRolesAsync(user)],
            PhoneNumber = user.PhoneNumber,
            PhoneNumberConfirmed = user.PhoneNumberConfirmed,
            AccessFailedCount = user.AccessFailedCount
        });
    }

    // api/account/
    [HttpGet]
    public async Task<ActionResult<IEnumerable<UserDetailDto>>> GetUsers()
    {
        var users = await userManager.Users.Select(u => new UserDetailDto
        {
            Id = u.Id,
            Email = u.Email,
            FullName = u.FullName,
            Roles = userManager.GetRolesAsync(u).Result.ToArray()
        }).ToListAsync();

        return Ok(users);
    }
}