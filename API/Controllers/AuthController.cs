using System;
using System.Collections.Generic;
using System.Diagnostics;
using System.IdentityModel.Tokens.Jwt;
using System.Linq;
using System.Security.Claims;
using System.Security.Cryptography;
using System.Text;
using System.Threading.Tasks;
using API.Configurations;
using API.Data;
using API.DTOs;
using API.Entity;
using API.Models;
using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Microsoft.Extensions.Logging;
using Microsoft.IdentityModel.Tokens;

namespace API.Controllers
{
    [Route("api/[Controller]")]
    [ApiController]
    public class AuthController : ControllerBase
    {

        private readonly UserManager<AppUser> _userManager;
        private readonly IConfiguration _configuration;
        private readonly TokenValidationParameters _tokenValidationParameters;
        private readonly StoreContext _context;

        public AuthController(UserManager<AppUser> userManager, IConfiguration configuration, StoreContext context, TokenValidationParameters tokenValidationParameters)
        {
            _configuration = configuration;
            _userManager = userManager;
            _context = context;
            _tokenValidationParameters = tokenValidationParameters;
        }

        [HttpPost]
        [Route("Register")]
        public async Task<IActionResult> Register([FromBody] UserRegistrationrequest registerUser)
        {
            if (ModelState.IsValid)
            {
                var user = await _userManager.FindByEmailAsync(registerUser.Email);

                if (user != null)
                {
                    return BadRequest(new AuthResult()
                    {
                        Result = false,
                        Errors = new List<string>()
                        {
                            "Email already exist"

                        }
                    });
                }

                var newUser = new AppUser()
                {
                    Email = registerUser.Email,
                    UserName = registerUser.Email
                };

                var isCreated = await _userManager.CreateAsync(newUser, registerUser.Password);

                if (isCreated.Succeeded)
                {
                    var token = await GenerateJwtToken(newUser);

                    return Ok(token);


                }
                return BadRequest(new AuthResult()
                {
                    Errors = new List<string>()
                    {
                        "Server Error"
                    },
                    Result = false
                });
            }

            return BadRequest();
        }

        [Route("Login")]
        [HttpPost]
        public async Task<IActionResult> Login([FromBody] UserLoginRequestDto loginUser)
        {
            if (ModelState.IsValid)
            {
                var existingUser = await _userManager.FindByEmailAsync(loginUser.Email);

                if (existingUser == null)
                {
                    return BadRequest(new AuthResult()
                    {
                        Errors = new List<string>()
                        {
                            "You are not a member",
                            "Please register"
                        },
                        Result = false
                    });
                }

                var isCorrect = await _userManager.CheckPasswordAsync(existingUser, loginUser.Password);

                if (!isCorrect)
                {
                    return BadRequest(new AuthResult()
                    {
                        Errors = new List<string>()
                        {
                            "Wrong password."
                        },
                        Result = false
                    });
                }

                var jwtToken = await GenerateJwtToken(existingUser);

                return Ok(jwtToken);


            }
            return BadRequest(new AuthResult()
            {
                Errors = new List<string>()
                {
                    "Please dont leave blanks"
                },
                Result = false
            });

        }

        private async Task<AuthResult> GenerateJwtToken(AppUser user)
        {
            var jwtTokenHandler = new JwtSecurityTokenHandler();

            var key = Encoding.UTF8.GetBytes(_configuration.GetSection("JwtConfig:Secret").Value);

            var tokenDescriptor = new SecurityTokenDescriptor()
            {
                Subject = new ClaimsIdentity(new[]
                {
                    new Claim(ClaimTypes.NameIdentifier ,user.Id.ToString()),
                    new Claim(JwtRegisteredClaimNames.Sub, user.Email),
                    new Claim(JwtRegisteredClaimNames.Email, user.Email),
                    new Claim(JwtRegisteredClaimNames.Jti, Guid.NewGuid().ToString()),
                    new Claim(JwtRegisteredClaimNames.Iat, DateTime.Now.ToUniversalTime().ToShortDateString())
                }),

                Expires = DateTime.UtcNow.Add(TimeSpan.Parse(_configuration.GetSection(key: "JwtConfig:ExpiryTimeFrame").Value)),
                SigningCredentials = new SigningCredentials(new SymmetricSecurityKey(key), SecurityAlgorithms.HmacSha256)
            };

            var token = jwtTokenHandler.CreateToken(tokenDescriptor);
            var jwtToken = jwtTokenHandler.WriteToken(token);

            var refreshToken = new RefreshToken()
            {
                JwtId = token.Id,
                Token = RandomStringGeneration(23),//genbeerat a refresh token
                AddedDate = DateTime.UtcNow,
                ExpiryDate = DateTime.UtcNow.AddMonths(6),
                IsRevoked = false,
                IsUsed = false,
                UserId = user.Id.ToString()

            };
            await _context.RefreshTokens.AddAsync(refreshToken);
            await _context.SaveChangesAsync();
            return new AuthResult()
            {
                Token = jwtToken,
                RefreshToken = refreshToken.Token,
                Result = true
            };




        }
        [HttpPost]
        [Route(template: "RefreshToken")]
        public async Task<IActionResult> RefreshToken([FromBody] TokenRequest tokenRequest)
        {
            if (ModelState.IsValid)
            {
                var result = VerifyAndGenerateToken(tokenRequest);
                if (result == null)
                {
                    return BadRequest(error: new AuthResult()
                    {
                        Errors = new List<string>(){
                    "geçersiz token"
                },
                        Result = false
                    });
            
                }
                return Ok(result);


            }
            return BadRequest(error: new AuthResult()
            {
                Errors = new List<string>(){
                    "GEÇERSİZ"
                },
                Result = false
            });



        }
        private async Task<AuthResult> VerifyAndGenerateToken(TokenRequest tokenRequest)
        {
            var jwtTokenHandler= new JwtSecurityTokenHandler();
            try{
                _tokenValidationParameters.ValidateLifetime=false;
                var tokenInVerification= jwtTokenHandler.ValidateToken(tokenRequest.Token,_tokenValidationParameters ,out var validatetoken);
                if(validatetoken is JwtSecurityToken jwtSecurityToken){
                    var result = jwtSecurityToken.Header.Alg.Equals(SecurityAlgorithms.HmacSha256,StringComparison.InvariantCultureIgnoreCase);
                    if(result==false){
                        return null;
                    }

                        
                }
                var utcExpireyDate= long.Parse(tokenInVerification.Claims.FirstOrDefault(x=>x.Type==JwtRegisteredClaimNames.Exp).Value);
                var expiryDate=UnixTimeStampToDateTime(utcExpireyDate);
                if(expiryDate>DateTime.Now){
                    return new AuthResult(){
                        Result=false,
                        Errors=new List<string>(){
                            "expired token"
                        }
                    };
                
                    
                }
                var storedToken= await _context.RefreshTokens.FirstOrDefaultAsync(x=>x.Token==tokenRequest.RefreshToken);
                if(storedToken==null){
                    return new AuthResult(){
                        Result=false,
                         Errors=new List<string>(){
                            "invalid token"
                        }

                    };
                }
                if(storedToken.IsUsed){
                    return new AuthResult(){
                        Result=false,
                         Errors=new List<string>(){
                            "invalid token"
                        }};};
                if(storedToken.IsRevoked){
                    return new AuthResult(){
                        Result=false,
                         Errors=new List<string>(){
                            "invalid token"
                        }};
                }
                var jti=tokenInVerification.Claims.FirstOrDefault(x=>x.Type==JwtRegisteredClaimNames.Acr).Value;
                if(storedToken.JwtId !=jti ){
                    return new AuthResult(){
                        Result=false,
                         Errors=new List<string>(){
                            "invalid token"
                        }};
                

                }
                if(storedToken.ExpiryDate<DateTime.UtcNow){
                      return new AuthResult(){
                        Result=false,
                         Errors=new List<string>(){
                            "expired token"
                        }

                };};
            storedToken.IsUsed=true;
            _context.RefreshTokens.Update(storedToken);
            await _context.SaveChangesAsync();//burada sen email async yazabilirsin idde sıkıntı olursa
            var storeuser=await _userManager.FindByIdAsync(storedToken.UserId);
            return await GenerateJwtToken(storeuser);





            }catch(Exception e){
                 return new AuthResult(){
                        Result=false,
                         Errors=new List<string>(){
                            "expired token"
                        }
                        };
               
                

            }

        }
        private DateTime  UnixTimeStampToDateTime(long unixtimestamp){
            var dateTimeVal=new DateTime(year:1970,month:1,day:1,hour:0,minute:0,0,0,DateTimeKind.Utc);
            dateTimeVal=dateTimeVal.AddSeconds(unixtimestamp).ToUniversalTime();
            return dateTimeVal;
        }
        private string RandomStringGeneration(int length)
        {
            var random = new Random();
            var chars = "ABCDEFGHIJKLMNOPRSTUWXYZ1234567890abcdefgh";
            return new string(Enumerable.Repeat(chars, length).Select(s => s[random.Next(s.Length)]).ToArray());

        }





























    }
}