using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity;

namespace API.Entity
{
    public class AppUser:IdentityUser<int>
    {
        public string Surname { get; set; }
        public int RegistrationNum { get; set; }
        public string Address { get; set; }
        public string RefreshToken{get;set;}=string.Empty;
        public DateTime TokenCreated { get; set; }
        public DateTime TokenExpires { get; set; }
    }
}