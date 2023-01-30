using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace API.Models
{
    public class AuthResult
    {
        public string Token { get; set; }   
        public string RefreshToken { get; set; }
        public bool Result { get; set; }    
        public List<string> Errors { get; set; }

    }
}