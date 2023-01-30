using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;

namespace API.DTOs
{
    public class UserDto
    {
        public string Id { get; set; }
        public string Email { get; set; }
        public string FirstName { get; set; }
        public string LastName { get; set; }

        public DateTime CreationDatetime {get;set;}
        public bool EmailConfirmed { get; set; }
        public bool IsLocked { get; set; }
        public string RoleName { get; set; }
    }
}