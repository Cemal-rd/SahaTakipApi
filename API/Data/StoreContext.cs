using System;
using System.Collections.Generic;
using System.Linq;
using System.Threading.Tasks;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;
using API.Entity;
using API.Models;

namespace API.Data
{
    public class StoreContext : IdentityDbContext<AppUser,AppRole,int>
    {
        public DbSet<RefreshToken> RefreshTokens{get;set;}
        
        public StoreContext(DbContextOptions options) : base(options)
        {

        }
    }
}