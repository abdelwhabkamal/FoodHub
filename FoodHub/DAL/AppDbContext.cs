using Microsoft.AspNetCore.Identity;
using Microsoft.AspNetCore.Identity.EntityFrameworkCore;
using Microsoft.EntityFrameworkCore;

namespace FoodHub.DAL
{
    public class AppDbContext:IdentityDbContext<IdentityUser>
    {
        public AppDbContext(DbContextOptions<AppDbContext> options) : base(options) { }
        protected override void OnModelCreating(ModelBuilder builder)
        {
            base.OnModelCreating(builder);
            //seedRole(builder);
        }
        private static void seedRole(ModelBuilder modelBuilder)
        {
            modelBuilder.Entity<IdentityRole>().HasData(
                new IdentityRole() { Name = "Admin", ConcurrencyStamp = "1", NormalizedName = "admin" },
                new IdentityRole() { Name = "User", ConcurrencyStamp = "2", NormalizedName = "user" },
                new IdentityRole() { Name = "Delivery", ConcurrencyStamp = "3", NormalizedName = "delivery" }
                );
        }
    }
}
