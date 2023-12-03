using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FoodHub.Service.Models.Authentication.User
{
    [NotMapped]
    public class JwtToken
    {
        public string Token { get; set; }
        public DateTime ExpiryTokenDate { get; set; }
    }
}
