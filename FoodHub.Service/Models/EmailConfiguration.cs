﻿using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FoodHub.Service.Models
{
    [NotMapped]
    public class EmailConfiguration
    {
        public string From { get; set; } =null!;
        public string SmtpServer { get; set; }=null!;
        public int Port { get; set; }
        public string Password { get; set; } = null!;
        public string UserName { get; set; } = null!;
    }
}
