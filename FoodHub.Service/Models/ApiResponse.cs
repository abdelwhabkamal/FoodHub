using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FoodHub.Service.Models
{
    [NotMapped]
    public class ApiResponse<T>
    {
        public bool IsSuccessed { get; set; }
        public string? Message { get; set; }
        public int StatusCode { get; set; }
        public T Response { get; set; }
    }
}
