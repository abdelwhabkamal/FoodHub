using Microsoft.AspNetCore.Authorization;
using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace FoodHub.Controllers
{
    [Authorize(Roles ="Admin")]
    [Route("api/[controller]")]
    [ApiController]
    public class AdminController : ControllerBase
    {
        // for test
        [HttpGet]
        public IEnumerable<string> Get()=>new List<string> {"Abdelwahab","Moataz","Ahmed"};
    }
}
