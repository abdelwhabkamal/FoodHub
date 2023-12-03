using MimeKit;
using System;
using System.Collections.Generic;
using System.ComponentModel.DataAnnotations.Schema;
using System.Linq;
using System.Text;
using System.Threading.Tasks;

namespace FoodHub.Service.Models
{
    [NotMapped]
    public class Message
    {
        public List<MailboxAddress> To { get; set; }
        public string Subject {  get; set; }
        public string Content { get; set; }
        public Message(IEnumerable<string> to,string subject,string content) {
            To = new List<MailboxAddress>();
            To.AddRange(to.Select(x => new MailboxAddress("email", x)));
            Subject = subject;
            Content = content;  
        }
    }
}
