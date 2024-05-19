using Microsoft.AspNetCore.Http;
using Microsoft.AspNetCore.Mvc;

namespace SoftServerCinema.Security.DTOs
{
    public class EmailWithAttachmentsDTO
    {
        [FromForm(Name = "To")]
        public string To { get; set; }

        [FromForm(Name = "Subject")]
        public string Subject { get; set; }

        [FromForm(Name = "pdf")]
        public IFormFile PdfAttachment { get; set; }

        [FromForm(Name = "qrCode")]
        public IFormFile QrCodeAttachment { get; set; }
    }
}
