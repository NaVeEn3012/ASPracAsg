using Microsoft.Extensions.Options;
using System.Net.Mail;
using SendGrid;
using SendGrid.Helpers.Mail;
using Microsoft.AspNetCore.Identity.UI.Services;
using Microsoft.Extensions.Configuration;

namespace ASPracAsg.Services
{
    public class EmailSender : IEmailSender
    {
        private readonly ILogger _logger;
        private readonly IConfiguration _configuration;

        public EmailSender(IOptions<AuthMessageSenderOptions> optionsAccessor,
                           ILogger<EmailSender> logger, IConfiguration configuration)
        {
            Options = optionsAccessor.Value;
            _logger = logger;
            _configuration = configuration;
        }

        public AuthMessageSenderOptions Options { get; }

        public async Task SendEmailAsync(string toEmail, string subject, string message)
        {
            await Execute(subject, message, toEmail);
        }


        public async Task Execute(string subject, string message, string toEmail)
        {
            var client = new SendGridClient(_configuration["SendGrid"]);
            var msg = new SendGridMessage()
            {
                From = new EmailAddress("navinbharathi@gmail.com", "FreshFarmMarket"),
                Subject = subject,
                PlainTextContent = message,
                HtmlContent = message
            };
            msg.AddTo(new EmailAddress(toEmail));

            // Disable click tracking.
            // See https://sendgrid.com/docs/User_Guide/Settings/tracking.html
            msg.SetClickTracking(false, false);
            var response = await client.SendEmailAsync(msg);
            _logger.LogInformation(response.IsSuccessStatusCode
                                   ? $"Email to {toEmail} queued successfully!"
                                   : $"{response.StatusCode.ToString()}");
        }
        public async Task SendOTPAsync(string toEmail, string subject, string message)
        {
            await ExecuteOTP(subject, message, toEmail);
        }
        public async Task ExecuteOTP(string subject, string message, string toEmail)
        {
            var client = new SendGridClient(_configuration["SendGrid"]);
            var msg = new SendGridMessage()
            {
                From = new EmailAddress("navinbharathi@gmail.com", "FreshFarmMarket"),
                Subject = subject,
                PlainTextContent = string.Format("Your OTP is :{0}", message),
                HtmlContent = string.Format("Your OTP is :{0}", message)
            };
            msg.AddTo(new EmailAddress(toEmail));

            // Disable click tracking.
            // See https://sendgrid.com/docs/User_Guide/Settings/tracking.html
            msg.SetClickTracking(false, false);
            var response = await client.SendEmailAsync(msg);
            _logger.LogInformation(response.IsSuccessStatusCode
                                   ? $"Email to {toEmail} queued successfully!"
                                   : $"{response.StatusCode.ToString()}");
        }
    }
}