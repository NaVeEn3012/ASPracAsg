using ASPracAsg.Model;

namespace ASPracAsg.Services
{
    public class AuditLogService
    {
        private readonly AuthDbContext _dbContext;

        public AuditLogService(AuthDbContext dbContext)
        {
            _dbContext = dbContext;
        }

        public async Task LogAsync(ApplicationUser user, string activity)
        {
            var auditLog = new AuditLog
            {
                UserId = user.Id,
                Activity = activity,
                DateTime = DateTime.Now
            };

            _dbContext.AuditLogs.Add(auditLog);
            await _dbContext.SaveChangesAsync();
        }
    }
}
