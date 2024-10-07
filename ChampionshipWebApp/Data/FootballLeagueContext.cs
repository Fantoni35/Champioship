
using Championship;
using Microsoft.EntityFrameworkCore;

public class FootballLeagueContext : DbContext
{
    public FootballLeagueContext(DbContextOptions<FootballLeagueContext> options)
        : base(options)
    {
    }

    public DbSet<Team> Teams { get; set; }
    public DbSet<Match> Matches { get; set; }
    public DbSet<MatchResult> MatchResults { get; set; }
    public DbSet<User> Users { get; set; }
    public DbSet<Language> Languages { get; set; }

    protected override void OnModelCreating(ModelBuilder modelBuilder)
    {
        modelBuilder.Entity<Team>(entity =>
        {
            entity.ToTable("Teams");
            entity.HasKey(t => t.Id);
            entity.Property(t => t.SquadName).IsRequired();
        });

        modelBuilder.Entity<Match>(entity =>
        {
            entity.ToTable("Matches");
            entity.HasKey(m => m.Id);

            entity.HasOne(m => m.HomeTeam)
                  .WithMany()
                  .HasForeignKey(m => m.HomeTeamId)
                  .OnDelete(DeleteBehavior.Restrict);

            entity.HasOne(m => m.AwayTeam)
                  .WithMany()
                  .HasForeignKey(m => m.AwayTeamId)
                  .OnDelete(DeleteBehavior.Restrict);

            entity.HasOne(m => m.Result)
                  .WithMany()
                  .HasForeignKey(m => m.ResultId)
                  .OnDelete(DeleteBehavior.SetNull);
        });

        modelBuilder.Entity<MatchResult>(entity =>
        {
            entity.ToTable("MatchResults");
            entity.HasKey(mr => mr.Id);
            entity.Property(mr => mr.HomeTeamScore).IsRequired();
            entity.Property(mr => mr.AwayTeamScore).IsRequired();
        });
    }

    public static void SeedLanguages(FootballLeagueContext context)
    {
        if (!context.Languages.Any())
        {
            context.Languages.AddRange(new List<Language>
        {
            new Language { Code = "en", Name = "English" },
            new Language { Code = "it", Name = "Italiano" },
            // Aggiungi altre lingue se necessario
        });
            context.SaveChanges();
        }
    }
}