using Microsoft.AspNetCore.Mvc;
using Microsoft.EntityFrameworkCore;
using Championship;
using Serilog;
namespace ChampionshipWebApp.Controllers;

public class TeamsController : Controller
{
    private readonly FootballLeagueContext _context;


    public TeamsController(FootballLeagueContext context)
    {
        _context = context;
    }
    public IActionResult AddTeams()
    {
        return View();
    }

   [HttpPost]
public async Task<IActionResult> AddTeam(string SquadName, int FondationYear, string City, string ColorOfClub, string StadiumName)
{
    Team existingTeam = null;

    

    if ((existingTeam == null && !await _context.Teams.AnyAsync(t => t.SquadName.ToLower() == SquadName.ToLower())) &&
        !string.IsNullOrWhiteSpace(SquadName) &&
        !string.IsNullOrWhiteSpace(City) &&
        !string.IsNullOrWhiteSpace(ColorOfClub) &&
        !string.IsNullOrWhiteSpace(StadiumName) &&
        FondationYear > 0)
    {
        if (existingTeam != null)
        {
            existingTeam.SquadName = SquadName;
            existingTeam.FondationYear = FondationYear;
            existingTeam.City = City;
            existingTeam.ColorOfClub = ColorOfClub;
            existingTeam.StadiumName = StadiumName;

            existingTeam.UpdatedAt = DateTime.Now;

            _context.Teams.Update(existingTeam);
        }
        else
        {
            var newTeam = new Team(SquadName, FondationYear, City, ColorOfClub, StadiumName)
            {
                CreatedAt = DateTime.Now, 
                UpdatedAt = DateTime.Now,  
                CreatedBy = User.Identity.Name,
                ModifiedBy = User.Identity.Name

            };
            
            _context.Teams.Add(newTeam);
        }

        await _context.SaveChangesAsync();

        var matches = await _context.Matches.ToListAsync();
        var matchResults = await _context.MatchResults.ToListAsync();
        _context.Matches.RemoveRange(matches);
        _context.MatchResults.RemoveRange(matchResults);
        await _context.SaveChangesAsync();

        var teams = await _context.Teams.ToListAsync();
        var calendar = GenerateCalendar(teams);
        await _context.Matches.AddRangeAsync(calendar.SelectMany(matchday => matchday));
        await _context.SaveChangesAsync();

        return RedirectToAction("Index", "Home");
    }

    Log.Error("Error adding or updating the team.. SquadName: {SquadName}, FondationYear: {FondationYear}, City: {City}, ColorOfClub: {ColorOfClub}, StadiumName: {StadiumName}", SquadName, FondationYear, City, ColorOfClub, StadiumName);
    return View("Error");
}



    [HttpGet]
    public async Task<IActionResult> Edit(string squadName)
    {
        var team = await _context.Teams.FirstOrDefaultAsync(t => t.SquadName == squadName);
        if (team == null)
        {
            return NotFound();
        }
        return View(team);
    }

    [HttpPost]
    public async Task<IActionResult> Edit(int id, string squadName, int fondationYear, string city, string colorOfClub, string stadiumName)
    {
        if (ModelState.IsValid)
        {
            var existingTeam = await _context.Teams.FirstOrDefaultAsync(t => t.Id == id);
            if (existingTeam != null)
            {
                bool squadNameExists = await _context.Teams
                    .AnyAsync(t => t.SquadName.ToLower() == squadName.ToLower() && t.Id != id);

                if (squadNameExists)
                {
                    ModelState.AddModelError("SquadName", "The squad name already exists.");
                    return View(existingTeam);
                }

                existingTeam.SquadName = squadName;
                existingTeam.FondationYear = fondationYear;
                existingTeam.City = city;
                existingTeam.ColorOfClub = colorOfClub;
                existingTeam.StadiumName = stadiumName;
                existingTeam.UpdatedAt = DateTime.Now;
                existingTeam.ModifiedBy = User.Identity.Name;

               
                _context.Teams.Update(existingTeam);
                await _context.SaveChangesAsync();

                return RedirectToAction("Index", "Home");
            }
            return View("Error"); 
        }
        return View(); 
    }


    [HttpPost]
    public async Task<IActionResult> Delete(int id)
    {
        var team = await _context.Teams.FindAsync(id);  
        if (team != null)
        {
            _context.Teams.Remove(team);

            var matches = await _context.Matches.ToListAsync();
            var matchResults = await _context.MatchResults.ToListAsync();
            _context.Matches.RemoveRange(matches);
            _context.MatchResults.RemoveRange(matchResults);
            await _context.SaveChangesAsync();

            var teams = await _context.Teams.ToListAsync();
            if (teams.Count >= 2)
            {
                var calendar = GenerateCalendar(teams);
                await _context.Matches.AddRangeAsync(calendar.SelectMany(matchday => matchday));
                await _context.SaveChangesAsync();
            }

            return RedirectToAction("Index", "Home");
        }
        return View("Error");
    }




    [HttpGet]
    public async Task<IActionResult> ViewCalendar()
    {
        var teams = await _context.Teams.ToListAsync();
        if (teams.Count < 2)
        {
            Log.Error("Insufficient teams to generate calendar. Number of teams: {TeamCount}", teams.Count);
            ViewBag.Message = "There are no teams, please enter at least 2.";
            return View("Calendar");
        }

        if (teams.Count % 2 != 0)
        {
            Log.Error("Odd number of teams found. Number of teams: {TeamCount}", teams.Count);
            ViewBag.Message = "The number of teams entered is odd, add at least one other team.";
            return View("Calendar");
        }

        var existingMatches = await _context.Matches.AnyAsync();
        if (!existingMatches)
        {
            var calendar = GenerateCalendar(teams);
            foreach (var matchday in calendar)
            {
                _context.Matches.AddRange(matchday);
            }
            await _context.SaveChangesAsync();
        }

        var matches = await _context.Matches.Include(m => m.Result).Include(m => m.HomeTeam).Include(m => m.AwayTeam).ToListAsync();
        var groupedMatches = matches.GroupBy(m => m.MatchDate.Date)
                                    .OrderBy(g => g.Key)
                                    .Select(g => g.ToList())
                                    .ToList();

        return View("Calendar", groupedMatches);
    }


    private async Task SaveMatchResults(List<List<Match>> calendar)
    {
        Random random = new Random();
        foreach (var matchday in calendar)
        {
            foreach (var match in matchday)
            {
                int homeGoals = random.Next(0, 4);
                int awayGoals = random.Next(0, 4);

                var result = new MatchResult(homeGoals, awayGoals);
                match.SetResult(result);

                _context.Matches.Add(match);
                _context.MatchResults.Add(result);
            }
        }

        await _context.SaveChangesAsync();
    }

    private List<List<Match>> GenerateCalendar(List<Team> teams)
    {
        var calendar = new List<List<Match>>();
        int numTeams = teams.Count;
        int numMatchdays = numTeams - 1;

        DateTime startDate = DateTime.Now;

        var rotatingTeams = new List<Team>(teams);

        for (int round = 0; round < numMatchdays; round++)
        {
            var matchday = new List<Match>();

            for (int j = 0; j < numTeams / 2; j++)
            {
                var homeTeam = rotatingTeams[j];
                var awayTeam = rotatingTeams[numTeams - 1 - j];

                var matchDate = startDate.AddDays(round * 7);
                var match = new Match(homeTeam, awayTeam, matchDate, homeTeam.StadiumName, homeTeam.City);
                matchday.Add(match);
            }

            calendar.Add(matchday);

            var lastTeam = rotatingTeams[numTeams - 1];
            rotatingTeams.RemoveAt(numTeams - 1);
            rotatingTeams.Insert(1, lastTeam);
        }

        for (int round = 0; round < numMatchdays; round++)
        {
            var matchday = new List<Match>();

            for (int j = 0; j < numTeams / 2; j++)
            {
                var homeTeam = rotatingTeams[numTeams - 1 - j];
                var awayTeam = rotatingTeams[j];

                var matchDate = startDate.AddDays((numMatchdays + round) * 7);
                var match = new Match(homeTeam, awayTeam, matchDate, homeTeam.StadiumName, homeTeam.City);
                matchday.Add(match);
            }

            calendar.Add(matchday);

            var lastTeam = rotatingTeams[numTeams - 1];
            rotatingTeams.RemoveAt(numTeams - 1);
            rotatingTeams.Insert(1, lastTeam);
        }

        return calendar;
    }



    [HttpPost]
    public IActionResult Rankings()
    {
        var rankings = GenerateRankings();
        return View("Rankings", rankings);
    }

    private Dictionary<Team, TeamStats> GenerateRankings()
    {
        var rankings = new Dictionary<Team, TeamStats>();


        var teams = _context.Teams.ToList();


        foreach (var team in teams)
        {
            rankings[team] = new TeamStats();
        }


        var matches = _context.Matches.Include(m => m.Result).Include(m => m.HomeTeam).Include(m => m.AwayTeam).ToList();

        foreach (var match in matches)
        {
            if (match.Result != null)
            {
                var homeTeamStats = rankings[match.HomeTeam];
                var awayTeamStats = rankings[match.AwayTeam];


                homeTeamStats.GamesPlayed++;
                awayTeamStats.GamesPlayed++;


                homeTeamStats.GoalsFor += match.Result.HomeTeamScore;
                homeTeamStats.GoalsAgainst += match.Result.AwayTeamScore;
                awayTeamStats.GoalsFor += match.Result.AwayTeamScore;
                awayTeamStats.GoalsAgainst += match.Result.HomeTeamScore;


                if (match.Result.HomeTeamScore > match.Result.AwayTeamScore)
                {
                    homeTeamStats.Wins++;
                    homeTeamStats.Points += 3;
                    awayTeamStats.Losses++;
                }
                else if (match.Result.HomeTeamScore < match.Result.AwayTeamScore)
                {
                    awayTeamStats.Wins++;
                    awayTeamStats.Points += 3;
                    homeTeamStats.Losses++;
                }
                else
                {
                    homeTeamStats.Draws++;
                    awayTeamStats.Draws++;
                    homeTeamStats.Points += 1;
                    awayTeamStats.Points += 1;
                }
            }
        }


        var sortedRankings = rankings.OrderByDescending(r => r.Value.Points)
                                     .ThenByDescending(r => r.Value.GoalDifference)
                                     .ThenByDescending(r => r.Value.GoalsFor)
                                     .ToDictionary(r => r.Key, r => r.Value);
        return sortedRankings;
    }
    [HttpPost]
    public async Task<IActionResult> SubmitResult(int matchId, int homeTeamScore, int awayTeamScore)
    {
        var match = await _context.Matches.Include(m => m.Result).FirstOrDefaultAsync(m => m.Id == matchId);
        if (match != null)
        {
            var matchday = match.MatchDate.Date;
            var previousMatchdayDate = matchday.AddDays(-7);

            var previousMatchdayMatches = await _context.Matches
                .Where(m => m.MatchDate.Date == previousMatchdayDate)
                .Include(m => m.Result)
                .ToListAsync();

            bool previousMatchdayComplete = previousMatchdayMatches.All(m => m.Result != null);

            if (!previousMatchdayComplete)
            {
                Log.Error("Attempt to submit results without all previous matchday results. MatchId: {MatchId}", matchId);
                ViewBag.Message = "Please enter results for all matches from the previous matchday before submitting results for this matchday.";

                var teams = await _context.Teams.ToListAsync();
                var groupedMatches = await GetGroupedMatches(teams);
                return View("Calendar", groupedMatches);
            }


            if (match.Result == null)
            {
                var result = new MatchResult(homeTeamScore, awayTeamScore);
                match.SetResult(result);
                await _context.SaveChangesAsync();
            }
            else
            {
                match.Result.HomeTeamScore = homeTeamScore;
                match.Result.AwayTeamScore = awayTeamScore;
                await _context.SaveChangesAsync();
            }
        }

        return RedirectToAction("ViewCalendar");
    }


    private async Task<List<List<Match>>> GetGroupedMatches(List<Team> teams)
    {
        var matches = await _context.Matches.Include(m => m.Result).Include(m => m.HomeTeam).Include(m => m.AwayTeam).ToListAsync();
        return matches.GroupBy(m => m.MatchDate.Date)
                      .OrderBy(g => g.Key)
                      .Select(g => g.ToList())
                      .ToList();
    }

    [HttpPost]
    public async Task<IActionResult> EditResult(int matchId)
    {
        var match = await _context.Matches
            .Include(m => m.HomeTeam)
            .Include(m => m.AwayTeam)
            .FirstOrDefaultAsync(m => m.Id == matchId);

        if (match == null)
        {
            return NotFound();
        }

        match.EditMode = true;

        var matches = await _context.Matches
            .Include(m => m.HomeTeam)
            .Include(m => m.AwayTeam)
            .Include(m => m.Result)
            .ToListAsync();

        var groupedMatches = matches.GroupBy(m => m.MatchDate.Date)
                                    .OrderBy(g => g.Key)
                                    .Select(g => g.ToList())
                                    .ToList();

        return View("Calendar", groupedMatches);
    }

}
