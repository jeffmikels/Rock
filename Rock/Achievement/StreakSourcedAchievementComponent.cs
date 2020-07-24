using System.Collections.Generic;
using System.Linq;
using Lucene.Net.Support;
using Rock.Data;
using Rock.Model;
using Rock.Web.Cache;

namespace Rock.Achievement
{
    /// <summary>
    /// Streak Sourced Achievement Component
    /// </summary>
    /// <seealso cref="Rock.Achievement.AchievementComponent" />
    public abstract class StreakSourcedAchievementComponent : AchievementComponent
    {
        /// <summary>
        /// Gets the supported configuration.
        /// </summary>
        public override AchievementConfiguration SupportedConfiguration =>
            new AchievementConfiguration( EntityTypeCache.Get<Streak>(), EntityTypeCache.Get<PersonAlias>() );

        /// <summary>
        /// Gets the source entities query.
        /// </summary>
        /// <param name="achievementTypeCache">The achievement type cache.</param>
        /// <param name="rockContext">The rock context.</param>
        /// <returns></returns>
        public override IQueryable<IEntity> GetSourceEntitiesQuery( AchievementTypeCache achievementTypeCache, RockContext rockContext )
        {
            if ( !achievementTypeCache.StreakTypeId.HasValue )
            {
                return Enumerable.Empty<Streak>().AsQueryable();
            }

            var service = new StreakService( rockContext );
            return service.Queryable().Where( s => s.StreakTypeId == achievementTypeCache.StreakTypeId );
        }

        /// <summary>
        /// Processes the specified achievement type cache for the source entity.
        /// </summary>
        /// <param name="rockContext">The rock context.</param>
        /// <param name="achievementTypeCache">The streak type achievement type cache.</param>
        /// <param name="sourceEntity">The source entity.</param>
        /// <returns>The set of attempts that were created or updated</returns>
        public override HashSet<AchievementAttempt> Process( RockContext rockContext, AchievementTypeCache achievementTypeCache, IEntity sourceEntity )
        {
            var streak = sourceEntity as Streak;
            var updatedAttempts = new HashSet<AchievementAttempt>();

            if ( streak == null )
            {
                return updatedAttempts;
            }

            // If the achievement type is not active (or null) then there is nothing to do
            if ( achievementTypeCache?.IsActive != true )
            {
                return updatedAttempts;
            }

            // If there are unmet prerequisites, then there is nothing to do
            var achievementTypeService = new AchievementTypeService( rockContext );
            var unmetPrerequisites = achievementTypeService.GetUnmetPrerequisites( achievementTypeCache.Id, streak.PersonAliasId );

            if ( unmetPrerequisites.Any() )
            {
                return updatedAttempts;
            }

            // Get all of the attempts for this streak and achievement combo, ordered by start date DESC so that
            // the most recent attempts can be found with FirstOrDefault
            var achievementAttemptService = new AchievementAttemptService( rockContext );
            var attempts = achievementAttemptService.QueryByStreakId( streak.Id )
                .Where( saa => saa.AchievementTypeId == achievementTypeCache.Id )
                .OrderByDescending( saa => saa.AchievementAttemptStartDateTime )
                .ToList();

            var mostRecentSuccess = attempts.FirstOrDefault( saa => saa.AchievementAttemptEndDateTime.HasValue && saa.IsSuccessful );
            var overachievementPossible = achievementTypeCache.AllowOverAchievement && mostRecentSuccess != null && !mostRecentSuccess.IsClosed;
            var successfulAttemptCount = attempts.Count( saa => saa.IsSuccessful );
            var maxSuccessesAllowed = achievementTypeCache.MaxAccomplishmentsAllowed ?? int.MaxValue;

            // If the most recent success is still open and overachievement is allowed, then update it
            if ( overachievementPossible )
            {
                UpdateOpenAttempt( mostRecentSuccess, achievementTypeCache, streak );
                updatedAttempts.Add( mostRecentSuccess );

                if ( !mostRecentSuccess.IsClosed )
                {
                    // New records can only be created once the open records are all closed
                    return updatedAttempts;
                }
            }

            // If the success count limit has been reached, then no more processing should be done
            if ( successfulAttemptCount >= maxSuccessesAllowed )
            {
                return updatedAttempts;
            }

            // Everything after the most recent success is on the table for deletion. Successes should not be
            // deleted. Everything after a success might be recalculated because of streak map data changes.
            // Try to reuse these attempts if they match for continuity, but if the start date is changed, they
            // get deleted.
            var attemptsToDelete = attempts;

            if ( mostRecentSuccess != null )
            {
                attemptsToDelete = attemptsToDelete
                    .Where( saa => saa.AchievementAttemptStartDateTime > mostRecentSuccess.AchievementAttemptStartDateTime )
                    .ToList();
            }

            var newAttempts = CreateNewAttempts( achievementTypeCache, streak, mostRecentSuccess );

            if ( newAttempts != null && newAttempts.Any() )
            {
                newAttempts = newAttempts.OrderBy( saa => saa.AchievementAttemptStartDateTime ).ToList();

                foreach ( var newAttempt in newAttempts )
                {
                    // Keep the old attempt if possible, otherwise add a new one
                    var existingAttempt = attemptsToDelete.FirstOrDefault( saa => saa.AchievementAttemptStartDateTime == newAttempt.AchievementAttemptStartDateTime );

                    if ( existingAttempt != null )
                    {
                        attemptsToDelete.Remove( existingAttempt );
                        CopyAttempt( newAttempt, existingAttempt );
                        updatedAttempts.Add( existingAttempt );
                    }
                    else
                    {
                        newAttempt.AchieverEntityId = streak.PersonAliasId;
                        newAttempt.AchievementTypeId = achievementTypeCache.Id;
                        achievementAttemptService.Add( newAttempt );
                        updatedAttempts.Add( newAttempt );
                    }

                    // If this attempt was successful then make re-check the max success limit
                    if ( newAttempt.IsSuccessful )
                    {
                        successfulAttemptCount++;

                        if ( successfulAttemptCount >= maxSuccessesAllowed )
                        {
                            break;
                        }
                    }
                }
            }

            if ( attemptsToDelete.Any() )
            {
                updatedAttempts.RemoveAll( attemptsToDelete );
                achievementAttemptService.DeleteRange( attemptsToDelete );
            }

            return updatedAttempts;
        }

        /// <summary>
        /// Update the open attempt record if there are changes. Be sure to close the attempt if it is no longer possible to make
        /// progress on this open attempt.
        /// </summary>
        /// <param name="openAttempt">The open attempt.</param>
        /// <param name="achievementTypeCache">The achievement type cache.</param>
        /// <param name="streak">The streak.</param>
        protected abstract void UpdateOpenAttempt( AchievementAttempt openAttempt, AchievementTypeCache achievementTypeCache, Streak streak );

        /// <summary>
        /// Create new attempt records and return them in a list. All new attempts should be after the most recent successful attempt.
        /// </summary>
        /// <param name="achievementTypeCache">The achievement type cache.</param>
        /// <param name="streak">The streak.</param>
        /// <param name="mostRecentSuccess">The most recent successful attempt.</param>
        /// <returns></returns>
        protected abstract List<AchievementAttempt> CreateNewAttempts( AchievementTypeCache achievementTypeCache, Streak streak, AchievementAttempt mostRecentSuccess );
    }
}
