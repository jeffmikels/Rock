﻿// <copyright>
// Copyright by the Spark Development Network
//
// Licensed under the Rock Community License (the "License");
// you may not use this file except in compliance with the License.
// You may obtain a copy of the License at
//
// http://www.rockrms.com/license
//
// Unless required by applicable law or agreed to in writing, software
// distributed under the License is distributed on an "AS IS" BASIS,
// WITHOUT WARRANTIES OR CONDITIONS OF ANY KIND, either express or implied.
// See the License for the specific language governing permissions and
// limitations under the License.
// </copyright>
//

using System;
using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.Composition;
using System.Linq;
using Rock.Attribute;
using Rock.Data;
using Rock.Model;
using Rock.Web.Cache;

namespace Rock.Achievement.Component
{
    /// <summary>
    /// Use to track achievements earned by engaging a specified number of times
    /// </summary>
    /// <seealso cref="Rock.Achievement.AchievementComponent" />
    [Description( "Use to track achievements earned by engaging a specified number of times" )]
    [Export( typeof( AchievementComponent ) )]
    [ExportMetadata( "ComponentName", "Streaks: Accumulative" )]

    [IntegerField(
        name: "Number to Accumulate",
        description: "The number of engagements required to earn this achievement.",
        required: true,
        order: 0,
        key: AttributeKey.NumberToAccumulate )]

    [IntegerField(
        name: "Timespan in Days",
        description: "The sliding window of days in which the engagements must occur.",
        required: false,
        order: 1,
        key: AttributeKey.TimespanInDays )]

    [DateField(
        name: "Start Date",
        description: "The date that defines when the engagements must occur on or after.",
        required: false,
        order: 2,
        key: AttributeKey.StartDateTime )]

    [DateField(
        name: "End Date",
        description: "The date that defines when the engagements must occur on or before.",
        required: false,
        order: 3,
        key: AttributeKey.EndDateTime )]

    [StreakTypeField(
        name: "Streak Type",
        description: "The source streak type from which achievements are earned.",
        required: true,
        order: 4,
        key: AttributeKey.StreakType )]

    public class AccumulativeAchievement : StreakSourcedAchievementComponent
    {
        #region Keys

        /// <summary>
        /// Keys to use for the attributes
        /// </summary>
        public static class AttributeKey
        {
            /// <summary>
            /// The number to accumulate
            /// </summary>
            public const string NumberToAccumulate = "NumberToAccumulate";

            /// <summary>
            /// The timespan in days
            /// </summary>
            public const string TimespanInDays = "TimespanInDays";

            /// <summary>
            /// The Start Date Time
            /// </summary>
            public const string StartDateTime = "StartDateTime";

            /// <summary>
            /// The End Date Time
            /// </summary>
            public const string EndDateTime = "EndDateTime";

            /// <summary>
            /// The streak type
            /// </summary>
            public const string StreakType = "StreakType";
        }

        #endregion Keys

        #region Abstract Method Overrides

        /// <summary>
        /// Gets the attribute keys stored in configuration.
        /// <see cref="AchievementType.ComponentConfigJson" />
        /// </summary>
        /// <value>
        /// The attribute keys stored in configuration.
        /// </value>
        /// <exception cref="NotImplementedException"></exception>
        public override HashSet<string> AttributeKeysStoredInConfig => new HashSet<string> { AttributeKey.StreakType };

        /// <summary>
        /// Should the achievement type process attempts if the given source entity has been modified in some way.
        /// </summary>
        /// <param name="achievementTypeCache">The achievement type cache.</param>
        /// <param name="sourceEntity">The source entity.</param>
        /// <returns></returns>
        public override bool ShouldProcess( AchievementTypeCache achievementTypeCache, IEntity sourceEntity )
        {
            var streak = sourceEntity as Streak;

            if ( streak == null )
            {
                return false;
            }

            return streak.StreakTypeId == GetStreakTypeCache( achievementTypeCache )?.Id;
        }

        /// <summary>
        /// Gets the source entities query. This is the set of source entities that should be passed to the process method
        /// when processing this achievement type.
        /// </summary>
        /// <param name="achievementTypeCache">The achievement type cache.</param>
        /// <param name="rockContext">The rock context.</param>
        /// <returns></returns>
        /// <exception cref="NotImplementedException"></exception>
        public override IQueryable<IEntity> GetSourceEntitiesQuery( AchievementTypeCache achievementTypeCache, RockContext rockContext )
        {
            var streakTypeCache = GetStreakTypeCache( achievementTypeCache );

            if ( streakTypeCache == null )
            {
                return Enumerable.Empty<Streak>().AsQueryable();
            }

            var service = new StreakService( rockContext );
            return service.Queryable().Where( s => s.StreakTypeId == streakTypeCache.Id );
        }

        /// <summary>
        /// Update the open attempt record if there are changes.
        /// </summary>
        /// <param name="openAttempt"></param>
        /// <param name="achievementTypeCache">The achievement type cache.</param>
        /// <param name="streak">The streak.</param>
        protected override void UpdateOpenAttempt( AchievementAttempt openAttempt, AchievementTypeCache achievementTypeCache, Streak streak )
        {
            var rockContext = new RockContext();
            var streakTypeService = new StreakTypeService( rockContext );
            var streakTypeCache = GetStreakTypeCache( achievementTypeCache );

            // Validate the attribute values
            var numberToAccumulate = GetAttributeValue( achievementTypeCache, AttributeKey.NumberToAccumulate ).AsInteger();

            if ( numberToAccumulate <= 0 )
            {
                ExceptionLogService.LogException( $"AccumulativeAchievement.UpdateOpenAttempt cannot process because the NumberToAccumulate attribute is less than 1" );
                return;
            }

            var attributeTimespanDays = GetAttributeValue( achievementTypeCache, AttributeKey.TimespanInDays ).AsIntegerOrNull();

            if ( attributeTimespanDays.HasValue && attributeTimespanDays.Value <= 0 )
            {
                ExceptionLogService.LogException( $"AccumulativeAchievement.UpdateOpenAttempt cannot process because the TimespanInDays attribute is less than 1" );
                return;
            }

            // Calculate the date range where the open attempt can be validly fulfilled
            var attributeMaxDate = GetAttributeValue( achievementTypeCache, AttributeKey.EndDateTime ).AsDateTime();
            var minDate = openAttempt.AchievementAttemptStartDateTime;
            var maxDate = CalculateMaxDateForAchievementAttempt( minDate, attributeMaxDate );

            // Get the max date that streaks can be broken. This is to avoid breaking streaks while people still have time to
            // engage in that day or week (because it is the current day or week)
            var maxDateForStreakBreaking = StreakTypeService.GetMaxDateForStreakBreaking( streakTypeCache );

            // Track the accumulation
            var accumulation = new ComputedStreak( minDate ) { EndDate = minDate };

            // Define what happens for each bit in the date range
            bool iterationAction( int currentUnit, DateTime currentDate, bool hasOccurrence, bool hasEngagement, bool hasExclusion )
            {
                var iterationCanStop = false;

                // If there is an engagement, then increment the accumulation
                if ( hasOccurrence && hasEngagement )
                {
                    accumulation.Count++;
                    accumulation.EndDate = currentDate;

                    // Check for a fulfilled attempt
                    if ( accumulation.Count >= numberToAccumulate )
                    {
                        var progress = CalculateProgress( accumulation.Count, numberToAccumulate );

                        openAttempt.AchievementAttemptEndDateTime = accumulation.EndDate;
                        openAttempt.Progress = progress;
                        openAttempt.IsClosed = !achievementTypeCache.AllowOverAchievement;
                        openAttempt.IsSuccessful = progress >= 1m;
                        iterationCanStop = !achievementTypeCache.AllowOverAchievement;
                    }
                }

                // If there is a timespan and this accumulation is too old, then the attempt is closed
                if ( attributeTimespanDays.HasValue )
                {
                    var inclusiveAge = ( currentDate - accumulation.StartDate ).Days + 1;

                    if ( inclusiveAge >= attributeTimespanDays.Value )
                    {
                        var progress = CalculateProgress( accumulation.Count, numberToAccumulate );

                        openAttempt.AchievementAttemptEndDateTime = accumulation.EndDate;
                        openAttempt.Progress = progress;
                        openAttempt.IsClosed = currentDate <= maxDateForStreakBreaking;
                        openAttempt.IsSuccessful = progress >= 1m;
                        iterationCanStop = true;
                    }
                }

                return iterationCanStop;
            }

            // Iterate through the streak date for the date range specified
            streakTypeService.IterateStreakMap( streakTypeCache, streak.PersonAliasId, minDate, maxDate, iterationAction, out var errorMessage );

            if ( !errorMessage.IsNullOrWhiteSpace() )
            {
                ExceptionLogService.LogException( $"AccumulativeAchievement.UpdateOpenAttempt got an error calling StreakTypeService.IterateStreakMap: {errorMessage}" );
                return;
            }

            // If the attempt wasn't closed in the iteration, then it will remain open
            if ( !openAttempt.IsClosed )
            {
                var progress = CalculateProgress( accumulation.Count, numberToAccumulate );

                openAttempt.Progress = progress;
                openAttempt.IsSuccessful = progress >= 1m;
            }
        }

        /// <summary>
        /// Create new attempt records and return them in a list. All new attempts should be after the most recent successful attempt.
        /// </summary>
        /// <param name="achievementTypeCache">The achievement type cache.</param>
        /// <param name="streak">The streak.</param>
        /// <param name="mostRecentSuccess">The most recent successful attempt.</param>
        /// <returns></returns>
        protected override List<AchievementAttempt> CreateNewAttempts( AchievementTypeCache achievementTypeCache, Streak streak, AchievementAttempt mostRecentSuccess )
        {
            var rockContext = new RockContext();
            var streakTypeService = new StreakTypeService( rockContext );
            var streakTypeCache = GetStreakTypeCache( achievementTypeCache );

            // Validate the attribute values
            var numberToAccumulate = GetAttributeValue( achievementTypeCache, AttributeKey.NumberToAccumulate ).AsInteger();

            if ( numberToAccumulate <= 0 )
            {
                ExceptionLogService.LogException( $"AccumulativeAchievement.CreateNewAttempts cannot process because the NumberToAccumulate attribute is less than 1" );
                return null;
            }

            var attributeTimespanDays = GetAttributeValue( achievementTypeCache, AttributeKey.TimespanInDays ).AsIntegerOrNull();

            if ( attributeTimespanDays.HasValue && attributeTimespanDays.Value <= 0 )
            {
                ExceptionLogService.LogException( $"AccumulativeAchievement.CreateNewAttempts cannot process because the TimespanInDays attribute is less than 1" );
                return null;
            }

            // Calculate the date range where new achievements can be validly found
            var attributeMinDate = GetAttributeValue( achievementTypeCache, AttributeKey.StartDateTime ).AsDateTime();
            var attributeMaxDate = GetAttributeValue( achievementTypeCache, AttributeKey.EndDateTime ).AsDateTime();
            var minDate = CalculateMinDateForAchievementAttempt( streak.EnrollmentDate, mostRecentSuccess, attributeMinDate, numberToAccumulate );
            var maxDate = CalculateMaxDateForAchievementAttempt( minDate, attributeMaxDate );

            // Get the max date that streaks can be broken. This is to avoid breaking streaks while people still have time to
            // engage in that day or week (because it is the current day or week)
            var maxDateForStreakBreaking = StreakTypeService.GetMaxDateForStreakBreaking( streakTypeCache );

            // Track the attempts in a list that will be returned. The int is the streak count for that attempt
            var attempts = new List<AchievementAttempt>();
            var accumulations = new List<ComputedStreak>();

            // Define what happens for each bit in the date range
            bool iterationAction( int currentUnit, DateTime currentDate, bool hasOccurrence, bool hasEngagement, bool hasExclusion )
            {
                // If there is an engagement and a timespan, then this is a possible attempt. If there is no timespan then only one
                // attempt needs to be tracked at a time
                if ( hasOccurrence && hasEngagement && ( attributeTimespanDays.HasValue || !accumulations.Any() ) )
                {
                    accumulations.Add( new ComputedStreak( currentDate ) );
                }

                for ( var i = accumulations.Count - 1; i >= 0; i-- )
                {
                    var accumulation = accumulations[i];

                    if ( hasOccurrence && hasEngagement )
                    {
                        // Increment the accumulation
                        accumulation.Count++;
                        accumulation.EndDate = currentDate;

                        // Check for a fulfilled attempt
                        if ( accumulation.Count >= numberToAccumulate )
                        {
                            accumulations.Clear();

                            if ( achievementTypeCache.AllowOverAchievement )
                            {
                                accumulations.Add( accumulation );
                                i = 0;
                            }
                            else
                            {
                                attempts.Add( GetAttempt( accumulation, numberToAccumulate, true ) );
                                break;
                            }
                        }
                    }

                    // If there is a timespan and this accumulation is too old, then the attempt is closed
                    if ( attributeTimespanDays.HasValue )
                    {
                        var inclusiveAge = ( currentDate - accumulation.StartDate ).Days + 1;

                        if ( inclusiveAge >= attributeTimespanDays.Value )
                        {
                            var timedOutAttempt = GetAttempt( accumulation, numberToAccumulate, currentDate <= maxDateForStreakBreaking );
                            attempts.Add( timedOutAttempt );
                            accumulations.RemoveAt( i );

                            // Remove more recently started accumulations that started before the next valid start date (based
                            // on the deficiency of this timed out attempt)
                            var nextValidStartDate = CalculateMinDateForAchievementAttempt( streak.EnrollmentDate, timedOutAttempt, attributeMinDate, numberToAccumulate );

                            for ( var j = accumulations.Count - 1; j >= i; j-- )
                            {
                                var moreRecentAccumulation = accumulations[j];

                                if ( moreRecentAccumulation.StartDate < nextValidStartDate )
                                {
                                    accumulations.RemoveAt( j );
                                }
                            }
                        }
                    }
                }

                return false;
            }

            // Iterate through the streak date for the date range specified
            streakTypeService.IterateStreakMap( streakTypeCache, streak.PersonAliasId, minDate, maxDate, iterationAction, out var errorMessage );

            if ( !errorMessage.IsNullOrWhiteSpace() )
            {
                ExceptionLogService.LogException( $"AccumulativeAchievement.CreateNewAttempts got an error calling StreakTypeService.IterateStreakMap: {errorMessage}" );
                return null;
            }

            // The longest leftover accumulation is an open attempt
            if ( accumulations.Any() )
            {
                var longestStreak = accumulations.First();
                attempts.Add( GetAttempt( longestStreak, numberToAccumulate, false ) );
            }

            return attempts;
        }

        #endregion Abstract Method Overrides

        #region Helpers

        /// <summary>
        /// Gets the streak type unique identifier.
        /// </summary>
        /// <param name="achievementTypeCache">The achievement type cache.</param>
        /// <returns></returns>
        private Guid? GetStreakTypeGuid( AchievementTypeCache achievementTypeCache )
        {
            return GetAttributeValue( achievementTypeCache, AttributeKey.StreakType ).AsGuidOrNull();
        }

        /// <summary>
        /// Gets the streak type cache.
        /// </summary>
        /// <param name="achievementTypeCache">The achievement type cache.</param>
        /// <returns></returns>
        private StreakTypeCache GetStreakTypeCache( AchievementTypeCache achievementTypeCache )
        {
            var streakTypeGuid = GetStreakTypeGuid( achievementTypeCache );
            return streakTypeGuid.HasValue ? StreakTypeCache.Get( streakTypeGuid.Value ) : null;
        }

        /// <summary>
        /// Gets the attempt from the streak
        /// </summary>
        /// <param name="accumulation">The accumulation.</param>
        /// <param name="targetCount">The target count.</param>
        /// <param name="isClosed">if set to <c>true</c> [is closed].</param>
        /// <returns></returns>
        private static AchievementAttempt GetAttempt( ComputedStreak accumulation, int targetCount, bool isClosed )
        {
            var progress = CalculateProgress( accumulation.Count, targetCount );

            return new AchievementAttempt
            {
                AchievementAttemptStartDateTime = accumulation.StartDate,
                AchievementAttemptEndDateTime = accumulation.EndDate,
                Progress = progress,
                IsClosed = isClosed,
                IsSuccessful = progress >= 1m
            };
        }

        #endregion Helpers
    }
}