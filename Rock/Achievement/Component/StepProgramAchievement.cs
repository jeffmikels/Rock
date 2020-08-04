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
using System.Data.Entity;
using System.Linq;
using System.Linq.Dynamic;
using Lucene.Net.Support;
using OpenXmlPowerTools;
using Rock.Attribute;
using Rock.Data;
using Rock.Model;
using Rock.Web.Cache;

namespace Rock.Achievement.Component
{
    /// <summary>
    /// Use to track achievements earned by accumulating interactions
    /// </summary>
    /// <seealso cref="AchievementComponent" />
    [Description( "Use to track achievements earned by completing a step program" )]
    [Export( typeof( AchievementComponent ) )]
    [ExportMetadata( "ComponentName", "Steps: Program Completion" )]

    [StepProgramField(
        name: "Step Program",
        description: "The step program from which the achievement is earned.",
        required: true,
        order: 0,
        key: AttributeKey.StepProgram )]

    [DateField(
        name: "Start Date",
        description: "The date that defines when the program must be completed on or after.",
        required: false,
        order: 2,
        key: AttributeKey.StartDateTime )]

    [DateField(
        name: "End Date",
        description: "The date that defines when the program must be completed on or before.",
        required: false,
        order: 3,
        key: AttributeKey.EndDateTime )]

    public class StepProgramAchievement : AchievementComponent
    {
        #region Keys

        /// <summary>
        /// Keys to use for the attributes
        /// </summary>
        public static class AttributeKey
        {
            /// <summary>
            /// The Start Date Time
            /// </summary>
            public const string StartDateTime = "StartDateTime";

            /// <summary>
            /// The End Date Time
            /// </summary>
            public const string EndDateTime = "EndDateTime";

            /// <summary>
            /// The step program
            /// </summary>
            public const string StepProgram = "StepProgram";
        }

        #endregion Keys

        /// <summary>
        /// Gets the attribute keys stored in configuration.
        /// <see cref="AchievementType.ComponentConfigJson" />
        /// </summary>
        /// <value>
        /// The attribute keys stored in configuration.
        /// </value>
        /// <exception cref="NotImplementedException"></exception>
        public override HashSet<string> AttributeKeysStoredInConfig => new HashSet<string> { AttributeKey.StepProgram };

        /// <summary>
        /// Gets the supported configuration.
        /// </summary>
        public override AchievementConfiguration SupportedConfiguration =>
            new AchievementConfiguration( EntityTypeCache.Get<Step>(), EntityTypeCache.Get<PersonAlias>() );

        /// <summary>
        /// Should the achievement type process attempts if the given source entity has been modified in some way.
        /// </summary>
        /// <param name="achievementTypeCache">The achievement type cache.</param>
        /// <param name="sourceEntity">The source entity.</param>
        /// <returns></returns>
        public override bool ShouldProcess( AchievementTypeCache achievementTypeCache, IEntity sourceEntity )
        {
            var step = sourceEntity as Step;

            if ( step == null )
            {
                return false;
            }

            var stepProgram = GetStepProgramCache( achievementTypeCache );

            if ( stepProgram == null )
            {
                return false;
            }

            var stepTypeIds = stepProgram.StepTypes.Select( st => st.Id );
            return stepTypeIds.Contains( step.StepTypeId );
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
            var stepProgram = GetStepProgramCache( achievementTypeCache );
            var stepTypes = stepProgram.StepTypes;
            var service = new StepService( rockContext );
            var query = service.Queryable();

            if ( stepTypes?.Any() == true )
            {
                var stepTypeIds = stepTypes.Select( st => st.Id );
                return query.Where( s => stepTypeIds.Contains( s.StepTypeId ) );
            }

            return query;
        }

        /// <summary>
        /// Determines whether this achievement type applies given the set of filters. The filters could be the query string
        /// of a web request.
        /// </summary>
        /// <param name="achievementTypeCache">The achievement type cache.</param>
        /// <param name="filters">The filters.</param>
        /// <returns>
        ///   <c>true</c> if [is relevant to all filters] [the specified filters]; otherwise, <c>false</c>.
        /// </returns>
        public override bool IsRelevantToAllFilters( AchievementTypeCache achievementTypeCache, List<KeyValuePair<string, string>> filters )
        {
            if ( filters.Count == 0 )
            {
                return true;
            }

            if ( filters.Count > 1 )
            {
                return false;
            }

            var filter = filters.First();

            if ( filter.Key.Equals( "StepProgramId", StringComparison.OrdinalIgnoreCase ) )
            {
                return filter.Value.AsInteger() == GetStepProgramCache( achievementTypeCache )?.Id;
            }

            return false;
        }

        /// <summary>
        /// Gets the achiever attempt query. This is the query (not enumerated) that joins attempts of this achievement type with the
        /// achiever entities, as well as the name (<see cref="AchieverAttemptItem.AchieverName"/> that could represent the achiever
        /// in a grid or other such display.
        /// </summary>
        /// <param name="achievementTypeCache">The achievement type cache.</param>
        /// <param name="rockContext">The rock context.</param>
        /// <returns></returns>
        public override IQueryable<AchieverAttemptItem> GetAchieverAttemptQuery( AchievementTypeCache achievementTypeCache, RockContext rockContext )
        {
            var attemptService = new AchievementAttemptService( rockContext );
            var personAliasService = new PersonAliasService( rockContext );

            var attemptQuery = attemptService.Queryable().Where( aa => aa.AchievementTypeId == achievementTypeCache.Id );
            var personAliasQuery = personAliasService.Queryable();

            return attemptQuery.Join(
                    personAliasQuery,
                    aa => aa.AchieverEntityId,
                    pa => pa.Id,
                    ( aa, pa ) => new AchieverAttemptItem
                    {
                        AchievementAttempt = aa,
                        Achiever = pa,
                        AchieverName = pa.Person.NickName + " " + pa.Person.LastName
                    } );
        }

        /// <summary>
        /// Processes the specified achievement type cache for the source entity.
        /// </summary>
        /// <param name="rockContext">The rock context.</param>
        /// <param name="achievementTypeCache">The achievement type cache.</param>
        /// <param name="sourceEntity">The source entity.</param>
        /// <returns>The set of attempts that were created or updated</returns>
        public override HashSet<AchievementAttempt> Process( RockContext rockContext, AchievementTypeCache achievementTypeCache, IEntity sourceEntity )
        {
            var step = sourceEntity as Step;
            var updatedAttempts = new HashSet<AchievementAttempt>();

            // If we cannot link the step to a person, then there is nothing to do
            if ( step == null )
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
            var unmetPrerequisites = achievementTypeService.GetUnmetPrerequisites( achievementTypeCache.Id, step.PersonAliasId );

            if ( unmetPrerequisites.Any() )
            {
                return updatedAttempts;
            }

            // Get all of the attempts for this program and achievement combo, ordered by start date DESC so that
            // the most recent attempts can be found with FirstOrDefault
            var achievementAttemptService = new AchievementAttemptService( rockContext );
            var attempts = achievementAttemptService.Queryable()
                .Where( aa =>
                    aa.AchievementTypeId == achievementTypeCache.Id &&
                    aa.AchieverEntityId == step.PersonAliasId )
                .ToList()
                .OrderByDescending( aa => aa.AchievementAttemptStartDateTime )
                .ToList();

            var mostRecentSuccess = attempts.FirstOrDefault( saa => saa.AchievementAttemptEndDateTime.HasValue && saa.IsSuccessful );

            // This component does not allow more than one success
            if ( mostRecentSuccess != null )
            {
                return updatedAttempts;
            }

            var currentAttempt = attempts.LastOrDefault();

            if ( currentAttempt == null )
            {
                currentAttempt = new AchievementAttempt
                {
                    AchieverEntityId = step.PersonAliasId,
                    AchievementTypeId = achievementTypeCache.Id
                };

                achievementAttemptService.Add( currentAttempt );
            }

            var attributeMinDate = GetAttributeValue( achievementTypeCache, AttributeKey.StartDateTime ).AsDateTime() ?? DateTime.MinValue;
            var attributeMaxDate = GetAttributeValue( achievementTypeCache, AttributeKey.EndDateTime ).AsDateTime() ?? DateTime.MaxValue;
            var completedStepTypeDates = GetCompletedStepTypeDates( achievementTypeCache, step.PersonAliasId, attributeMinDate, attributeMaxDate );

            var stepProgram = GetStepProgramCache( achievementTypeCache );
            var stepTypeCount = stepProgram.StepTypes.Count;
            
            var progress = CalculateProgress( completedStepTypeDates.Count, stepTypeCount );
            var isSuccessful = progress >= 1m;

            currentAttempt.AchievementAttemptStartDateTime = completedStepTypeDates.FirstOrDefault();
            currentAttempt.AchievementAttemptEndDateTime = completedStepTypeDates.LastOrDefault();
            currentAttempt.Progress = progress;
            currentAttempt.IsClosed = isSuccessful;
            currentAttempt.IsSuccessful = isSuccessful;

            return updatedAttempts;
        }

        /// <summary>
        /// Gets the name of the source that these achievements are measured from.
        /// </summary>
        /// <param name="achievementTypeCache">The achievement type cache.</param>
        /// <returns></returns>
        public override string GetSourceName( AchievementTypeCache achievementTypeCache )
        {
            var stepProgram = GetStepProgramCache( achievementTypeCache );

            if ( stepProgram != null )
            {
                return stepProgram.Name;
            }

            return string.Empty;
        }

        #region Helpers

        /// <summary>
        /// Gets the interaction channel unique identifier.
        /// </summary>
        /// <param name="achievementTypeCache">The achievement type cache.</param>
        /// <returns></returns>
        private Guid? GetStepProgramGuid( AchievementTypeCache achievementTypeCache )
        {
            var delimited = GetAttributeValue( achievementTypeCache, AttributeKey.StepProgram );
            var guids = delimited.SplitDelimitedValues().AsGuidOrNullList();
            return guids.FirstOrDefault();
        }

        /// <summary>
        /// Gets the interaction component unique identifier.
        /// </summary>
        /// <param name="achievementTypeCache">The achievement type cache.</param>
        /// <returns></returns>
        private Guid? GetInteractionComponentGuid( AchievementTypeCache achievementTypeCache )
        {
            var delimited = GetAttributeValue( achievementTypeCache, AttributeKey.StepProgram );
            var guids = delimited.SplitDelimitedValues().AsGuidOrNullList();
            return guids.Count == 2 ? guids[1] : null;
        }

        /// <summary>
        /// Gets the step program cache.
        /// </summary>
        /// <param name="achievementTypeCache">The achievement type cache.</param>
        /// <returns></returns>
        private StepProgramCache GetStepProgramCache( AchievementTypeCache achievementTypeCache )
        {
            var guid = GetStepProgramGuid( achievementTypeCache );
            return guid.HasValue ? StepProgramCache.Get( guid.Value ) : null;
        }

        /// <summary>
        /// Gets the interaction dates.
        /// </summary>
        /// <param name="achievementTypeCache">The achievementTypeCache.</param>
        /// <param name="personAliasId">The person alias identifier.</param>
        /// <param name="minDate">The minimum date.</param>
        /// <param name="maxDate">The maximum date.</param>
        /// <returns></returns>
        private List<DateTime> GetCompletedStepTypeDates( AchievementTypeCache achievementTypeCache, int personAliasId, DateTime minDate, DateTime maxDate )
        {
            var rockContext = new RockContext();
            var query = GetSourceEntitiesQuery( achievementTypeCache, rockContext ) as IQueryable<Step>;
            var dayAfterMaxDate = maxDate.AddDays( 1 );

            rockContext.SqlLogging( true );
            return query
                .AsNoTracking()
                .Where( s =>
                    s.PersonAliasId == personAliasId &&
                    s.CompletedDateTime >= minDate &&
                    s.CompletedDateTime < dayAfterMaxDate )
                .ToList()
                .GroupBy( s => s.StepTypeId )
                .Select( g => new
                {
                    StepTypeId = g.Key,
                    CompletedDateTime = g.Max( s => s.CompletedDateTime.Value )
                } )
                .Select( s => s.CompletedDateTime )
                .OrderBy( d => d )
                .ToList();
        }

        /// <summary>
        /// Gets the attempt from the accumulation
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