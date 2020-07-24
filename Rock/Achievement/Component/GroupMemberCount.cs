// <copyright>
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

using System.Collections.Generic;
using System.ComponentModel;
using System.ComponentModel.Composition;
using System.Data.Entity;
using System.Linq;
using System.Linq.Dynamic;
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
    [Description( "Use to track achievements earned by having a certain number of group members" )]
    [Export( typeof( AchievementComponent ) )]
    [ExportMetadata( "ComponentName", "Group Members: Count" )]

    [IntegerField(
        name: "Number to Accumulate",
        description: "The number of group members required to earn this achievement.",
        required: true,
        order: 0,
        key: AttributeKey.NumberToAccumulate )]

    public class GroupMemberCountAchievement : AchievementComponent
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
        }

        #endregion Keys

        /// <summary>
        /// Gets the supported configuration.
        /// </summary>
        public override AchievementConfiguration SupportedConfiguration =>
            new AchievementConfiguration( EntityTypeCache.Get<GroupMember>(), EntityTypeCache.Get<Group>() );

        /// <summary>
        /// Gets the source entities query. This is the set of source entities that should be passed to the process method
        /// when processing this achievement type.
        /// </summary>
        /// <param name="achievementTypeCache">The achievement type cache.</param>
        /// <param name="rockContext">The rock context.</param>
        /// <returns></returns>
        public override IQueryable<IEntity> GetSourceEntitiesQuery( AchievementTypeCache achievementTypeCache, RockContext rockContext )
        {
            var service = new GroupMemberService( rockContext );
            var query = service.Queryable();

            if ( !achievementTypeCache.SourceEntityQualifierColumn.IsNullOrWhiteSpace() )
            {
                query = query.Where( $"{achievementTypeCache.SourceEntityQualifierColumn} = @0", achievementTypeCache.SourceEntityQualifierValue );
            }

            return query
                .Where( gm => !gm.IsArchived )
                .GroupBy( gm => gm.GroupId )
                .Select( g => g.FirstOrDefault() );
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
            var now = RockDateTime.Now;
            var groupMember = sourceEntity as GroupMember;
            var updatedAttempts = new HashSet<AchievementAttempt>();

            // Validate the attribute values
            var numberToAccumulate = GetAttributeValue( achievementTypeCache, AttributeKey.NumberToAccumulate ).AsInteger();

            if ( numberToAccumulate <= 0 )
            {
                ExceptionLogService.LogException( $"{GetType().Name}.Process cannot process because the NumberToAccumulate attribute is less than 1" );
                return updatedAttempts;
            }

            if ( groupMember == null )
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
            var unmetPrerequisites = achievementTypeService.GetUnmetPrerequisites( achievementTypeCache.Id, groupMember.GroupId );

            if ( unmetPrerequisites.Any() )
            {
                return updatedAttempts;
            }

            // Get all of the attempts for this interaction and achievement combo, ordered by start date DESC so that
            // the most recent attempts can be found with FirstOrDefault
            var achievementAttemptService = new AchievementAttemptService( rockContext );
            var attempt = achievementAttemptService.Queryable()
                .Where( aa =>
                    aa.AchievementTypeId == achievementTypeCache.Id &&
                    aa.AchieverEntityId == groupMember.GroupId )
                .ToList()
                .OrderByDescending( aa => aa.AchievementAttemptStartDateTime )
                .LastOrDefault();

            var newCount = GetGroupMemberCount( achievementTypeCache, groupMember.GroupId );
            var progress = CalculateProgress( newCount, numberToAccumulate );

            // There is no attempt yet
            if ( attempt == null && newCount == 0 )
            {
                return updatedAttempts;
            }

            // Once you earn the achievement, you cannot lose it
            if ( attempt?.IsSuccessful == true )
            {
                return updatedAttempts;
            }

            // There is no change
            if ( attempt?.Progress == progress )
            {
                return updatedAttempts;
            }

            // Progress cannot go down
            if ( attempt != null && attempt.Progress >= progress )
            {
                return updatedAttempts;
            }

            // New attempt
            if ( attempt == null )
            {
                attempt = new AchievementAttempt
                {
                    AchievementTypeId = achievementTypeCache.Id,
                    AchieverEntityId = groupMember.GroupId,
                    AchievementAttemptStartDateTime = now,
                    AchievementAttemptEndDateTime = now,
                    IsClosed = false
                };

                achievementAttemptService.Add( attempt );
            }

            attempt.Progress = progress;
            attempt.IsSuccessful = progress >= 1m;

            updatedAttempts.Add( attempt );
            return updatedAttempts;
        }

        #region Helpers

        /// <summary>
        /// Gets the group member count.
        /// </summary>
        /// <param name="achievementTypeCache">The achievement type cache.</param>
        /// <param name="groupId">The group identifier.</param>
        /// <returns></returns>
        private int GetGroupMemberCount( AchievementTypeCache achievementTypeCache, int groupId )
        {
            var rockContext = new RockContext();
            var groupMemberService = new GroupMemberService( rockContext );
            var query = groupMemberService.Queryable().AsNoTracking();

            if ( !achievementTypeCache.SourceEntityQualifierColumn.IsNullOrWhiteSpace() )
            {
                query = query.Where( $"{achievementTypeCache.SourceEntityQualifierColumn} = @0", achievementTypeCache.SourceEntityQualifierValue );
            }

            return query.Count( gm => gm.GroupId == groupId && !gm.IsArchived );
        }

        #endregion Helpers
    }
}