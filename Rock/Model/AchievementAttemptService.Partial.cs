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
using System.Data.Entity;
using System.Linq;
using Rock.Data;
using Rock.Web.Cache;

namespace Rock.Model
{
    /// <summary>
    /// Service/Data access class for <see cref="AchievementAttempt"/> entity objects.
    /// </summary>
    public partial class AchievementAttemptService
    {
        /// <summary>
        /// Queries attempts by streak type identifier.
        /// </summary>
        /// <param name="streakTypeId">The streak type identifier.</param>
        /// <returns></returns>
        public IQueryable<AchievementAttempt> QueryByStreakTypeId( int streakTypeId )
        {
            var streakEntityTypeId = EntityTypeCache.Get<Streak>().Id;

            return Queryable().Where( aa =>
                aa.AchievementType.SourceEntityTypeId == streakEntityTypeId &&
                aa.AchievementType.SourceEntityQualifierColumn == nameof( Streak.StreakTypeId ) &&
                aa.AchievementType.SourceEntityQualifierValue == streakTypeId.ToString()
            );
        }

        /// <summary>
        /// Queries attempts by streak identifier.
        /// </summary>
        /// <param name="streakId">The streak identifier.</param>
        /// <returns></returns>
        public IQueryable<AchievementAttempt> QueryByStreakId( int streakId )
        {
            var rockContext = Context as RockContext;
            var streakService = new StreakService( rockContext );
            var streakQuery = streakService.Queryable()
                .AsNoTracking()
                .Where( s => s.Id == streakId );

            var streakEntityTypeId = EntityTypeCache.Get<Streak>().Id;
            var personEntityTypeId = EntityTypeCache.Get<Person>().Id;
            var personAliasEntityTypeId = EntityTypeCache.Get<PersonAlias>().Id;

            return Queryable().Where( aa =>
                aa.AchievementType.SourceEntityTypeId == streakEntityTypeId &&
                aa.AchievementType.SourceEntityQualifierColumn == nameof( Streak.StreakTypeId ) &&
                streakQuery.Select( s => s.StreakTypeId.ToString() ).Contains( aa.AchievementType.SourceEntityQualifierValue ) &&
                (
                    (
                        aa.AchievementType.AchieverEntityTypeId == personEntityTypeId &&
                        streakQuery.Select( s => s.PersonAlias.PersonId ).Contains( aa.AchieverEntityId )
                    ) ||
                    (
                        aa.AchievementType.AchieverEntityTypeId == personAliasEntityTypeId &&
                        streakQuery.Select( s => s.PersonAliasId ).Contains( aa.AchieverEntityId )
                    )
                )
            );
        }

        /// <summary>
        /// Queries attempts by person identifier.
        /// </summary>
        /// <param name="personId">The person identifier.</param>
        /// <returns></returns>
        public IQueryable<AchievementAttempt> QueryByPersonId( int personId )
        {
            var rockContext = Context as RockContext;
            var personAliasService = new PersonAliasService( rockContext );
            var personEntityTypeId = EntityTypeCache.Get<Person>().Id;
            var personAliasEntityTypeId = EntityTypeCache.Get<PersonAlias>().Id;

            var personAliasIdQuery = personAliasService.Queryable()
                .AsNoTracking()
                .Where( pa => pa.PersonId == personId )
                .Select( pa => pa.Id );

            return Queryable().Where( aa =>
                (
                    aa.AchievementType.AchieverEntityTypeId == personEntityTypeId &&
                    aa.AchieverEntityId == personId
                ) ||
                (
                    aa.AchievementType.AchieverEntityTypeId == personAliasEntityTypeId &&
                    personAliasIdQuery.Contains( aa.AchieverEntityId )
                )
            );
        }
    }
}