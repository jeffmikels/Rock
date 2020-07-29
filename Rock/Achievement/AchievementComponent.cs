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
using System.Linq;
using Rock.Data;
using Rock.Model;
using Rock.Web.Cache;

namespace Rock.Achievement
{
    /// <summary>
    /// Base class for achievement components
    /// </summary>
    public abstract class AchievementComponent : Rock.Extension.Component
    {
        /// <summary>
        /// Gets the supported configuration.
        /// </summary>
        public abstract AchievementConfiguration SupportedConfiguration { get; }

        /// <summary>
        /// Gets the attribute keys stored in configuration.
        /// <see cref="AchievementType.ComponentConfigJson"/>
        /// </summary>
        /// <value>
        /// The attribute keys stored in configuration.
        /// </value>
        public abstract HashSet<string> AttributeKeysStoredInConfig { get; }

        /// <summary>
        /// Gets the attribute value defaults.
        /// </summary>
        /// <value>
        /// The attribute defaults.
        /// </value>
        public override Dictionary<string, string> AttributeValueDefaults
        {
            get => new Dictionary<string, string>
            {
                { "Active", "True" },
                { "Order", "0" }
            };
        }

        /// <summary>
        /// Gets a value indicating whether this instance is active.
        /// </summary>
        /// <value>
        ///   <c>true</c> if this instance is active; otherwise, <c>false</c>.
        /// </value>
        public override bool IsActive
        {
            get => true;
        }

        /// <summary>
        /// Gets the order.
        /// </summary>
        /// <value>
        /// The order.
        /// </value>
        public override int Order
        {
            get => 0;
        }

        /// <summary>
        /// Initializes a new instance of the <see cref="AchievementComponent" /> class.
        /// </summary>
        public AchievementComponent() : base( false )
        {
            // Override default constructor of Component that loads attributes (needs to be done by each instance)
        }

        /// <summary>
        /// Loads the attributes for the <see cref="AchievementType" />.
        /// </summary>
        /// <param name="achievementType"></param>
        public void LoadAttributes( AchievementType achievementType )
        {
            if ( achievementType is null )
            {
                throw new ArgumentNullException( nameof( achievementType ) );
            }

            achievementType.LoadAttributes();
        }

        /// <summary>
        /// Gets the value of an attribute key. Do not use this method. Use <see cref="GetAttributeValue(AchievementTypeCache, string)" />
        /// </summary>
        /// <param name="key">The key.</param>
        /// <returns></returns>
        public override string GetAttributeValue( string key )
        {
            throw new Exception( "Use the GetAttributeValue( AchievementTypeCache, key ) method instead." );
        }

        /// <summary>
        /// Gets the attribute value for the achievement
        /// </summary>
        /// <param name="achievementTypeCache"></param>
        /// <param name="key">The key.</param>
        /// <returns></returns>
        protected string GetAttributeValue( AchievementTypeCache achievementTypeCache, string key )
        {
            if ( achievementTypeCache is null )
            {
                throw new ArgumentNullException( nameof( achievementTypeCache ) );
            }

            if ( AttributeKeysStoredInConfig.Contains( key ) )
            {
                return achievementTypeCache.GetComponentConfigValue( key );
            }

            return achievementTypeCache.GetAttributeValue( key );
        }

        /// <summary>
        /// Convert attribute values to a dictionary configuration. This will be serialized and stored on the model.
        /// <see cref="AchievementType.ComponentConfigJson" />
        /// </summary>
        /// <param name="achievementTypeCache">The achievement type cache.</param>
        /// <returns></returns>
        public virtual Dictionary<string, string> GenerateConfigFromAttributeValues( AchievementTypeCache achievementTypeCache )
        {
            var dictionary = new Dictionary<string, string>();

            foreach ( var key in AttributeKeysStoredInConfig )
            {
                dictionary[key] = achievementTypeCache.GetAttributeValue( key );
            }

            return dictionary;
        }

        #region Attempt Calculation Helpers

        /// <summary>
        /// Copies the source attempt properties to the target.
        /// </summary>
        /// <param name="source">The source.</param>
        /// <param name="target">The target.</param>
        protected void CopyAttempt( AchievementAttempt source, AchievementAttempt target )
        {
            target.Progress = source.Progress;
            target.IsClosed = source.IsClosed;
            target.IsSuccessful = source.IsSuccessful;
            target.AchievementAttemptStartDateTime = source.AchievementAttemptStartDateTime;
            target.AchievementAttemptEndDateTime = source.AchievementAttemptEndDateTime;
        }

        /// <summary>
        /// Calculates the minimum date for the next achievement attempt.
        /// </summary>
        /// <param name="minDate">The date to begin looking for the next attempt allowed date. Use <see cref="DateTime.MinValue"/> as a default.</param>
        /// <param name="mostRecentClosedAttempt">The most recent closed attempt.</param>
        /// <param name="achievementTypeStartDate">The achievement type start date.</param>
        /// <param name="targetCount">How many engagements are required to be successful</param>
        /// <returns></returns>
        protected DateTime CalculateMinDateForAchievementAttempt( DateTime minDate, AchievementAttempt mostRecentClosedAttempt, DateTime? achievementTypeStartDate, int targetCount )
        {
            // If the achievement start date is later, then use that
            if ( achievementTypeStartDate.HasValue && achievementTypeStartDate.Value > minDate )
            {
                minDate = achievementTypeStartDate.Value;
            }

            if ( mostRecentClosedAttempt != null )
            {
                var deficiency = CalculateDeficiency( mostRecentClosedAttempt, targetCount );

                // If the most recent closed attempt has an end date, then the next attempt must be at least one day after
                if ( mostRecentClosedAttempt.AchievementAttemptEndDateTime.HasValue && deficiency == 0 )
                {
                    // We know the end date and it used all the bits, so just start after the end date.
                    minDate = mostRecentClosedAttempt.AchievementAttemptEndDateTime.Value.AddDays( 1 );
                }
                else if ( deficiency >= 1 )
                {
                    // Increment from the start date by the deficiency
                    minDate = mostRecentClosedAttempt.AchievementAttemptStartDateTime.AddDays( deficiency );
                }
                else
                {
                    // This shouldn't happen
                    minDate = mostRecentClosedAttempt.AchievementAttemptStartDateTime.AddDays( 1 );
                }
            }

            return minDate;
        }

        /// <summary>
        /// Calculates the maximum date for an achievement attempt to be completed.
        /// </summary>
        /// <param name="minDate">The minimum date.</param>
        /// <param name="achievementTypeEndDate">The achievement type end date.</param>
        /// <returns></returns>
        protected DateTime CalculateMaxDateForAchievementAttempt( DateTime minDate, DateTime? achievementTypeEndDate )
        {
            // Use today as a starting point for the end date
            var maxDate = RockDateTime.Today;

            // If the achievement type has an end date and it is before today, then the attempt cannot be beyond that
            if ( achievementTypeEndDate.HasValue && achievementTypeEndDate.Value < maxDate )
            {
                maxDate = achievementTypeEndDate.Value;
            }

            // If somehow the max became less than the min date, use the min date
            if ( maxDate < minDate )
            {
                maxDate = minDate;
            }

            return maxDate;
        }

        /// <summary>
        /// Calculates the progress.
        /// </summary>
        /// <param name="actualCount">The actual count.</param>
        /// <param name="targetCount">The target count.</param>
        /// <returns></returns>
        protected static decimal CalculateProgress( int actualCount, int targetCount )
        {
            return decimal.Divide( actualCount, targetCount );
        }

        /// <summary>
        /// Calculates the deficiency.
        /// </summary>
        /// <param name="attempt">The attempt.</param>
        /// <param name="targetCount">The target count.</param>
        /// <returns></returns>
        protected static int CalculateDeficiency( AchievementAttempt attempt, int targetCount )
        {
            var progress = attempt?.Progress ?? 0m;

            if ( progress < 0m )
            {
                progress = 0m;
            }
            else if ( progress > 1m )
            {
                progress = 1m;
            }

            var attemptCount = ( int ) decimal.Round( progress * targetCount );
            return targetCount - attemptCount;
        }

        #endregion Attempt Calculation Helpers

        #region Abstract Methods

        /// <summary>
        /// Processes the specified achievement type cache for the source entity.
        /// </summary>
        /// <param name="rockContext">The rock context.</param>
        /// <param name="achievementTypeCache">The streak type achievement type cache.</param>
        /// <param name="sourceEntity">The source entity.</param>
        /// <returns>The set of attempts that were created or updated</returns>
        public abstract HashSet<AchievementAttempt> Process( RockContext rockContext, AchievementTypeCache achievementTypeCache, IEntity sourceEntity );

        /// <summary>
        /// Should the achievement type process attempts if the given source entity has been modified in some way.
        /// </summary>
        /// <param name="achievementTypeCache">The achievement type cache.</param>
        /// <param name="sourceEntity">The source entity.</param>
        /// <returns></returns>
        public abstract bool ShouldProcess( AchievementTypeCache achievementTypeCache, IEntity sourceEntity );

        /// <summary>
        /// Gets the source entities query. This is the set of source entities that should be passed to the process method
        /// when processing this achievement type.
        /// </summary>
        /// <param name="achievementTypeCache">The achievement type cache.</param>
        /// <param name="rockContext">The rock context.</param>
        /// <returns></returns>
        public abstract IQueryable<IEntity> GetSourceEntitiesQuery( AchievementTypeCache achievementTypeCache, RockContext rockContext );

        #endregion Abstract Methods
    }
}
